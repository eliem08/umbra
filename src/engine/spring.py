"""
Spring Boot (Java) annotation parser.

Java has no parser in the Python stdlib, and pulling in tree-sitter/JavaParser is
heavyweight for an MVP. Spring routing is, however, almost entirely declarative
via annotations, which makes a focused line-oriented parser tractable and
accurate for the common cases:

- Class-level ``@RequestMapping("/prefix")`` on ``@RestController`` / ``@Controller``
- Method mappings: ``@GetMapping`` / ``@PostMapping`` / ``@PutMapping`` /
  ``@DeleteMapping`` / ``@PatchMapping`` and generic ``@RequestMapping(method=...)``
- Authorization via ``@PreAuthorize`` / ``@Secured`` / ``@RolesAllowed`` at the
  class or method level (configurable through AuthConfig)

It assumes the conventional one-controller-per-file layout. This is a pragmatic
static MVP, not a full Java semantic analyzer.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .authconfig import AuthConfig
from .parser import normalize_path
from .schemas import RouteEndpoint, ScanResult
from .fsutil import iter_source_files, DEFAULT_EXCLUDE_DIRS

VERB_ANNOTATIONS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}
MAPPING_ANNOTATIONS = set(VERB_ANNOTATIONS) | {"RequestMapping"}

_ANNOTATION_RE = re.compile(r"^@(\w+)\s*(\((.*)\))?\s*$", re.DOTALL)
_CLASS_RE = re.compile(r"\b(class|interface|enum)\s+\w+")
_QUOTED_RE = re.compile(r'"([^"]*)"')
_REQUEST_METHOD_RE = re.compile(r"RequestMethod\.(\w+)")


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """
    Collapse multi-line annotations / signatures into single logical lines while
    preserving the starting 1-indexed physical line number.
    """
    out: List[Tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start_line = i + 1
        buf = lines[i]
        # Join continuation lines while parentheses are unbalanced.
        while buf.count("(") > buf.count(")") and i + 1 < len(lines):
            i += 1
            buf += " " + lines[i].strip()
        out.append((start_line, buf.strip()))
        i += 1
    return out


def _extract_path(args: str) -> Optional[str]:
    """Pull the route path out of annotation args (value=/path=/positional)."""
    if not args:
        return None
    for key in ("value", "path"):
        m = re.search(key + r"\s*=\s*\{?\s*\"([^\"]*)\"", args)
        if m:
            return m.group(1)
    # Fall back to the first bare quoted string (positional path argument).
    m = _QUOTED_RE.search(args)
    return m.group(1) if m else None


def _extract_methods(annotation: str, args: str) -> List[str]:
    if annotation in VERB_ANNOTATIONS:
        return [VERB_ANNOTATIONS[annotation]]
    # Generic @RequestMapping: read method=RequestMethod.X (possibly an array).
    methods = [m.upper() for m in _REQUEST_METHOD_RE.findall(args or "")]
    return methods or ["GET"]


class SpringParser:
    """Parses Spring Boot controllers in a directory tree into RouteEndpoints."""

    def __init__(self, base_dir: str, auth_config: Optional[AuthConfig] = None,
                 exclude_dirs: Optional[set] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.auth_config = auth_config or AuthConfig()
        self.exclude_dirs = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs

    def parse_directory(self) -> ScanResult:
        endpoints: List[RouteEndpoint] = []
        for full_path, rel_path in iter_source_files(self.base_dir, (".java",), self.exclude_dirs):
            endpoints.extend(self.parse_file(full_path, rel_path))
        return ScanResult(routes=endpoints)

    def parse_file(self, filepath: str, rel_path: str) -> List[RouteEndpoint]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            return []

        endpoints: List[RouteEndpoint] = []
        logical = _logical_lines(text)

        class_prefix = ""
        class_auth = False
        seen_class = False
        pending: List[Tuple[int, str, str]] = []  # (lineno, annotation_name, args)

        for lineno, line in logical:
            m = _ANNOTATION_RE.match(line)
            if m:
                pending.append((lineno, m.group(1), m.group(3) or ""))
                continue

            if not seen_class and _CLASS_RE.search(line):
                # Resolve class-level prefix + auth from the annotations above the class.
                for _, name, args in pending:
                    if name == "RequestMapping":
                        p = _extract_path(args)
                        if p:
                            class_prefix = p
                    if self.auth_config.spring_annotation_match(name):
                        class_auth = True
                seen_class = True
                pending = []
                continue

            # A non-annotation, non-class line: if a mapping annotation is pending,
            # this is the handler method it decorates.
            mapping = next((a for a in pending if a[1] in MAPPING_ANNOTATIONS), None)
            if mapping:
                method_auth = class_auth or any(
                    self.auth_config.spring_annotation_match(name) for _, name, _ in pending
                )
                auth_names = [name for _, name, _ in pending if self.auth_config.spring_annotation_match(name)]
                _, ann_name, ann_args = mapping
                method_path = _extract_path(ann_args) or ""
                combined = (class_prefix or "") + (method_path or "")
                norm = normalize_path(combined or "/")
                verbs = _extract_methods(ann_name, ann_args)

                auth_info = None
                if method_auth:
                    parts = []
                    if class_auth:
                        parts.append("class-level authorization")
                    if auth_names:
                        parts.append(f"annotations: {', '.join(sorted(set(auth_names)))}")
                    auth_info = "; ".join(parts) or "authorization annotation"

                for verb in verbs:
                    endpoints.append(RouteEndpoint(
                        path=norm,
                        method=verb,
                        auth_required=method_auth,
                        auth_info=auth_info,
                        source_file=rel_path,
                        line_number=mapping[0],
                        framework="Spring Boot",
                        language="java",
                    ))
            pending = []

        return endpoints
