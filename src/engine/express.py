"""
Express (JavaScript/TypeScript) route parser.

Express is the hardest target for static analysis: routes are registered at
runtime and middleware composition is dynamic. A static parser therefore has
*structurally lower* recall here than for FastAPI/Spring — this is documented,
not a bug, and ``--express-entry`` (runtime discovery) is the high-recall path.
What this static MVP catches reliably:

- ``app.get('/x', handler)`` / ``router.post('/x', mw, handler)`` for all verbs
- Chained ``router.route('/x').get(...).post(...)`` definitions
- Mount prefixes: ``app.use('/api', router)`` (router routes inherit ``/api``)
- Inline auth middleware: ``router.get('/x', requireAuth, handler)`` and factory
  calls like ``auth()`` / ``passport.authenticate(...)``
- Prefix-level auth: ``app.use('/api', authGuard, router)``

What it cannot catch (use runtime discovery): prefixes/routers wired through data
(``routes.forEach(r => app.use(r.path, r.route))``), conditional registration, etc.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set, Tuple

from .authconfig import AuthConfig
from .parser import normalize_path
from .schemas import RouteEndpoint, ScanResult
from .fsutil import iter_source_files, DEFAULT_EXCLUDE_DIRS

JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
VERB_ALT = r"get|post|put|delete|patch|options|head|all"

# Direct call:  router.get('/users/:id', requireAuth, handler)
_ROUTE_RE = re.compile(
    rf"""([A-Za-z_$][\w$]*)\.({VERB_ALT})\s*\(\s*
        (['"`])(?P<path>[^'"`]*)\3\s*(?P<rest>,.*)?$""",
    re.VERBOSE,
)
# Chained base:  router.route('/users/:id')  ... .get(...).post(...)
_ROUTE_CHAIN_RE = re.compile(
    rf"""([A-Za-z_$][\w$]*)\.route\s*\(\s*(['"`])(?P<path>[^'"`]*)\2\s*\)"""
    , re.VERBOSE,
)
_VERB_CALL_RE = re.compile(rf"\.({VERB_ALT})\s*\(")
_USE_RE = re.compile(r"""[A-Za-z_$][\w$]*\.use\s*\(\s*(?P<inner>[^)]*)\)""")
_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$.]*$")


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """
    Build logical lines, joining (a) unbalanced-paren continuations and (b) fluent
    method chains where the next line begins with '.' (e.g. `router`\n`.route('/')`
    \n`.post(...)`). Dot-continuations are appended without a separating space so the
    chain reads as `router.route('/').post(...)`.
    """
    out: List[Tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start_line = i + 1
        buf = lines[i]
        while i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            if buf.count("(") > buf.count(")"):
                i += 1
                buf += " " + lines[i].strip()
            elif nxt.startswith("."):
                i += 1
                buf = buf.rstrip() + lines[i].strip()
            else:
                break
        out.append((start_line, buf.strip()))
        i += 1
    return out


def _split_args(inner: str) -> List[str]:
    """Split a call's argument list on top-level commas only."""
    args, depth, buf, quote = [], 0, "", None
    for ch in inner:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
            buf += ch
        elif ch in "([{":
            depth += 1
            buf += ch
        elif ch in ")]}":
            depth -= 1
            buf += ch
        elif ch == "," and depth == 0:
            args.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        args.append(buf.strip())
    return args


def _extract_balanced(s: str, open_idx: int) -> str:
    """Given the index of an opening '(', return the substring inside the matching ')'."""
    depth, quote = 0, None
    for i in range(open_idx, len(s)):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:i]
    return s[open_idx + 1:]


class ExpressParser:
    def __init__(self, base_dir: str, auth_config: Optional[AuthConfig] = None,
                 exclude_dirs: Optional[Set[str]] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.auth_config = auth_config or AuthConfig()
        self.exclude_dirs = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs
        self.prefix_map: Dict[str, str] = {}
        self.prefix_auth: Dict[str, bool] = {}

    def _iter_js_files(self):
        yield from iter_source_files(self.base_dir, JS_EXTENSIONS, self.exclude_dirs)

    def parse_directory(self) -> ScanResult:
        self._prescan_mounts()
        endpoints: List[RouteEndpoint] = []
        for full, rel in self._iter_js_files():
            endpoints.extend(self.parse_file(full, rel))
        return ScanResult(routes=endpoints)

    def _prescan_mounts(self) -> None:
        for full, _ in self._iter_js_files():
            try:
                with open(full, "r", encoding="utf-8") as f:
                    text = f.read()
            except Exception:
                continue
            for _, line in _logical_lines(text):
                for m in _USE_RE.finditer(line):
                    args = _split_args(m.group("inner"))
                    if not args or args[0][:1] not in "'\"`":
                        continue  # first arg isn't a path string -> not a mount
                    prefix = args[0].strip("'\"`")
                    idents = [a for a in args[1:] if _IDENT_RE.match(a)]
                    if not idents:
                        continue
                    router_ident = idents[-1]
                    self.prefix_map[router_ident] = prefix
                    if any(self._arg_is_auth(mw) for mw in args[1:-1]):
                        self.prefix_auth[router_ident] = True

    def _arg_is_auth(self, arg: str) -> bool:
        """
        True if a handler-list argument is an auth middleware.

        Distinguishes middleware from the route handler: a factory call like
        ``auth('manageUsers')`` or ``passport.authenticate(...)`` uses its callee
        name; a bare identifier like ``requireAuth`` uses itself. A plain member
        reference such as ``authController.register`` (the handler) is ignored.
        """
        arg = arg.strip()
        callee: Optional[str] = None
        if "(" in arg:
            head = arg.split("(", 1)[0]
            callee = head.split(".")[-1].strip()
        elif "." not in arg and _IDENT_RE.match(arg):
            callee = arg
        if not callee:
            return False
        return self.auth_config.express_middleware_match(callee)

    def _args_auth(self, args_str: str) -> Tuple[bool, Optional[str]]:
        hits = [a for a in _split_args(args_str.lstrip(",")) if self._arg_is_auth(a)]
        if hits:
            return True, "inline middleware: " + ", ".join(hits)
        return False, None

    def _emit(self, obj, verb, route_path, args_str, lineno, rel_path, endpoints):
        prefix = self.prefix_map.get(obj, "")
        norm = normalize_path((prefix or "") + (route_path or "") or "/")
        inline_auth, info = self._args_auth(args_str or "")
        prefix_auth = self.prefix_auth.get(obj, False)
        auth_required = inline_auth or prefix_auth
        info_parts = []
        if prefix_auth:
            info_parts.append(f"mount-level middleware on '{obj}'")
        if info:
            info_parts.append(info)
        auth_info = "; ".join(info_parts) if info_parts else None

        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"] if verb == "ALL" else [verb]
        for method in methods:
            endpoints.append(RouteEndpoint(
                path=norm, method=method, auth_required=auth_required, auth_info=auth_info,
                source_file=rel_path, line_number=lineno, framework="Express", language="javascript",
            ))

    def parse_file(self, filepath: str, rel_path: str) -> List[RouteEndpoint]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            return []

        endpoints: List[RouteEndpoint] = []
        for lineno, line in _logical_lines(text):
            # Chained: x.route('/p').get(...).post(...)
            handled_chain = False
            for cm in _ROUTE_CHAIN_RE.finditer(line):
                handled_chain = True
                obj, route_path = cm.group(1), cm.group("path")
                tail = line[cm.end():]
                for vm in _VERB_CALL_RE.finditer(tail):
                    verb = vm.group(1).upper()
                    args_str = _extract_balanced(tail, vm.end() - 1)
                    self._emit(obj, verb, route_path, args_str, lineno, rel_path, endpoints)

            if handled_chain:
                continue

            # Direct: x.get('/p', mw, handler)
            m = _ROUTE_RE.search(line)
            if m:
                self._emit(m.group(1), m.group(2).upper(), m.group("path"),
                           m.group("rest") or "", lineno, rel_path, endpoints)
        return endpoints
