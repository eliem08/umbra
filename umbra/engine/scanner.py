"""
Multi-language scan dispatcher.

Routes a path to the appropriate parser(s) and merges the results into a single
ScanResult:

- ``.py``                      -> Python AST parser (FastAPI / Flask)
- ``.java``                    -> Spring Boot parser
- ``.js/.jsx/.ts/.tsx/...``    -> Express parser

For a directory, all three parsers run (each filters by file extension), so a
polyglot monorepo is scanned in one pass. For a single file, the parser is
chosen by extension.
"""
from __future__ import annotations

import os
from typing import Optional

from .authconfig import AuthConfig, load_auth_config
from .parser import ASTParser
from .spring import SpringParser
from .express import ExpressParser, JS_EXTENSIONS
from .express_runtime import discover_express_routes
from .fsutil import iter_source_files, DEFAULT_EXCLUDE_DIRS
from .schemas import ScanResult

_ALL_EXTS = (".py", ".java") + JS_EXTENSIONS


def scan_path(
    path: str,
    auth_config: Optional[AuthConfig] = None,
    express_entry: Optional[str] = None,
    exclude_dirs: Optional[set] = None,
) -> ScanResult:
    """
    Scan a file or directory across all supported languages.

    The filesystem is walked exactly once; files are bucketed by language and
    handed to the relevant parser, which avoids re-walking the tree per parser.

    When `express_entry` is given, Express routes are discovered at runtime by
    introspecting the live app (catching dynamically-registered routes), and
    those *replace* statically-parsed JavaScript routes — runtime is
    authoritative for Express.
    """
    if auth_config is None:
        auth_config = load_auth_config(path)
    excludes = DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs

    routes = []

    if os.path.isfile(path):
        lower = path.lower()
        if lower.endswith(".py"):
            routes = ASTParser(path, auth_config=auth_config).parse_directory().routes
        elif lower.endswith(".java"):
            routes = SpringParser(path, auth_config=auth_config).parse_directory().routes
        elif lower.endswith(JS_EXTENSIONS):
            routes = ExpressParser(path, auth_config=auth_config).parse_directory().routes
    else:
        # Single filesystem walk, bucketed by language.
        py_files, java_files, js_files = [], [], []
        for full, rel in iter_source_files(path, _ALL_EXTS, excludes):
            low = full.lower()
            if low.endswith(".py"):
                py_files.append((full, rel))
            elif low.endswith(".java"):
                java_files.append((full, rel))
            elif low.endswith(JS_EXTENSIONS):
                js_files.append((full, rel))

        routes.extend(ASTParser(path, auth_config=auth_config, exclude_dirs=excludes).parse_directory(py_files).routes)
        routes.extend(SpringParser(path, auth_config=auth_config, exclude_dirs=excludes).parse_directory(java_files).routes)
        routes.extend(ExpressParser(path, auth_config=auth_config, exclude_dirs=excludes).parse_directory(js_files).routes)

    if express_entry:
        runtime_routes = discover_express_routes(express_entry, auth_config=auth_config)
        # Drop statically-parsed JS routes; runtime discovery supersedes them.
        routes = [r for r in routes if r.language != "javascript"] + runtime_routes

    return ScanResult(routes=routes)
