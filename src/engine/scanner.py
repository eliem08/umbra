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
from .schemas import ScanResult


def scan_path(
    path: str,
    auth_config: Optional[AuthConfig] = None,
    express_entry: Optional[str] = None,
) -> ScanResult:
    """
    Scan a file or directory across all supported languages.

    When `express_entry` is given, Express routes are discovered at runtime by
    introspecting the live app (catching dynamically-registered routes), and
    those *replace* statically-parsed JavaScript routes — runtime is
    authoritative for Express.
    """
    if auth_config is None:
        auth_config = load_auth_config(path)

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
        # Directory: run every parser; each only touches files it understands.
        routes.extend(ASTParser(path, auth_config=auth_config).parse_directory().routes)
        routes.extend(SpringParser(path, auth_config=auth_config).parse_directory().routes)
        routes.extend(ExpressParser(path, auth_config=auth_config).parse_directory().routes)

    if express_entry:
        runtime_routes = discover_express_routes(express_entry, auth_config=auth_config)
        # Drop statically-parsed JS routes; runtime discovery supersedes them.
        routes = [r for r in routes if r.language != "javascript"] + runtime_routes

    return ScanResult(routes=routes)
