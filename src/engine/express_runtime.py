"""
Runtime-assisted Express discovery.

Static parsing of Express (see ``express.py``) structurally misses
dynamically-registered routes. This module instead loads the running app and
enumerates its *actual* router stack via a small Node introspection script,
then maps the result into the same ``RouteEndpoint`` model the rest of the
pipeline uses. Auth is inferred from the real middleware chain attached to each
route — including ``app.use(...)`` / ``router.use(...)`` middleware that no
static parser can attribute reliably.

This requires Node.js on PATH and that the target codebase's dependencies are
installed (so its entry module can be ``require``d). It degrades gracefully:
callers get a clear ``RuntimeDiscoveryError`` rather than a silent empty result.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List, Optional

from .authconfig import AuthConfig
from .parser import normalize_path
from .schemas import RouteEndpoint

_INTROSPECT_SCRIPT = os.path.join(os.path.dirname(__file__), "runtime", "express_introspect.js")


class RuntimeDiscoveryError(RuntimeError):
    pass


def node_available(node_path: str = "node") -> bool:
    return shutil.which(node_path) is not None


def discover_express_routes(
    entry_path: str,
    auth_config: Optional[AuthConfig] = None,
    node_path: str = "node",
    timeout: float = 30.0,
) -> List[RouteEndpoint]:
    """
    Run the Node introspector against an Express app entry file and return the
    discovered endpoints as RouteEndpoints.
    """
    auth_config = auth_config or AuthConfig()

    if not node_available(node_path):
        raise RuntimeDiscoveryError(
            f"Node.js executable '{node_path}' not found on PATH. Runtime discovery requires Node."
        )
    if not os.path.exists(entry_path):
        raise RuntimeDiscoveryError(f"Express entry file not found: {entry_path}")
    if not os.path.exists(_INTROSPECT_SCRIPT):
        raise RuntimeDiscoveryError(f"Introspection script missing: {_INTROSPECT_SCRIPT}")

    try:
        proc = subprocess.run(
            [node_path, _INTROSPECT_SCRIPT, os.path.abspath(entry_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeDiscoveryError(
            f"Express introspection timed out after {timeout}s. Does the entry start a blocking process?"
        ) from e

    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise RuntimeDiscoveryError(
            f"Introspector produced no output (exit {proc.returncode}). stderr: {proc.stderr.strip()}"
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeDiscoveryError(
            f"Could not parse introspector output as JSON: {e}. Raw: {stdout[:300]}"
        ) from e

    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeDiscoveryError(payload["error"])

    raw_routes = payload.get("routes", []) if isinstance(payload, dict) else []
    rel_source = os.path.basename(entry_path)

    endpoints: List[RouteEndpoint] = []
    for item in raw_routes:
        middleware = item.get("middleware", []) or []
        auth_hit = next((mw for mw in middleware if auth_config.express_middleware_match(mw)), None)
        auth_required = auth_hit is not None
        auth_info = None
        if auth_required:
            auth_info = f"runtime middleware: {auth_hit} (chain: {', '.join(middleware)})"

        endpoints.append(RouteEndpoint(
            path=normalize_path(item.get("path", "/")),
            method=item.get("method", "GET"),
            auth_required=auth_required,
            auth_info=auth_info,
            # Runtime discovery has no source line; 0 signals "discovered at runtime".
            source_file=rel_source,
            line_number=0,
            framework="Express",
            language="javascript",
        ))
    return endpoints
