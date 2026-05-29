import os
import json
import logging
import difflib
import secrets
from typing import List, Dict, Any, Optional, Set

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Mount

from mcp.server import Server, NotificationOptions
from mcp.server.sse import SseServerTransport
from mcp.server.models import InitializationOptions
import mcp.types as types

from umbra.engine.parser import ASTParser, normalize_path
from umbra.engine.matcher import OpenAPIMatcher
from umbra.engine.schemas import RouteEndpoint, ScanResult
from umbra.engine.scanner import scan_path
from umbra.engine.gitdiff import annotate_new_endpoints, GitError

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShadowScanMCPServer")

# 1. Initialize MCP low-level Server
server = Server("shadow-api-scanner")

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """
    Exposes explicit JSON Schema definitions with natural-language description fields
    to ensure the consuming LLM has the exact semantic context it needs to call tools.
    """
    return [
        types.Tool(
            name="scan_codebase",
            description="Statically scans the target codebase directory and identifies all routes, parameters, and authentication middleware across FastAPI, Flask, Spring Boot, and Express.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The absolute path to the local directory containing the codebase (Python/Java/JavaScript) to scan."
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="list_new_unauthenticated",
            description=(
                "Lists endpoints introduced or changed within a git window (e.g. 'this week') "
                "that lack active bearer-token validation or authorization middleware. "
                "Use this for system health checks like 'what did we ship this week that is unprotected?'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The absolute path to the local git repository / codebase directory to scan."
                    },
                    "since": {
                        "type": "string",
                        "description": "Git window: a date or relative date ('1 week ago', '2026-05-01') or a baseline revision ('origin/main'). Defaults to '1 week ago'."
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="compare_posture",
            description="Compares identified codebase routes against a production OpenAPI schema to detect undocumented shadow APIs and compute documentation coverage.",
            inputSchema={
                "type": "object",
                "properties": {
                    "codebase_routes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "description": "A dictionary representing a parsed codebase route endpoint matching the RouteEndpoint schema."
                        },
                        "description": "The list of parsed route endpoint dictionaries obtained from a previous scan_codebase execution."
                    },
                    "openapi_url": {
                        "type": "string",
                        "description": "The URL, local file path, or raw JSON string of the production openapi.json file."
                    }
                },
                "required": ["codebase_routes", "openapi_url"]
            }
        ),
        types.Tool(
            name="get_remediation_diff",
            description="Generates a proposed git unified diff patch to inject token-based authentication middleware into a specified python file containing a shadow endpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "route": {
                        "type": "string",
                        "description": "A JSON string or formatted text representation of the shadow route endpoint details (containing file, line, and framework info)."
                    }
                },
                "required": ["route"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> types.CallToolResult:
    """
    Handles execution of the registered MCP tools.
    """
    logger.info(f"Received call_tool request for: '{name}' with arguments: {arguments}")
    
    if name == "scan_codebase":
        path = arguments.get("path")
        if not path:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text="Error: Missing required argument 'path'")]
            )
        try:
            scan_result = scan_path(path)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=scan_result.model_dump_json(indent=2))]
            )
        except Exception as e:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"Error executing scan_codebase: {str(e)}")]
            )

    elif name == "list_new_unauthenticated":
        path = arguments.get("path")
        since = arguments.get("since") or "1 week ago"
        if not path:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text="Error: Missing required argument 'path'")]
            )
        try:
            scan_result = scan_path(path)
            try:
                annotate_new_endpoints(scan_result.routes, path, since)
            except GitError as ge:
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text=f"Git error: {ge}")]
                )
            offenders = [r for r in scan_result.routes if r.is_new and not r.auth_required]
            payload = {
                "since": since,
                "new_unauthenticated_count": len(offenders),
                "endpoints": [r.model_dump() for r in offenders],
            }
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(payload, indent=2))]
            )
        except Exception as e:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"Error executing list_new_unauthenticated: {str(e)}")]
            )

    elif name == "compare_posture":
        codebase_routes = arguments.get("codebase_routes")
        openapi_url = arguments.get("openapi_url")
        if codebase_routes is None or openapi_url is None:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text="Error: Missing required 'codebase_routes' or 'openapi_url'")]
            )
        try:
            # Parse list of route endpoints back into Pydantic models
            routes = [RouteEndpoint(**r) for r in codebase_routes]
            scan_result = ScanResult(routes=routes)
            
            # Execute comparison posture logic
            matcher = OpenAPIMatcher(openapi_url)
            report = matcher.generate_report(scan_result)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=report.model_dump_json(indent=2))]
            )
        except Exception as e:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"Error executing compare_posture: {str(e)}")]
            )

    elif name == "get_remediation_diff":
        route_str = arguments.get("route")
        if not route_str:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text="Error: Missing required argument 'route'")]
            )
        try:
            # Load route endpoint descriptor
            route_dict = {}
            if route_str.strip().startswith("{"):
                route_dict = json.loads(route_str)
            else:
                # Try parsing as a simpler text representation if not JSON
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text="Error: Route argument must be a JSON string.")]
                )
            
            source_file = route_dict.get("source_file")
            line_number = route_dict.get("line_number")
            framework = route_dict.get("framework", "FastAPI")
            path = route_dict.get("path")
            method = route_dict.get("method", "GET")
            
            if not source_file or not line_number:
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text="Error: Route descriptor must contain 'source_file' and 'line_number'")]
                )
                
            diff_patch = generate_remediation_patch(source_file, int(line_number), framework, path, method)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=diff_patch)]
            )
        except Exception as e:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"Error executing get_remediation_diff: {str(e)}")]
            )

    else:
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Error: Unknown tool '{name}'")]
        )


def generate_remediation_patch(source_file: str, line_number: int, framework: str, path: str, method: str) -> str:
    """
    Generates a unified git patch that inserts authentication middleware to secure a route.
    """
    # Attempt to resolve the file path in current directory or parent directory
    resolved_path = os.path.abspath(source_file)
    if not os.path.exists(resolved_path):
        # Check relative path
        if os.path.exists(os.path.join(os.getcwd(), source_file)):
            resolved_path = os.path.join(os.getcwd(), source_file)
        else:
            # Return generic mockup patch if file does not exist locally
            return f"""--- a/{source_file}
+++ b/{source_file}
@@ -{line_number},3 +{line_number},4 @@
# Generic Remediation Patch for {framework} Endpoint
# Target: {method} {path}
# Action: Inject authentication token validation controls.
"""

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            original_lines = f.readlines()
    except Exception as e:
        return f"# Error reading file {source_file}: {e}"

    idx = line_number - 1
    if idx < 0 or idx >= len(original_lines):
        return f"# Error: Line number {line_number} is out of bounds for {source_file}"

    modified_lines = original_lines.copy()

    # Search upwards for the route decorator line
    decorator_idx = -1
    for i in range(min(idx, len(original_lines) - 1), max(-1, idx - 10), -1):
        line = original_lines[i].strip()
        if line.startswith("@") and ("route" in line or method.lower() in line):
            decorator_idx = i
            break

    if framework == "FastAPI":
        # 1. Ensure Depends import exists
        has_depends = any("Depends" in l for l in original_lines)
        if not has_depends:
            insert_idx = 0
            for i, l in enumerate(modified_lines):
                if not l.strip().startswith("#") and l.strip():
                    insert_idx = i
                    break
            modified_lines.insert(insert_idx, "from fastapi import Depends\n")
            if decorator_idx >= insert_idx:
                decorator_idx += 1
                
        # 2. Modify decorator to inject dependencies=[Depends(verify_token)]
        if decorator_idx != -1:
            dec_line = modified_lines[decorator_idx]
            if "dependencies=" not in dec_line:
                if dec_line.strip().endswith(")"):
                    open_paren = dec_line.find("(")
                    close_paren = dec_line.rfind(")")
                    if open_paren != -1 and close_paren != -1:
                        inner = dec_line[open_paren + 1:close_paren].strip()
                        if inner:
                            new_dec = dec_line[:close_paren] + ", dependencies=[Depends(verify_token)])" + dec_line[close_paren + 1:]
                        else:
                            new_dec = dec_line[:open_paren + 1] + "dependencies=[Depends(verify_token)])" + dec_line[close_paren + 1:]
                        modified_lines[decorator_idx] = new_dec
    else:
        # Flask remediation
        # 1. Ensure jwt_required import exists
        has_jwt = any("jwt_required" in l for l in original_lines)
        if not has_jwt:
            insert_idx = 0
            for i, l in enumerate(modified_lines):
                if not l.strip().startswith("#") and l.strip():
                    insert_idx = i
                    break
            modified_lines.insert(insert_idx, "from flask_jwt_extended import jwt_required\n")
            if decorator_idx >= insert_idx:
                decorator_idx += 1
                
        # 2. Inject @jwt_required() decorator directly below route decorator
        if decorator_idx != -1:
            line = modified_lines[decorator_idx]
            indent = len(line) - len(line.lstrip())
            indent_str = " " * indent
            modified_lines.insert(decorator_idx + 1, f"{indent_str}@jwt_required()\n")

    # Generate standard git unified diff
    diff = list(difflib.unified_diff(
        original_lines,
        modified_lines,
        fromfile=f"a/{source_file}",
        tofile=f"b/{source_file}",
        lineterm=""
    ))
    return "\n".join(diff)


def _valid_tokens() -> Set[str]:
    """
    Reads accepted tokens from the environment. Supports a single
    SHADOW_SCAN_TOKEN and/or a comma-separated SHADOW_SCAN_TOKENS for basic
    multi-tenant key rotation. No hardcoded fallback: if nothing is configured
    the server fails closed (deny all) rather than shipping a known default.
    """
    tokens: Set[str] = set()
    single = os.environ.get("SHADOW_SCAN_TOKEN", "").strip()
    if single:
        tokens.add(single)
    multi = os.environ.get("SHADOW_SCAN_TOKENS", "")
    for tok in multi.split(","):
        tok = tok.strip()
        if tok:
            tokens.add(tok)
    return tokens


def _token_is_valid(presented: Optional[str]) -> bool:
    """Constant-time comparison against every configured token."""
    if not presented:
        return False
    valid = _valid_tokens()
    if not valid:
        return False
    # compare_digest against each candidate; OR the results without short-circuit.
    matched = False
    for tok in valid:
        if secrets.compare_digest(presented, tok):
            matched = True
    return matched


# --- Token Authorization Middleware ---
class TokenAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware verifying token auth for the SSE endpoints.
    Allows authentication via 'Authorization: Bearer <token>' header OR '?token=<token>' query parameter.
    Fails closed: requests are rejected with 401 unless they present a configured token.
    """
    async def dispatch(self, request: Request, call_next):
        # We protect the /sse and /messages paths specifically
        if request.url.path in ("/sse", "/messages"):
            if not _valid_tokens():
                logger.error(
                    "Rejecting request: no SHADOW_SCAN_TOKEN/SHADOW_SCAN_TOKENS configured. "
                    "Set one before exposing the server."
                )
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized: server has no authentication token configured."}
                )

            auth_token = None
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                auth_token = auth_header.split(" ", 1)[1]
            else:
                auth_token = request.query_params.get("token")

            if not _token_is_valid(auth_token):
                logger.warning(f"Unauthorized access attempt to {request.url.path} from client {request.client}")
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized: Invalid or missing authentication token."}
                )

        return await call_next(request)


# --- FastAPI Host Application ---
app = FastAPI(title="Umbra MCP Host")

# CORS: explicit allowlist via SHADOW_SCAN_CORS_ORIGINS (comma-separated).
# Defaults to no cross-origin access. Wildcard "*" is permitted but, per the CORS
# spec, is incompatible with credentialed requests, so credentials are disabled
# whenever the wildcard is used to avoid the unsafe `*` + credentials combination.
_cors_origins = [o.strip() for o in os.environ.get("SHADOW_SCAN_CORS_ORIGINS", "").split(",") if o.strip()]
_allow_credentials = bool(_cors_origins) and "*" not in _cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Apply Token Verification Middleware
app.add_middleware(TokenAuthMiddleware)

# Optional x402 payment gate (monetize per-call MCP access) via the official
# x402 SDK. No-op unless UMBRA_X402_ENABLED is set. Added after TokenAuth so it
# runs first on the request path: pay, then authenticate. Requires the optional
# dependency: pip install "umbra-scan[x402]".
from umbra.mcp.payments import apply_x402  # noqa: E402
apply_x402(app)

# Initialize SSE Transport
# POST requests go to /messages
sse = SseServerTransport("/messages")

# Mount messages post handler
app.router.routes.append(Mount("/messages", app=sse.handle_post_message))


@app.get("/")
async def health(request: Request):
    """Unauthenticated health/readiness endpoint (used by Apify Standby probes)."""
    return JSONResponse({
        "service": "umbra-mcp",
        "status": "ok",
        "endpoints": {"sse": "/sse", "messages": "/messages"},
    })


@app.get("/sse")
async def handle_sse(request: Request):
    """
    Establishes Server-Sent Events stream connection and executes the MCP server.
    """
    logger.info("New SSE client connection initiated.")
    async with sse.connect_sse(request.scope, request.receive, request._send) as (
        read_stream,
        write_stream,
    ):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="shadow-api-scanner",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
