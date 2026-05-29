import os
import json
import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from src.engine.parser import ASTParser, normalize_path
from src.engine.matcher import OpenAPIMatcher
from src.engine.schemas import RouteEndpoint, ScanResult
from src.engine.agent_bridge import redact_payload, redact_text, redact_credentials_hook
from src.cli.main import main as cli_main
from src.mcp.server import app as mcp_app, server as mcp_server, handle_list_tools, handle_call_tool

# Path helper for mock project files
MOCK_DIR = os.path.join(os.path.dirname(__file__), "mock_project")
OPENAPI_FILE = os.path.join(MOCK_DIR, "openapi.json")


def test_path_normalization():
    """Ensure path parameters from FastAPI, Flask, and OpenAPI normalize to canonical :param format."""
    assert normalize_path("/users/{id}") == "/users/:id"
    assert normalize_path("/users/<int:id>") == "/users/:id"
    assert normalize_path("/users/<username>") == "/users/:username"
    assert normalize_path("/users/{id}/profile/") == "/users/:id/profile"
    assert normalize_path("/") == "/"


def test_ast_parser_fastapi():
    """Test AST static parsing on FastAPI mock application."""
    parser = ASTParser(os.path.join(MOCK_DIR, "app_fastapi.py"))
    scan_result = parser.parse_directory()
    routes = scan_result.routes
    
    assert len(routes) == 3
    
    # Verify GET /api/v1/users/:id (Authorized)
    get_user = next(r for r in routes if r.path == "/api/v1/users/:id" and r.method == "GET")
    assert get_user.auth_required is True
    assert "Depends(verify_token)" in get_user.auth_info
    assert get_user.framework == "FastAPI"

    # Verify GET /healthz (Public)
    get_health = next(r for r in routes if r.path == "/healthz" and r.method == "GET")
    assert get_health.auth_required is False
    assert get_health.framework == "FastAPI"

    # Verify POST /api/v1/debug-dump (Shadow / No Auth)
    post_debug = next(r for r in routes if r.path == "/api/v1/debug-dump" and r.method == "POST")
    assert post_debug.auth_required is False
    assert post_debug.framework == "FastAPI"


def test_ast_parser_flask():
    """Test AST static parsing on Flask mock application."""
    parser = ASTParser(os.path.join(MOCK_DIR, "app_flask.py"))
    scan_result = parser.parse_directory()
    routes = scan_result.routes

    assert len(routes) == 3

    # Verify GET /api/v1/items (Authorized)
    get_items = next(r for r in routes if r.path == "/api/v1/items" and r.method == "GET")
    assert get_items.auth_required is True
    assert "jwt_required" in get_items.auth_info
    assert get_items.framework == "Flask"

    # Verify GET /info (Public)
    get_info = next(r for r in routes if r.path == "/info" and r.method == "GET")
    assert get_info.auth_required is False
    assert get_info.framework == "Flask"

    # Verify GET /api/v1/internal-status (Shadow / No Auth)
    get_status = next(r for r in routes if r.path == "/api/v1/internal-status" and r.method == "GET")
    assert get_status.auth_required is False
    assert get_status.framework == "Flask"


def test_openapi_matcher():
    """Test path matching, coverage calculation, and shadow API identification."""
    parser = ASTParser(MOCK_DIR)
    scan_result = parser.parse_directory()
    
    # Ingest openapi.json
    matcher = OpenAPIMatcher(OPENAPI_FILE)
    report = matcher.generate_report(scan_result)

    # 6 total routes parsed (3 FastAPI, 3 Flask)
    assert report.parsed_routes_count == 6
    assert report.registered_routes_count == 4

    # Shadow APIs expected:
    # 1. POST /api/v1/debug-dump
    # 2. GET /api/v1/internal-status
    shadow_paths = {r.path for r in report.shadow_endpoints}
    assert "/api/v1/debug-dump" in shadow_paths
    assert "/api/v1/internal-status" in shadow_paths
    assert len(report.shadow_endpoints) == 2

    # Coverage ratio: 4 routes match out of 6 total in code = 66.67%
    # Unique parsed sets:
    # (GET, /api/v1/users/:id) - match
    # (GET, /healthz) - match
    # (POST, /api/v1/debug-dump) - shadow
    # (GET, /api/v1/items) - match
    # (GET, /info) - match
    # (GET, /api/v1/internal-status) - shadow
    # Unique codebase routes = 6, matches = 4. Ratio = 4/6 = 0.6666...
    assert pytest.approx(report.coverage_ratio, 0.01) == 0.67

    # Missing auth endpoints (no auth):
    # - /healthz (FastAPI public)
    # - /api/v1/debug-dump (FastAPI shadow)
    # - /info (Flask public)
    # - /api/v1/internal-status (Flask shadow)
    assert len(report.missing_auth_endpoints) == 4


def test_cli_dashboard():
    """Test the CLI dashboard execution and exit codes under strict CI/CD constraints."""
    runner = CliRunner()

    # 1. Normal mode (returns 0 even with shadow APIs)
    result = runner.invoke(cli_main, ["--path", MOCK_DIR, "--openapi", OPENAPI_FILE])
    assert result.exit_code == 0
    assert "Summary Statistics" in result.output
    assert "Detected Shadow Endpoints" in result.output

    # 2. Strict mode (should fail and return 1 due to shadow APIs and auth violations)
    strict_result = runner.invoke(cli_main, ["--path", MOCK_DIR, "--openapi", OPENAPI_FILE, "--strict"])
    assert strict_result.exit_code == 1
    assert "SCAN FAILED" in strict_result.output


def test_antigravity_bridge_redaction():
    """Verify Google Antigravity custom hook redacts tokens, JWTs, and PII recursively."""
    dirty_text = (
        "Here is the database secret: api_key='super-secret-key-999'\n"
        "And the User auth JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMiJ9.abc\n"
        "Contact security admin at support@company.com immediately."
    )

    clean_text = redact_text(dirty_text)
    assert "[REDACTED_SECRET]" in clean_text
    assert "[REDACTED_JWT]" in clean_text
    assert "[REDACTED_EMAIL]" in clean_text
    assert "super-secret-key-999" not in clean_text
    assert "support@company.com" not in clean_text

    # Test recursive payload redactor
    payload = {
        "metadata": {
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiYm9iIn0.xyz",
            "db_secret": "password = 'admin-password-1234'"
        },
        "emails": ["user1@company.com", "user2@company.com"],
        "safe_field": 42
    }
    redacted = redact_payload(payload)
    assert redacted["metadata"]["token"] == "[REDACTED_JWT]"
    assert "admin-password-1234" not in redacted["metadata"]["db_secret"]
    assert redacted["emails"] == ["[REDACTED_EMAIL]", "[REDACTED_EMAIL]"]
    assert redacted["safe_field"] == 42


def test_parser_and_matcher_hard_cases(tmp_path):
    """Test cross-file Blueprint/Router prefixes, tuple methods, and name-agnostic path parameter matching."""
    app_file = tmp_path / "main.py"
    router_file = tmp_path / "routes.py"
    
    # Write main.py with include_router prefix
    app_file.write_text("""
from fastapi import FastAPI
from routes import my_router
app = FastAPI()
app.include_router(my_router, prefix="/api/v3")
""")
    
    # Write routes.py with a route using a tuple method
    router_file.write_text("""
from fastapi import APIRouter
my_router = APIRouter()
@my_router.route("/items/{item_id}", methods=("GET", "POST"))
def handle_item(item_id: int):
    return {}
""")
    
    parser = ASTParser(str(tmp_path))
    scan_result = parser.parse_directory()
    routes = scan_result.routes
    
    # Since prefix scanning resolves 'my_router' -> '/api/v3',
    # and /items/{item_id} -> /items/:item_id,
    # the resolved path should be /api/v3/items/:item_id for both GET and POST!
    assert len(routes) == 2
    get_route = next(r for r in routes if r.method == "GET")
    post_route = next(r for r in routes if r.method == "POST")
    
    assert get_route.path == "/api/v3/items/:item_id"
    assert post_route.path == "/api/v3/items/:item_id"
    
    # 2. Test Parameter-name-agnostic matching
    # Let's say codebase path parameter is 'item_id' and openapi path is 'id'
    mock_openapi = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v3/items/{id}": {
                "get": {},
                "post": {}
            }
        }
    }
    
    matcher = OpenAPIMatcher(mock_openapi)
    report = matcher.generate_report(scan_result)
    
    # Both routes should match successfully (coverage ratio = 1.0) because of shape matching!
    assert report.coverage_ratio == 1.0
    assert len(report.shadow_endpoints) == 0


def test_redactor_hard_cases():
    """Verify credentials redactor does not over-redact safe keywords but cleans nested secrets."""
    payload = {
        "token_type": "Bearer",
        "verify_token_endpoint": "/auth/verify",
        "nested": [
            "Normal text without secrets",
            "Support email support@gmail.com",
            {"key_assignment": "secret_key = 'super-secret-key-xyz'"}
        ]
    }
    redacted = redact_payload(payload)
    
    # Safe fields preserved
    assert redacted["token_type"] == "Bearer"
    assert redacted["verify_token_endpoint"] == "/auth/verify"
    assert redacted["nested"][0] == "Normal text without secrets"
    
    # Secret values and emails redacted correctly
    assert redacted["nested"][1] == "Support email [REDACTED_EMAIL]"
    assert "super-secret-key-xyz" not in redacted["nested"][2]["key_assignment"]
    assert "[REDACTED_SECRET]" in redacted["nested"][2]["key_assignment"]


@pytest.mark.asyncio
async def test_mcp_tool_definitions():
    """Verify tool schemas are explicitly defined with detailed natural-language description fields."""
    tools = await handle_list_tools()
    assert len(tools) == 4

    new_tool = next(t for t in tools if t.name == "list_new_unauthenticated")
    assert "introduced" in new_tool.description.lower()

    scan_tool = next(t for t in tools if t.name == "scan_codebase")
    assert "The absolute path to the local directory" in scan_tool.inputSchema["properties"]["path"]["description"]

    posture_tool = next(t for t in tools if t.name == "compare_posture")
    assert "The list of parsed route endpoint dictionaries" in posture_tool.inputSchema["properties"]["codebase_routes"]["description"]
    assert "The URL, local file path, or raw JSON string" in posture_tool.inputSchema["properties"]["openapi_url"]["description"]

    diff_tool = next(t for t in tools if t.name == "get_remediation_diff")
    assert "A JSON string or formatted text representation" in diff_tool.inputSchema["properties"]["route"]["description"]


@pytest.mark.asyncio
async def test_mcp_tool_execution():
    """Verify low-level MCP server handlers call underlying engines and generate remediation patches."""
    # Test scan_codebase tool
    scan_res = await handle_call_tool("scan_codebase", {"path": MOCK_DIR})
    assert scan_res.isError is not True
    routes_json = json.loads(scan_res.content[0].text)
    assert "routes" in routes_json
    assert len(routes_json["routes"]) == 6

    # Test compare_posture tool
    compare_res = await handle_call_tool("compare_posture", {
        "codebase_routes": routes_json["routes"],
        "openapi_url": OPENAPI_FILE
    })
    assert compare_res.isError is not True
    report_json = json.loads(compare_res.content[0].text)
    assert report_json["parsed_routes_count"] == 6
    assert len(report_json["shadow_endpoints"]) == 2

    # Test get_remediation_diff tool
    shadow_endpoint = report_json["shadow_endpoints"][0]
    # Inject workspace directory into source_file so it runs on actual files
    shadow_endpoint["source_file"] = os.path.join(MOCK_DIR, os.path.basename(shadow_endpoint["source_file"]))
    
    diff_res = await handle_call_tool("get_remediation_diff", {
        "route": json.dumps(shadow_endpoint)
    })
    assert diff_res.isError is not True
    diff_text = diff_res.content[0].text
    
    # Patch should contain unified diff headers
    assert "---" in diff_text
    assert "+++" in diff_text
    assert "Depends(verify_token)" in diff_text or "jwt_required" in diff_text


def test_mcp_server_token_authorization_middleware(monkeypatch):
    """Verify Token Authorization Middleware protects SSE and messages endpoints."""
    from unittest.mock import AsyncMock
    monkeypatch.setattr(mcp_server, "run", AsyncMock())

    # Set expected token
    os.environ["SHADOW_SCAN_TOKEN"] = "test-token-value"
    
    # Create test client
    client = TestClient(mcp_app)

    # 1. Missing Token on /sse -> 401
    resp_sse_missing = client.get("/sse")
    assert resp_sse_missing.status_code == 401
    assert "Unauthorized" in resp_sse_missing.json()["detail"]

    # 2. Invalid Token on /sse -> 401
    resp_sse_invalid = client.get("/sse?token=wrong-token")
    assert resp_sse_invalid.status_code == 401

    # 3. Invalid Token via query parameter on POST /messages -> 401
    resp_msg_invalid_query = client.post("/messages?token=wrong-token", json={})
    assert resp_msg_invalid_query.status_code == 401

    # 5. Invalid Token on /messages POST -> 401
    resp_msg_invalid = client.post("/messages", json={"dummy": "data"})
    assert resp_msg_invalid.status_code == 401

    # 6. Valid Token on /messages POST -> passes middleware (fails in router due to invalid MCP frame, but not 401)
    # Since we send empty JSON, the MCP transport will raise a 400/500 parsing error, not a 401.
    resp_msg_valid = client.post("/messages", json={}, headers={"Authorization": "Bearer test-token-value"})
    assert resp_msg_valid.status_code != 401
