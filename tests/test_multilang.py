import os
import json
import shutil
import subprocess
import pytest

from src.engine.scanner import scan_path
from src.engine.spring import SpringParser
from src.engine.express import ExpressParser
from src.engine.express_runtime import discover_express_routes, RuntimeDiscoveryError, node_available
from src.engine.authconfig import AuthConfig, load_auth_config
from src.engine.reporters import report_to_sarif, render_report
from src.engine.matcher import OpenAPIMatcher
from src.engine.gitdiff import GitInspector, annotate_new_endpoints, GitError
from src.engine.schemas import ScanResult

POLY_DIR = os.path.join(os.path.dirname(__file__), "mock_polyglot")
MOCK_DIR = os.path.join(os.path.dirname(__file__), "mock_project")
RUNTIME_ENTRY = os.path.join(POLY_DIR, "runtime_app.js")

GIT_AVAILABLE = shutil.which("git") is not None
NODE_AVAILABLE = node_available()


# --------------------------------------------------------------------------- #
# Spring Boot parser
# --------------------------------------------------------------------------- #
def test_spring_parser():
    parser = SpringParser(os.path.join(POLY_DIR, "UserController.java"))
    routes = parser.parse_directory().routes
    by_key = {(r.method, r.path): r for r in routes}

    assert ("GET", "/api/v1/users/:id") in by_key
    assert by_key[("GET", "/api/v1/users/:id")].auth_required is True
    assert by_key[("GET", "/api/v1/users/:id")].framework == "Spring Boot"
    assert by_key[("GET", "/api/v1/users/:id")].language == "java"

    # POST inherits the class prefix and has no auth annotation
    assert ("POST", "/api/v1/users") in by_key
    assert by_key[("POST", "/api/v1/users")].auth_required is False

    # Generic @RequestMapping with method=RequestMethod.GET
    assert ("GET", "/api/v1/users/search") in by_key
    assert by_key[("GET", "/api/v1/users/search")].auth_required is False


# --------------------------------------------------------------------------- #
# Express parser
# --------------------------------------------------------------------------- #
def test_express_parser_with_mount_prefix():
    parser = ExpressParser(POLY_DIR)
    routes = parser.parse_directory().routes
    by_key = {(r.method, r.path): r for r in routes}

    # router is mounted at /api, so router routes inherit the prefix
    assert ("GET", "/api/profile") in by_key
    assert by_key[("GET", "/api/profile")].auth_required is True  # requireAuth middleware
    assert by_key[("GET", "/api/profile")].framework == "Express"

    assert ("POST", "/api/public-comment") in by_key
    assert by_key[("POST", "/api/public-comment")].auth_required is False

    assert ("GET", "/api/admin/:section") in by_key
    assert by_key[("GET", "/api/admin/:section")].auth_required is False

    # Direct app route, no prefix
    assert ("GET", "/health") in by_key
    assert by_key[("GET", "/health")].auth_required is False


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
def test_scan_path_polyglot_directory():
    result = scan_path(POLY_DIR)
    frameworks = {r.framework for r in result.routes}
    assert "Spring Boot" in frameworks
    assert "Express" in frameworks
    # 3 Java + 4 Express endpoints
    assert len(result.routes) == 7


def test_scan_path_python_only_unchanged():
    """The dispatcher must produce the same 6 routes as the original Python parser."""
    result = scan_path(MOCK_DIR)
    assert len(result.routes) == 6
    assert {r.framework for r in result.routes} == {"FastAPI", "Flask"}


# --------------------------------------------------------------------------- #
# Runtime-assisted Express discovery
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not NODE_AVAILABLE, reason="node not installed")
def test_express_runtime_discovery():
    routes = discover_express_routes(RUNTIME_ENTRY)
    by_key = {(r.method, r.path): r for r in routes}

    assert ("GET", "/health") in by_key
    assert by_key[("GET", "/health")].auth_required is False

    # Auth inferred from the real middleware chain (requireAuth).
    assert ("GET", "/api/secure") in by_key
    assert by_key[("GET", "/api/secure")].auth_required is True

    assert ("POST", "/api/open") in by_key
    assert by_key[("POST", "/api/open")].auth_required is False

    # The payoff: dynamically-generated routes that static parsing cannot see.
    assert ("GET", "/api/orders/:id") in by_key
    assert ("GET", "/api/invoices/:id") in by_key

    # line_number 0 marks a runtime-discovered route.
    assert all(r.line_number == 0 for r in routes)
    assert all(r.framework == "Express" for r in routes)


@pytest.mark.skipif(not NODE_AVAILABLE, reason="node not installed")
def test_scan_path_runtime_supersedes_static_js():
    result = scan_path(POLY_DIR, express_entry=RUNTIME_ENTRY)
    js = {(r.method, r.path) for r in result.routes if r.language == "javascript"}
    java = [r for r in result.routes if r.language == "java"]

    # Java still parsed statically alongside runtime JS.
    assert len(java) == 3
    # Runtime-discovered dynamic route is present...
    assert ("GET", "/api/orders/:id") in js
    # ...and statically-parsed JS routes were replaced (not merged/duplicated).
    assert ("GET", "/api/admin/:section") not in js


@pytest.mark.skipif(not NODE_AVAILABLE, reason="node not installed")
def test_runtime_discovery_error_on_bad_entry(tmp_path):
    bad = tmp_path / "bad.js"
    bad.write_text("module.exports = { not_an_app: true };")
    with pytest.raises(RuntimeDiscoveryError):
        discover_express_routes(str(bad))


def test_runtime_discovery_requires_node():
    """A bogus node executable name surfaces a clear error, not a crash."""
    with pytest.raises(RuntimeDiscoveryError):
        discover_express_routes(RUNTIME_ENTRY, node_path="definitely-not-node-xyz")


# --------------------------------------------------------------------------- #
# Regression tests from dogfooding real OSS repos
# --------------------------------------------------------------------------- #
def test_fastapi_constructor_prefix_and_annotated_alias_auth(tmp_path):
    """
    Mirrors the full-stack-fastapi-template patterns:
      - APIRouter(prefix="/items") constructor prefix must be applied
      - auth via `Annotated` alias (CurrentUser) must be detected
      - a generic Depends(get_db) (SessionDep) must NOT count as auth
    """
    (tmp_path / "deps.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import Depends\n"
        "def get_db(): ...\n"
        "def get_current_user(): ...\n"
        "SessionDep = Annotated[str, Depends(get_db)]\n"
        "CurrentUser = Annotated[str, Depends(get_current_user)]\n"
    )
    (tmp_path / "items.py").write_text(
        "from fastapi import APIRouter\n"
        "from deps import SessionDep, CurrentUser\n"
        "router = APIRouter(prefix='/items')\n"
        "@router.get('/')\n"
        "def list_items(session: SessionDep): return []\n"
        "@router.post('/')\n"
        "def create_item(session: SessionDep, user: CurrentUser): return {}\n"
    )
    result = scan_path(str(tmp_path))
    by_key = {(r.method, r.path): r for r in result.routes}

    # Constructor prefix applied
    assert ("GET", "/items") in by_key
    assert ("POST", "/items") in by_key
    # DB-only dependency is NOT auth (the dangerous false-positive we must avoid)
    assert by_key[("GET", "/items")].auth_required is False
    # Annotated alias CurrentUser IS auth
    assert by_key[("POST", "/items")].auth_required is True


def test_express_route_chaining_and_factory_auth(tmp_path):
    (tmp_path / "user.route.js").write_text(
        "const express = require('express');\n"
        "const auth = require('./auth');\n"
        "const router = express.Router();\n"
        "router\n"
        "  .route('/')\n"
        "  .post(auth('manageUsers'), validate(x), ctrl.create)\n"
        "  .get(auth('getUsers'), ctrl.list);\n"
        "module.exports = router;\n"
    )
    parser = ExpressParser(str(tmp_path))
    by_key = {(r.method, r.path): r for r in parser.parse_directory().routes}
    assert ("POST", "/") in by_key and by_key[("POST", "/")].auth_required is True
    assert ("GET", "/") in by_key and by_key[("GET", "/")].auth_required is True


def test_default_excludes_skip_tests_and_vendor(tmp_path):
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/real')\ndef real(): return {}\n"
    )
    testdir = tmp_path / "tests"
    testdir.mkdir()
    (testdir / "test_routes.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/from-tests')\ndef t(): return {}\n"
    )
    vendordir = tmp_path / "node_modules" / "pkg"
    vendordir.mkdir(parents=True)
    (vendordir / "v.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/vendored')\ndef v(): return {}\n"
    )
    paths = {r.path for r in scan_path(str(tmp_path)).routes}
    assert "/real" in paths
    assert "/from-tests" not in paths   # tests/ excluded
    assert "/vendored" not in paths     # node_modules excluded


# --------------------------------------------------------------------------- #
# Configurable auth patterns
# --------------------------------------------------------------------------- #
def test_custom_auth_keyword_detected():
    """A bespoke decorator name only counts as auth when declared in config."""
    config = AuthConfig(keywords={"gatekeeper"})
    assert config.keyword_match("gatekeeper_required") is True
    assert config.keyword_match("login_required") is False  # not in this custom set


def test_load_auth_config_extend(tmp_path):
    cfg = tmp_path / ".shadowscan.json"
    cfg.write_text(json.dumps({"auth": {"extend_keywords": ["gatekeeper"]}}))
    loaded = load_auth_config(str(tmp_path))
    # Defaults preserved AND extended
    assert "gatekeeper" in loaded.keywords
    assert "jwt" in loaded.keywords


# --------------------------------------------------------------------------- #
# SARIF / JSON reporters
# --------------------------------------------------------------------------- #
def test_sarif_report_structure():
    parser_result = scan_path(MOCK_DIR)
    matcher = OpenAPIMatcher(os.path.join(MOCK_DIR, "openapi.json"))
    report = matcher.generate_report(parser_result)

    sarif = json.loads(report_to_sarif(report))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "shadow-api-scanner"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"shadow-endpoint", "missing-auth"} <= rule_ids
    # Every shadow + missing-auth finding is represented as a result
    assert len(run["results"]) == len(report.shadow_endpoints) + len(report.missing_auth_endpoints)
    for res in run["results"]:
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_render_report_rejects_unknown_format():
    parser_result = ScanResult(routes=[])
    matcher = OpenAPIMatcher({"paths": {}})
    report = matcher.generate_report(parser_result)
    with pytest.raises(ValueError):
        render_report(report, "xml")


# --------------------------------------------------------------------------- #
# Git "introduced this week"
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not GIT_AVAILABLE, reason="git not installed")
def test_git_annotates_new_endpoints(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, text=True)

    git("init")
    git("config", "user.email", "dev@example.com")
    git("config", "user.name", "Dev Tester")

    app = repo / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/new-thing')\n"
        "def new_thing():\n"
        "    return {}\n"
    )
    git("add", "-A")
    git("commit", "-m", "add endpoint")

    result = scan_path(str(repo))
    new = annotate_new_endpoints(result.routes, str(repo), "1 hour ago")

    assert len(new) == 1
    route = new[0]
    assert route.is_new is True
    assert route.path == "/new-thing"
    assert route.author == "Dev Tester"
    assert route.commit  # short sha populated
    assert route.change_type in ("added", "modified")


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git not installed")
def test_git_inspector_rejects_non_repo(tmp_path):
    with pytest.raises(GitError):
        annotate_new_endpoints([], str(tmp_path), "1 week ago")


# --------------------------------------------------------------------------- #
# MCP server hardening
# --------------------------------------------------------------------------- #
def test_mcp_token_helpers(monkeypatch):
    import src.mcp.server as srv

    # No token configured -> fail closed
    monkeypatch.delenv("SHADOW_SCAN_TOKEN", raising=False)
    monkeypatch.delenv("SHADOW_SCAN_TOKENS", raising=False)
    assert srv._valid_tokens() == set()
    assert srv._token_is_valid("anything") is False
    assert srv._token_is_valid(None) is False

    # Multi-token support
    monkeypatch.setenv("SHADOW_SCAN_TOKEN", "primary")
    monkeypatch.setenv("SHADOW_SCAN_TOKENS", "rotate-a, rotate-b")
    assert srv._valid_tokens() == {"primary", "rotate-a", "rotate-b"}
    assert srv._token_is_valid("rotate-b") is True
    assert srv._token_is_valid("wrong") is False


def test_mcp_fail_closed_without_token(monkeypatch):
    """With no token configured, the SSE endpoint must reject (not silently allow)."""
    from fastapi.testclient import TestClient
    import src.mcp.server as srv

    monkeypatch.delenv("SHADOW_SCAN_TOKEN", raising=False)
    monkeypatch.delenv("SHADOW_SCAN_TOKENS", raising=False)
    client = TestClient(srv.app)
    resp = client.get("/sse")
    assert resp.status_code == 401
    assert "no authentication token configured" in resp.json()["detail"]


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git not installed")
@pytest.mark.asyncio
async def test_mcp_list_new_unauthenticated(tmp_path):
    from src.mcp.server import handle_call_tool

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, text=True)

    git("init")
    git("config", "user.email", "dev@example.com")
    git("config", "user.name", "Dev Tester")
    (repo / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/leaky')\n"
        "def leaky():\n"
        "    return {}\n"
    )
    git("add", "-A")
    git("commit", "-m", "add leaky endpoint")

    res = await handle_call_tool("list_new_unauthenticated", {"path": str(repo), "since": "1 hour ago"})
    assert res.isError is not True
    payload = json.loads(res.content[0].text)
    assert payload["new_unauthenticated_count"] == 1
    assert payload["endpoints"][0]["path"] == "/leaky"
