# Shadow API Scanner

A production-grade, highly-extensible DevSecOps static analysis tool that audits **FastAPI, Flask, Spring Boot, and Express** codebases. It automatically identifies undocumented "Shadow API" endpoints, detects endpoints completely lacking authentication middleware, attributes endpoints to the commit that introduced them ("what shipped this week?"), calculates API coverage ratios, and emits CI-native **SARIF** reports. It provides developer integrations (POSIX CLI, Remote SSE MCP Server, and Google Antigravity SDK).

## What's new

- **Multi-language scanning** — Python (FastAPI/Flask) via AST, Java (Spring Boot) and JavaScript/TypeScript (Express) via focused declarative parsers. A single scan of a polyglot monorepo dispatches all parsers.
- **Runtime-assisted Express discovery (`--express-entry`)** — because Express registers routes at runtime, static parsing structurally misses dynamically-mounted/looped routes. Point the scanner at your app's entry file and it introspects the *live* router stack via a bundled Node script, reconstructs mount prefixes, and infers auth from the real middleware chain (`app.use`/`router.use` included). Runtime results supersede static JS parsing. Requires Node.js and the app's installed dependencies.
- **Configurable auth detection** — drop a `.shadowscan.yml` / `.shadowscan.json` in your repo to teach the scanner your bespoke decorators, dependency callables, Spring annotations, or Express middleware. Eliminates false negatives on custom auth.
- **Git provenance (`--since`)** — flag endpoints introduced or changed within a window (`"1 week ago"`, a date, or a baseline ref like `origin/main`), attributed to commit + author. Powers the "endpoints introduced this week lacking auth" MCP query.
- **SARIF + JSON output (`--format`)** — `--format sarif` produces SARIF 2.1.0 consumable by GitHub Advanced Security code scanning so findings appear inline on PRs.
- **Hardened MCP server** — fail-closed token auth (no hardcoded default), constant-time comparison, multi-token rotation, and a spec-safe CORS allowlist.

### Auth config example (`.shadowscan.yml`)

```yaml
auth:
  # Union these into the built-in defaults (keeps jwt/auth/token/... as well):
  extend_keywords: [gatekeeper, entitlement]
  extend_express_auth_middleware: [withSession]
  # Or replace a list outright:
  spring_auth_annotations: [PreAuthorize, Secured, CustomGuard]
```

---

## Workspace Structure

```
├── .agents/
│   └── skills/           # Antigravity Skills directory
├── src/
│   ├── __init__.py
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── parser.py      # Python AST parser for FastAPI & Flask
│   │   ├── spring.py      # Spring Boot (Java) annotation parser
│   │   ├── express.py     # Express (JS/TS) static route parser
│   │   ├── express_runtime.py # Runtime-assisted Express discovery (Node)
│   │   ├── runtime/
│   │   │   └── express_introspect.js # Live router-stack introspector
│   │   ├── scanner.py     # Multi-language scan dispatcher
│   │   ├── authconfig.py  # Configurable auth-detection patterns
│   │   ├── gitdiff.py     # Git provenance ("introduced this week")
│   │   ├── reporters.py   # SARIF 2.1.0 + JSON reporters
│   │   ├── matcher.py     # Matcher and comparison logic
│   │   ├── schemas.py     # Pydantic V2 data validation models
│   │   └── agent_bridge.py # Antigravity custom tools & policy hooks
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py       # Click terminal entry point
│   └── mcp/
│       ├── __init__.py
│       └── server.py     # Remote SSE MCP server with Token Auth
├── tests/
│   ├── mock_project/     # Dummy files with shadow/documented routes
│   └── test_scanner.py   # Complete pytest suite
├── pyproject.toml
└── README.md
```

---

## Key Features

### 1. Tier 1: Core AST Engine
- **AST Parsing (`src/engine/parser.py`)**: Uses Python's native `ast` module to scan Python source files recursively. It identifies path parameters (e.g. `{id}`, `<int:id>`) and extracts HTTP verbs. It checks for authentication dependencies (FastAPI `Depends`/`Security` in function signatures or decorators, Flask authentication decorators).
- **Endpoint Registry Matching (`src/engine/matcher.py`)**: Compares parsed routes against a production `openapi.json` definition. Normalizes path variables to compute the documentation path coverage ratio:
  $$C = \frac{|E_{\text{parsed}} \cap E_{\text{registry}}|}{|E_{\text{parsed}}|}$$
- **Pydantic V2 schemas (`src/engine/schemas.py`)**: Strong typing and validation utilizing Pydantic V2 standard features.

### 2. Tier 2: Developer CLI
- **Sleek CLI Terminal (`src/cli/main.py`)**: Exposes the `shadow-scan` command.
- Displays a `rich` ANSI colored dashboard highlighting shadow endpoints and security posture.
- **Pre-Commit Enforcement**: Supports `--strict` flag. Exits with status code `1` if any undocumented APIs or auth-less endpoints are detected, blocking commits or CI/CD pipelines.

### 3. Tier 3: Remote Server-Sent Events (SSE) MCP Server
- **Multi-Tenant HTTP SSE Server (`src/mcp/server.py`)**: Built over FastAPI using the official `mcp` SDK.
- **Robust Token Authorization Middleware**: Enforces validation of token-based authentication via `Authorization: Bearer <token>` headers or a `?token=<token>` query string parameter.
- **Explicit Schema Handlers**: Exposes tools with clear descriptions to prevent LLM hallucinations:
  1. `scan_codebase(path: str)`: Scans the codebase path (Python/Java/JavaScript) and returns routes.
  2. `compare_posture(codebase_routes: list, openapi_url: str)`: Runs comparison logic and reports coverage/shadow APIs.
  3. `get_remediation_diff(route: str)`: Generates a proposed git unified diff patch to automatically inject authentication middleware.
  4. `list_new_unauthenticated(path: str, since: str)`: Lists endpoints introduced/changed within a git window that lack auth — the "what did we ship this week that's unprotected?" health check.
- **Hardened transport**: Token auth fails closed (no default token), uses constant-time comparison, supports rotation via `SHADOW_SCAN_TOKENS`, and restricts CORS to an explicit allowlist via `SHADOW_SCAN_CORS_ORIGINS`.

### 4. Google Antigravity SDK Integration
- **Agent Bridge (`src/engine/agent_bridge.py`)**: Exposes custom tools and policies.
- **Declarative Safety Policies**: Restricts agent commands: `deny("*")`, `allow("view_file")`, `allow("parse_routes")`, and `ask_user("apply_remediation")` requiring explicit human approval.
- **Transform Lifecycle Hook**: Intercepts tool outputs to recursively redact hardcoded secrets, JWT tokens, and PII (emails) before sending data to the LLM.

---

## Installation & Setup

1. Install dependencies:
   ```bash
   pip install -e .
   ```

2. Run the test suite:
   ```bash
   python -m pytest tests/test_scanner.py -v
   ```

---

## CLI Usage

Run the scanner locally against the provided mock project:
```bash
shadow-scan --path tests/mock_project --openapi tests/mock_project/openapi.json
```

To run as a pre-commit block in strict CI/CD pipelines:
```bash
shadow-scan --path tests/mock_project --openapi tests/mock_project/openapi.json --strict
```

Scan a polyglot directory (Python + Java + JavaScript) and emit SARIF for GitHub code scanning:
```bash
shadow-scan --path ./src --openapi ./openapi.json --format sarif --output results.sarif
```

Gate only on endpoints introduced this week that are undocumented or unauthenticated:
```bash
shadow-scan --path ./ --openapi ./openapi.json --since "1 week ago" --new-only --strict
```

Use runtime-assisted discovery for an Express service (catches dynamically-registered routes):
```bash
shadow-scan --path ./services/api --openapi ./openapi.json --express-entry ./services/api/server.js
```

---

## Remote MCP Server Usage

1. Start the Remote SSE MCP server:
   ```bash
   # Set the token for authorized scanners
   $env:SHADOW_SCAN_TOKEN="my-secret-key-123"
   python -m uvicorn src.mcp.server:app --port 8000 --reload
   ```

2. AI agents connect to:
   - SSE connection endpoint: `http://localhost:8000/sse?token=my-secret-key-123`
   - Messages post endpoint: `http://localhost:8000/messages`
