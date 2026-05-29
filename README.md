# Umbra

> Hunt the shadow APIs before attackers do.

**Umbra** is a production-grade, highly-extensible DevSecOps static analysis tool that audits **FastAPI, Flask, Spring Boot, and Express** codebases. It automatically identifies undocumented "Shadow API" endpoints, detects endpoints completely lacking authentication middleware, attributes endpoints to the commit that introduced them ("what shipped this week?"), calculates API coverage ratios, and emits CI-native **SARIF** reports. It provides developer integrations (POSIX CLI, Remote SSE MCP Server, and Google Antigravity SDK).

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
├── umbra/
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
- **AST Parsing (`umbra/engine/parser.py`)**: Uses Python's native `ast` module to scan Python source files recursively. It identifies path parameters (e.g. `{id}`, `<int:id>`) and extracts HTTP verbs. It checks for authentication dependencies (FastAPI `Depends`/`Security` in function signatures or decorators, Flask authentication decorators).
- **Endpoint Registry Matching (`umbra/engine/matcher.py`)**: Compares parsed routes against a production `openapi.json` definition. Normalizes path variables to compute the documentation path coverage ratio:
  $$C = \frac{|E_{\text{parsed}} \cap E_{\text{registry}}|}{|E_{\text{parsed}}|}$$
- **Pydantic V2 schemas (`umbra/engine/schemas.py`)**: Strong typing and validation utilizing Pydantic V2 standard features.

### 2. Tier 2: Developer CLI
- **Sleek CLI Terminal (`umbra/cli/main.py`)**: Exposes the `umbra` command (with `shadow-scan` alias).
- Displays a `rich` ANSI colored dashboard highlighting shadow endpoints and security posture.
- **Pre-Commit Enforcement**: Supports `--strict` flag. Exits with status code `1` if any undocumented APIs or auth-less endpoints are detected, blocking commits or CI/CD pipelines.

### 3. Tier 3: Remote Server-Sent Events (SSE) MCP Server
- **Multi-Tenant HTTP SSE Server (`umbra/mcp/server.py`)**: Built over FastAPI using the official `mcp` SDK.
- **Robust Token Authorization Middleware**: Enforces validation of token-based authentication via `Authorization: Bearer <token>` headers or a `?token=<token>` query string parameter.
- **Explicit Schema Handlers**: Exposes tools with clear descriptions to prevent LLM hallucinations:
  1. `scan_codebase(path: str)`: Scans the codebase path (Python/Java/JavaScript) and returns routes.
  2. `compare_posture(codebase_routes: list, openapi_url: str)`: Runs comparison logic and reports coverage/shadow APIs.
  3. `get_remediation_diff(route: str)`: Generates a proposed git unified diff patch to automatically inject authentication middleware.
  4. `list_new_unauthenticated(path: str, since: str)`: Lists endpoints introduced/changed within a git window that lack auth — the "what did we ship this week that's unprotected?" health check.
- **Hardened transport**: Token auth fails closed (no default token), uses constant-time comparison, supports rotation via `SHADOW_SCAN_TOKENS`, and restricts CORS to an explicit allowlist via `SHADOW_SCAN_CORS_ORIGINS`.

### 4. Google Antigravity SDK Integration
- **Agent Bridge (`umbra/engine/agent_bridge.py`)**: Exposes custom tools and policies.
- **Declarative Safety Policies**: Restricts agent commands: `deny("*")`, `allow("view_file")`, `allow("parse_routes")`, and `ask_user("apply_remediation")` requiring explicit human approval.
- **Transform Lifecycle Hook**: Intercepts tool outputs to recursively redact hardcoded secrets, JWT tokens, and PII (emails) before sending data to the LLM.

---

## Installation

```bash
pip install umbra-scan
```

This installs the `umbra` command (with `shadow-scan` as an alias). For
runtime-assisted Express discovery you also need Node.js on PATH.

### From source (development)

```bash
pip install -e .
python -m pytest tests/ -v
```

---

## CLI Usage

Run the scanner locally against the provided mock project:
```bash
umbra --path tests/mock_project --openapi tests/mock_project/openapi.json
```

To run as a pre-commit block in strict CI/CD pipelines:
```bash
umbra --path tests/mock_project --openapi tests/mock_project/openapi.json --strict
```

Scan a polyglot directory (Python + Java + JavaScript) and emit SARIF for GitHub code scanning:
```bash
umbra --path ./src --openapi ./openapi.json --format sarif --output results.sarif
```

Gate only on endpoints introduced this week that are undocumented or unauthenticated:
```bash
umbra --path ./ --openapi ./openapi.json --since "1 week ago" --new-only --strict
```

Use runtime-assisted discovery for an Express service (catches dynamically-registered routes):
```bash
umbra --path ./services/api --openapi ./openapi.json --express-entry ./services/api/server.js
```

---

## CI/CD Integration

### GitHub Action

Drop the scanner into a workflow; findings appear inline on PRs via code scanning:

```yaml
# .github/workflows/shadow-scan.yml
name: Shadow API Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required to upload SARIF
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: eliem08/umbra@v0.1.0
        with:
          path: ./src
          openapi: ./openapi.json
          strict: "true"
          # since: "origin/${{ github.base_ref }}"   # gate only this PR's new endpoints
          # new-only: "true"
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/eliem08/umbra
    rev: v0.1.0
    hooks:
      - id: shadow-scan
        args: ["--path", ".", "--openapi", "openapi.json", "--strict"]
```

The repository's own CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the
test matrix and self-scans the mock project, uploading SARIF — a working reference.

---

## Performance

Scanning parses each source file exactly once and parallelizes across CPU cores
for large codebases (above ~300 files), so scan time scales with the number of
cores. Measured on real repositories (8-core machine):

| Codebase | Source files | Wall time | Peak memory |
|---|---:|---:|---:|
| Django (full) | 1,008 | ~11 s | ~4 MB |
| Home Assistant | 9,704 | ~19 s | ~10 MB |

A typical single service (a few hundred files) scans in 2–5 s and runs serially.

Tune or disable parallelism with the `SHADOW_SCAN_WORKERS` environment variable
(e.g. `SHADOW_SCAN_WORKERS=1` forces serial; defaults to the CPU count). Vendor,
build, and test directories (`node_modules`, `.venv`, `tests`, `target`, ...) are
excluded by default.

---

## Remote MCP Server Usage

1. Start the Remote SSE MCP server:
   ```bash
   # Set the token for authorized scanners
   $env:SHADOW_SCAN_TOKEN="my-secret-key-123"
   python -m uvicorn umbra.mcp.server:app --port 8000 --reload
   ```

2. AI agents connect to:
   - SSE connection endpoint: `http://localhost:8000/sse?token=my-secret-key-123`
   - Messages post endpoint: `http://localhost:8000/messages`

---

## Monetizing MCP access with x402

Umbra ships an optional [x402](https://x402.org) payment gate (built on the
official `x402` SDK) so you can charge per call for hosted MCP access. It is
**off by default**. Install the extra and enable it via env:

```bash
pip install "umbra-scan[x402]"
```

```bash
# testnet (Base Sepolia) — the public facilitator needs no API key
$env:UMBRA_X402_ENABLED="true"
$env:UMBRA_X402_PAY_TO="0xYourReceivingWallet"                 # required (EVM address)
$env:UMBRA_X402_FACILITATOR="https://x402.org/facilitator"     # default; testnet
$env:UMBRA_X402_NETWORK="eip155:84532"                         # Base Sepolia (CAIP-2)
$env:UMBRA_X402_PRICE="$0.001"                                 # per call
```

For **Base mainnet**, switch the network to `eip155:8453` and the facilitator to a
production one (e.g. Coinbase CDP `https://api.cdp.coinbase.com/platform/v2/x402`).

When enabled, unpaid requests to `/sse` and `/messages` get an HTTP `402` with
x402 payment requirements; the buyer's x402 client pays and retries, the official
middleware verifies/settles via the facilitator, and the request is served. The
wallet and facilitator are **your** accounts — Umbra hardcodes no credentials,
and the gate **fails closed** if `payTo` is unset. See
[umbra/mcp/payments.py](umbra/mcp/payments.py).

> Note: this gates the HTTP transport (x402 protocol level). Fine-grained
> *per-tool* MCP billing (via the TypeScript `@x402/mcp` wrapper) is a future
> addition for the Python server.

---

## Deploy to Apify (and the Apify MCP marketplace)

Umbra includes an Apify Actor definition ([.actor/](.actor/)). Two modes:

- **Batch**: a normal run reads input (`path`, `openapi`, `since`, `strict`),
  scans, and pushes endpoints to the default dataset (report + SARIF go to the
  key-value store).
- **Standby / MCP**: when run in Standby mode, the Actor serves the MCP SSE
  server, so Umbra can be consumed as a tool via Apify's MCP marketplace. Token
  auth and the x402 gate apply as usual.

Publish with the Apify CLI:

```bash
npm i -g apify-cli
apify login
apify push     # builds .actor/Dockerfile and deploys to your Apify account
```

Entry: [umbra/apify/main.py](umbra/apify/main.py). Requires an Apify account.
