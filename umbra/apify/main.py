"""
Apify Actor entrypoint for Umbra — SDK-free.

The Apify Python SDK pulls a heavy transitive stack (crawlee -> browserforge ->
pydantic) that is fragile to build in a container. The Actor only needs to read
its input, push items to the default dataset, and store a couple of records — all
of which Apify exposes as a stable REST API addressed via standard env vars. So
this entry talks to that API directly with httpx (already an Umbra dependency),
which removes the entire SDK dependency-conflict surface.

Two modes:

- Standby (MCP marketplace): when APIFY_META_ORIGIN=STANDBY, serve the MCP SSE
  server on the assigned port so agents can use Umbra as an MCP tool. Token auth
  (SHADOW_SCAN_TOKEN) and the x402 gate (UMBRA_X402_*) apply as usual.
- Batch: read input (gitUrl / path / openapi / since / strict). If gitUrl is
  given the repo is cloned first, then scanned; endpoints go to the default
  dataset and the report + SARIF to the key-value store. A non-zero exit (under
  strict) marks the run as failed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

import httpx

from umbra.engine.scanner import scan_path
from umbra.engine.matcher import OpenAPIMatcher
from umbra.engine.gitdiff import annotate_new_endpoints, GitError
from umbra.engine.reporters import report_to_sarif, report_to_json


# --------------------------------------------------------------------------- #
# Apify platform glue (REST API via env vars; no SDK)
# --------------------------------------------------------------------------- #
def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


def _api_base() -> str:
    return _env("APIFY_API_BASE_URL", default="https://api.apify.com").rstrip("/")


def _token() -> str:
    return _env("APIFY_TOKEN")


def _is_standby() -> bool:
    return _env("APIFY_META_ORIGIN").upper() == "STANDBY" or bool(os.environ.get("ACTOR_STANDBY_PORT"))


def _serve_mcp() -> None:
    import uvicorn
    port = int(_env("ACTOR_STANDBY_PORT", "ACTOR_WEB_SERVER_PORT", "PORT", default="8000"))
    uvicorn.run("umbra.mcp.server:app", host="0.0.0.0", port=port)


def get_input() -> dict:
    """Fetch the Actor input record from the default key-value store (or {})."""
    store = _env("ACTOR_DEFAULT_KEY_VALUE_STORE_ID", "APIFY_DEFAULT_KEY_VALUE_STORE_ID")
    key = _env("ACTOR_INPUT_KEY", "APIFY_INPUT_KEY", default="INPUT")
    token = _token()
    if not store or not token:
        return {}
    url = f"{_api_base()}/v2/key-value-stores/{store}/records/{key}"
    try:
        with httpx.Client(timeout=30.0) as c:
            r = c.get(url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return r.json()
    except Exception as e:
        print(f"[umbra] could not read input: {e}", file=sys.stderr)
        return {}


def push_items(items: list) -> None:
    """Append items to the default dataset."""
    dataset = _env("ACTOR_DEFAULT_DATASET_ID", "APIFY_DEFAULT_DATASET_ID")
    token = _token()
    if not dataset or not token or not items:
        return
    url = f"{_api_base()}/v2/datasets/{dataset}/items"
    with httpx.Client(timeout=60.0) as c:
        c.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            content=json.dumps(items),
        ).raise_for_status()


def set_record(key: str, value: str, content_type: str = "application/json") -> None:
    """Store a record in the default key-value store."""
    store = _env("ACTOR_DEFAULT_KEY_VALUE_STORE_ID", "APIFY_DEFAULT_KEY_VALUE_STORE_ID")
    token = _token()
    if not store or not token:
        return
    url = f"{_api_base()}/v2/key-value-stores/{store}/records/{key}"
    with httpx.Client(timeout=60.0) as c:
        c.put(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
            content=value,
        ).raise_for_status()


# --------------------------------------------------------------------------- #
# Scan logic
# --------------------------------------------------------------------------- #
def _clone_repo(git_url: str, branch: str = "", full_history: bool = False) -> str:
    """Clone a repo to a temp dir and return its path. Shallow unless full_history."""
    dest = tempfile.mkdtemp(prefix="umbra-scan-")
    cmd = ["git", "clone"]
    if not full_history:
        cmd += ["--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [git_url, dest]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return dest


def _resolve_openapi(openapi: str, target: str) -> str:
    """If openapi is a relative file path and we cloned a repo, resolve it inside the clone."""
    if not openapi:
        return openapi
    s = openapi.strip()
    if s.startswith(("http://", "https://")) or s.startswith("{") or os.path.isabs(s):
        return openapi
    candidate = os.path.join(target, s)
    return candidate if os.path.exists(candidate) else openapi


def _run_scan(inp: dict) -> dict:
    git_url = (inp.get("gitUrl") or "").strip()
    since = inp.get("since")
    openapi = inp.get("openapi")

    cleanup = ""
    if git_url:
        target = _clone_repo(git_url, inp.get("gitBranch") or "", full_history=bool(since))
        cleanup = target
        openapi = _resolve_openapi(openapi, target)
    else:
        target = inp.get("path") or "."

    try:
        result = scan_path(target)
        if since:
            try:
                annotate_new_endpoints(result.routes, target, since)
            except GitError:
                pass
        report = OpenAPIMatcher(openapi).generate_report(result) if openapi else None
        return {"routes": [r.model_dump() for r in result.routes], "report": report}
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def main() -> None:
    if _is_standby():
        print("[umbra] Standby mode: serving MCP server.")
        _serve_mcp()
        return

    inp = get_input()
    scanned = _run_scan(inp)

    push_items(scanned["routes"])
    report = scanned["report"]
    if report is not None:
        set_record("REPORT", report_to_json(report))
        set_record("SARIF", report_to_sarif(report))
        violations = len(report.shadow_endpoints) + len(report.missing_auth_endpoints)
        print(f"[umbra] {len(scanned['routes'])} routes, "
              f"{len(report.shadow_endpoints)} shadow, {len(report.missing_auth_endpoints)} missing-auth.")
        if inp.get("strict") and violations:
            print(f"[umbra] strict: {violations} policy violation(s).", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"[umbra] {len(scanned['routes'])} routes scanned (no OpenAPI provided).")


if __name__ == "__main__":
    main()
