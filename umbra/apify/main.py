"""
Apify Actor entrypoint for Umbra.

Two modes, auto-detected at runtime:

- Standby (MCP marketplace): when Apify runs the Actor in Standby mode
  (APIFY_META_ORIGIN=STANDBY), serve the MCP SSE server on the assigned port so
  agents can consume Umbra as an MCP tool. Token auth (SHADOW_SCAN_TOKEN) and the
  x402 payment gate (UMBRA_X402_*) apply exactly as in any other deployment.

- Batch: a normal Actor run reads input (gitUrl / path / openapi / since /
  strict). If `gitUrl` is given the target repo is cloned first, then scanned;
  every discovered endpoint is pushed to the default dataset and the full report
  + SARIF are stored in the key-value store.

The Apify SDK is imported lazily so the rest of the package has no hard
dependency on it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from umbra.engine.scanner import scan_path
from umbra.engine.matcher import OpenAPIMatcher
from umbra.engine.gitdiff import annotate_new_endpoints, GitError
from umbra.engine.reporters import report_to_sarif, report_to_json


def _is_standby() -> bool:
    return os.environ.get("APIFY_META_ORIGIN", "").upper() == "STANDBY" \
        or bool(os.environ.get("ACTOR_STANDBY_PORT"))


def _serve_mcp() -> None:
    import uvicorn
    port = int(
        os.environ.get("ACTOR_STANDBY_PORT")
        or os.environ.get("ACTOR_WEB_SERVER_PORT")
        or os.environ.get("PORT")
        or 8000
    )
    uvicorn.run("umbra.mcp.server:app", host="0.0.0.0", port=port)


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

    cleanup: str = ""
    if git_url:
        # Full history only when a git window is requested (shallow clones can't
        # resolve --since); otherwise a shallow clone is much faster.
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
        return {
            "routes": [r.model_dump() for r in result.routes],
            "report": report,
        }
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


async def amain() -> None:
    from apify import Actor

    async with Actor:
        if _is_standby():
            Actor.log.info("Standby mode: serving Umbra MCP server.")
            _serve_mcp()
            return

        inp = await Actor.get_input() or {}
        scanned = _run_scan(inp)

        await Actor.push_data(scanned["routes"])
        if scanned["report"] is not None:
            await Actor.set_value("REPORT", report_to_json(scanned["report"]), content_type="application/json")
            await Actor.set_value("SARIF", report_to_sarif(scanned["report"]), content_type="application/json")

            violations = len(scanned["report"].shadow_endpoints) + len(scanned["report"].missing_auth_endpoints)
            if inp.get("strict") and violations:
                await Actor.fail(status_message=f"Umbra found {violations} policy violation(s).")


def main() -> None:
    import asyncio
    asyncio.run(amain())


if __name__ == "__main__":
    main()
