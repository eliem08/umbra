"""
Apify Actor entrypoint for Umbra.

Two modes, auto-detected at runtime:

- Standby (MCP marketplace): when Apify runs the Actor in Standby mode
  (APIFY_META_ORIGIN=STANDBY), serve the MCP SSE server on the assigned port so
  agents can consume Umbra as an MCP tool. Token auth (SHADOW_SCAN_TOKEN) and the
  x402 payment gate (UMBRA_X402_*) apply exactly as in any other deployment.

- Batch: a normal Actor run reads input (path / openapi / since / strict),
  scans, pushes each discovered endpoint to the default dataset, and stores the
  full report + SARIF in the key-value store.

The Apify SDK is imported lazily so the rest of the package has no hard
dependency on it.
"""
from __future__ import annotations

import os

from src.engine.scanner import scan_path
from src.engine.matcher import OpenAPIMatcher
from src.engine.gitdiff import annotate_new_endpoints, GitError
from src.engine.reporters import report_to_sarif, report_to_json


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
    uvicorn.run("src.mcp.server:app", host="0.0.0.0", port=port)


def _run_scan(inp: dict) -> dict:
    path = inp.get("path") or "."
    openapi = inp.get("openapi")
    since = inp.get("since")

    result = scan_path(path)
    if since:
        try:
            annotate_new_endpoints(result.routes, path, since)
        except GitError:
            pass

    report = None
    if openapi:
        report = OpenAPIMatcher(openapi).generate_report(result)

    return {
        "routes": [r.model_dump() for r in result.routes],
        "report": report,
    }


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
