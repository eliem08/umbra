"""
Machine-readable report formats for CI ingestion.

- ``json``: the full ScannerReport, for arbitrary downstream tooling.
- ``sarif``: SARIF 2.1.0, which GitHub Advanced Security "code scanning" ingests
  natively so findings appear inline on pull requests and in the Security tab.

SARIF is the lever that turns this from a CLI toy into something an enterprise
security team can wire into their existing PR workflow.
"""
from __future__ import annotations

import json
from typing import Dict, List

from .schemas import RouteEndpoint, ScannerReport

TOOL_NAME = "shadow-api-scanner"
TOOL_VERSION = "0.1.0"
INFO_URI = "https://github.com/your-org/shadow-api-scanner"

# Rule catalogue. `level` follows SARIF: error | warning | note.
RULES = {
    "shadow-endpoint": {
        "name": "ShadowEndpoint",
        "shortDescription": "Undocumented (shadow) API endpoint",
        "fullDescription": "An endpoint exists in code but is absent from the production OpenAPI registry. Shadow endpoints bypass API governance and SOC 2 / ISO 27001 documentation controls.",
        "level": "error",
    },
    "missing-auth": {
        "name": "MissingAuthentication",
        "shortDescription": "Endpoint lacks authentication/authorization",
        "fullDescription": "No authentication dependency, middleware, or authorization annotation was detected on this endpoint. It may be publicly reachable without credentials.",
        "level": "error",
    },
}


def report_to_json(report: ScannerReport, indent: int = 2) -> str:
    """Serialize the full report as JSON."""
    return report.model_dump_json(indent=indent)


def _result(rule_id: str, message: str, route: RouteEndpoint) -> Dict:
    rule = RULES[rule_id]
    return {
        "ruleId": rule_id,
        "level": rule["level"],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(route.source_file)},
                    "region": {"startLine": max(1, route.line_number)},
                }
            }
        ],
        "properties": {
            "method": route.method,
            "path": route.path,
            "framework": route.framework,
            "language": route.language,
            "is_new": route.is_new,
            "commit": route.commit,
            "author": route.author,
        },
    }


def _uri(source_file: str) -> str:
    # SARIF artifact URIs use forward slashes and should be relative.
    return source_file.replace("\\", "/")


def report_to_sarif(report: ScannerReport, indent: int = 2) -> str:
    """Serialize the report as a SARIF 2.1.0 log."""
    results: List[Dict] = []

    for route in report.shadow_endpoints:
        results.append(_result(
            "shadow-endpoint",
            f"Shadow endpoint {route.method} {route.path} is not present in the OpenAPI registry.",
            route,
        ))

    for route in report.missing_auth_endpoints:
        results.append(_result(
            "missing-auth",
            f"Endpoint {route.method} {route.path} has no detected authentication/authorization control.",
            route,
        ))

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": INFO_URI,
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule["name"],
                                "shortDescription": {"text": rule["shortDescription"]},
                                "fullDescription": {"text": rule["fullDescription"]},
                                "defaultConfiguration": {"level": rule["level"]},
                            }
                            for rule_id, rule in RULES.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=indent)


def render_report(report: ScannerReport, fmt: str) -> str:
    """Dispatch to the requested machine-readable format."""
    fmt = fmt.lower()
    if fmt == "json":
        return report_to_json(report)
    if fmt == "sarif":
        return report_to_sarif(report)
    raise ValueError(f"Unsupported report format: {fmt!r}. Expected 'json' or 'sarif'.")
