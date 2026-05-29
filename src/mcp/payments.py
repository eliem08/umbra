"""
x402 payment gate for the Umbra MCP server.

x402 (https://x402.org) turns HTTP 402 "Payment Required" into a real payment
handshake for agentic/API access:

  1. Client calls a protected endpoint with no payment.
  2. Server replies 402 with a JSON body describing accepted payments
     (`accepts`: scheme, network, amount, asset, payTo, ...).
  3. Client pays and retries with an `X-PAYMENT` header (base64 JSON payload).
  4. Server verifies the payment with a *facilitator* (and optionally settles),
     then serves the resource and returns an `X-PAYMENT-RESPONSE` header.

This lets Umbra monetize per-call access to the hosted MCP (e.g. a scan costs N
USDC). It is OFF by default and only activates when configured via env, so it
does not affect self-hosted/free usage or the existing test suite.

PRODUCTION SEAMS (require your accounts/keys, not hardcoded here):
  - UMBRA_X402_PAY_TO     : the wallet address that receives payment.
  - UMBRA_X402_FACILITATOR: a facilitator base URL that verifies/settles
                            payments (e.g. Coinbase's x402 facilitator). Without
                            it the gate fails closed.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

X402_VERSION = 1


@dataclass
class X402Config:
    enabled: bool = False
    pay_to: str = ""
    network: str = "base-sepolia"
    asset: str = "USDC"
    # Price in the asset's smallest unit as a string (e.g. USDC has 6 decimals,
    # so "10000" == 0.01 USDC). x402 amounts are integer strings.
    max_amount_required: str = "10000"
    facilitator_url: str = ""
    scheme: str = "exact"
    max_timeout_seconds: int = 60
    description: str = "Umbra MCP access"
    protected_paths: tuple = ("/sse", "/messages")

    @classmethod
    def from_env(cls) -> "X402Config":
        return cls(
            enabled=os.environ.get("UMBRA_X402_ENABLED", "").lower() in ("1", "true", "yes"),
            pay_to=os.environ.get("UMBRA_X402_PAY_TO", "").strip(),
            network=os.environ.get("UMBRA_X402_NETWORK", "base-sepolia").strip(),
            asset=os.environ.get("UMBRA_X402_ASSET", "USDC").strip(),
            max_amount_required=os.environ.get("UMBRA_X402_AMOUNT", "10000").strip(),
            facilitator_url=os.environ.get("UMBRA_X402_FACILITATOR", "").rstrip("/"),
            description=os.environ.get("UMBRA_X402_DESCRIPTION", "Umbra MCP access"),
        )


def payment_requirements(cfg: X402Config, resource: str) -> Dict:
    """Build a single x402 payment-requirements object for a resource."""
    return {
        "scheme": cfg.scheme,
        "network": cfg.network,
        "maxAmountRequired": cfg.max_amount_required,
        "resource": resource,
        "description": cfg.description,
        "mimeType": "application/json",
        "payTo": cfg.pay_to,
        "maxTimeoutSeconds": cfg.max_timeout_seconds,
        "asset": cfg.asset,
    }


def _payment_required_response(cfg: X402Config, resource: str, error: str) -> JSONResponse:
    return JSONResponse(
        status_code=402,
        content={
            "x402Version": X402_VERSION,
            "accepts": [payment_requirements(cfg, resource)],
            "error": error,
        },
    )


def _decode_payment_header(value: str) -> Optional[Dict]:
    try:
        return json.loads(base64.b64decode(value).decode("utf-8"))
    except Exception:
        return None


# A verifier takes (payment_payload, requirements) and returns a dict like
# {"isValid": bool, "payer": str, ...}. The default calls a facilitator; tests
# inject a stub so no network/wallet is needed.
Verifier = Callable[[Dict, Dict, X402Config], Dict]


def facilitator_verifier(payload: Dict, requirements: Dict, cfg: X402Config) -> Dict:
    if not cfg.facilitator_url:
        return {"isValid": False, "error": "no facilitator configured"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{cfg.facilitator_url}/verify",
                json={
                    "x402Version": X402_VERSION,
                    "paymentPayload": payload,
                    "paymentRequirements": requirements,
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        return {"isValid": False, "error": f"facilitator verify failed: {e}"}


class X402Middleware(BaseHTTPMiddleware):
    """Enforces x402 payment on configured paths. No-op unless enabled."""

    def __init__(self, app, config: Optional[X402Config] = None, verifier: Optional[Verifier] = None):
        super().__init__(app)
        self.config = config or X402Config.from_env()
        self.verifier = verifier or facilitator_verifier

    async def dispatch(self, request: Request, call_next):
        cfg = self.config
        if not cfg.enabled or request.url.path not in cfg.protected_paths:
            return await call_next(request)

        resource = str(request.url)

        # Fail closed if misconfigured — never serve paid content for free by accident.
        if not cfg.pay_to:
            return _payment_required_response(cfg, resource, "payment not configured (missing payTo)")

        header = request.headers.get("x-payment")
        if not header:
            return _payment_required_response(cfg, resource, "X-PAYMENT header is required")

        payload = _decode_payment_header(header)
        if payload is None:
            return _payment_required_response(cfg, resource, "malformed X-PAYMENT header")

        result = self.verifier(payload, payment_requirements(cfg, resource), cfg)
        if not result.get("isValid"):
            return _payment_required_response(
                cfg, resource, result.get("error", "payment verification failed")
            )

        response = await call_next(request)
        # Surface settlement info to the client per the x402 spec.
        settlement = {"success": True, "payer": result.get("payer"), "network": cfg.network}
        response.headers["X-PAYMENT-RESPONSE"] = base64.b64encode(
            json.dumps(settlement).encode("utf-8")
        ).decode("utf-8")
        return response
