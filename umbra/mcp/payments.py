"""
x402 payment gate for the Umbra MCP server, built on the official x402 SDK.

x402 (https://x402.org) turns HTTP 402 "Payment Required" into a real payment
handshake for agentic/API access. This module attaches the official x402 FastAPI
middleware to the MCP HTTP endpoints so you can charge per call for hosted
access. It is OFF by default and only activates when configured via env, so it
never affects self-hosted/free usage.

Install the optional dependency to use it:

    pip install "umbra-scan[x402]"

Configuration (env):
    UMBRA_X402_ENABLED      "true" to enable (default off).
    UMBRA_X402_PAY_TO       your receiving wallet address (required when enabled).
    UMBRA_X402_FACILITATOR  facilitator base URL. Default https://x402.org/facilitator
                            (Base Sepolia + Solana devnet, no API key). For Base
                            mainnet use https://api.cdp.coinbase.com/platform/v2/x402
                            (Coinbase CDP) or another production facilitator.
    UMBRA_X402_NETWORK      CAIP-2 network id. Default eip155:84532 (Base Sepolia).
                            Base mainnet is eip155:8453.
    UMBRA_X402_PRICE        price per call, e.g. "$0.001" (default).

NOTE on MCP: this gates the HTTP transport endpoints (/sse, /messages) at the
x402 protocol level. Fine-grained *per-tool* MCP billing is provided upstream by
the TypeScript `@x402/mcp` wrapper; a Python equivalent is a future addition.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

DEFAULT_FACILITATOR = "https://x402.org/facilitator"  # testnet, no API key
DEFAULT_NETWORK = "eip155:84532"  # Base Sepolia (CAIP-2); mainnet is eip155:8453


class X402NotInstalled(RuntimeError):
    """Raised when x402 is enabled but the optional `x402` package isn't installed."""


@dataclass
class X402Config:
    enabled: bool = False
    pay_to: str = ""
    network: str = DEFAULT_NETWORK
    price: str = "$0.001"
    facilitator_url: str = DEFAULT_FACILITATOR
    # MCP transport routes to protect, mapped to human descriptions.
    protected: Dict[str, str] = field(default_factory=lambda: {
        "GET /sse": "Umbra MCP event stream",
        "POST /messages": "Umbra MCP tool call",
    })

    @classmethod
    def from_env(cls) -> "X402Config":
        return cls(
            enabled=os.environ.get("UMBRA_X402_ENABLED", "").lower() in ("1", "true", "yes"),
            pay_to=os.environ.get("UMBRA_X402_PAY_TO", "").strip(),
            network=os.environ.get("UMBRA_X402_NETWORK", DEFAULT_NETWORK).strip(),
            price=os.environ.get("UMBRA_X402_PRICE", "$0.001").strip(),
            facilitator_url=os.environ.get("UMBRA_X402_FACILITATOR", DEFAULT_FACILITATOR).strip().rstrip("/"),
        )


def apply_x402(app, config: Optional[X402Config] = None) -> bool:
    """
    Attach the official x402 payment middleware to a FastAPI/Starlette `app`.

    Returns True if the gate was attached, False if disabled (no-op). Raises
    ValueError if enabled without a payTo (fail closed — never serve paid content
    for free by accident), and X402NotInstalled if the optional SDK is missing.
    """
    cfg = config or X402Config.from_env()
    if not cfg.enabled:
        return False
    if not cfg.pay_to:
        raise ValueError(
            "UMBRA_X402_ENABLED is set but UMBRA_X402_PAY_TO is empty. "
            "Set your receiving wallet address (fail-closed)."
        )

    try:
        from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
        from x402.http.middleware.fastapi import PaymentMiddlewareASGI
        from x402.http.types import RouteConfig
        from x402.mechanisms.evm.exact import ExactEvmServerScheme
        from x402.server import x402ResourceServer
    except ImportError as e:  # pragma: no cover - depends on optional dep
        raise X402NotInstalled(
            'x402 payments require the optional dependency. Install with: '
            'pip install "umbra-scan[x402]"'
        ) from e

    facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=cfg.facilitator_url))
    server = x402ResourceServer(facilitator)
    server.register(cfg.network, ExactEvmServerScheme())

    routes = {
        route: RouteConfig(
            accepts=[PaymentOption(
                scheme="exact", pay_to=cfg.pay_to, price=cfg.price, network=cfg.network,
            )],
            mime_type="application/json",
            description=desc,
        )
        for route, desc in cfg.protected.items()
    }

    app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)
    return True
