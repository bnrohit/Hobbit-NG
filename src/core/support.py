"""Optional open-source support helpers.

Hobbit-NG never requires payment. This module only surfaces a configured
Stripe-hosted Payment Link and deliberately contains no Stripe secret keys or
card-handling logic.
"""

from __future__ import annotations

import os
import sys
from typing import Mapping
from urllib.parse import urlparse

DEFAULT_MESSAGE = (
    "Hobbit-NG is free and open source. If it helps you, an optional donation "
    "can support continued development, testing, documentation, and maintenance."
)


def _settings(config: Mapping | None) -> dict:
    raw = dict((config or {}).get("support", {}) or {})
    return {
        "enabled": bool(raw.get("enabled", True)),
        "provider": str(raw.get("provider", "stripe")),
        "donation_url_env": str(raw.get("donation_url_env", "HOBBIT_DONATION_URL")),
        "interactive_prompt": bool(raw.get("interactive_prompt", True)),
        "message": str(raw.get("message", DEFAULT_MESSAGE)),
    }


def _valid_stripe_payment_link(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (host == "stripe.com" or host.endswith(".stripe.com"))


def support_info(config: Mapping | None = None, environ: Mapping[str, str] | None = None) -> dict:
    settings = _settings(config)
    env = os.environ if environ is None else environ
    raw_url = str(env.get(settings["donation_url_env"], "")).strip()
    donation_url = raw_url if _valid_stripe_payment_link(raw_url) else None
    return {
        "enabled": settings["enabled"],
        "provider": settings["provider"],
        "configured": bool(settings["enabled"] and donation_url),
        "donation_url": donation_url if settings["enabled"] else None,
        "donation_url_env": settings["donation_url_env"],
        "message": settings["message"],
        "free_and_open_source": True,
        "feature_gating": False,
    }


def maybe_prompt_support(
    config: Mapping | None = None,
    *,
    skip_prompt: bool = False,
    input_fn=input,
    output_fn=print,
    environ: Mapping[str, str] | None = None,
    interactive: bool | None = None,
) -> str:
    """Offer optional support without interfering with automation.

    Returns one of: disabled, unconfigured, skipped, skipped_noninteractive,
    donate. The prompt is shown only when a valid Stripe link is configured and
    stdin/stdout are interactive terminals.
    """

    settings = _settings(config)
    info = support_info(config, environ)
    if not info["enabled"]:
        return "disabled"
    if not info["configured"]:
        return "unconfigured"
    if skip_prompt or not settings["interactive_prompt"]:
        return "skipped"
    if interactive is None:
        interactive = bool(
            getattr(sys.stdin, "isatty", lambda: False)()
            and getattr(sys.stdout, "isatty", lambda: False)()
        )
    if not interactive:
        return "skipped_noninteractive"

    output_fn("")
    output_fn(info["message"])
    choice = input_fn("Support Hobbit-NG? [d] Donate / [Enter] Skip: ").strip().lower()
    if choice in {"d", "donate", "y", "yes"}:
        output_fn(f"Stripe donation link: {info['donation_url']}")
        return "donate"

    output_fn("Skipped. All Hobbit-NG features remain available for free.")
    return "skipped"
