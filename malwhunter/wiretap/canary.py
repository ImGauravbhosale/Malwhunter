"""Tripwire environment variables — realistic-looking secret names set to
unique per-run values. If a tripwire value is ever observed leaving the
sandbox, that's a near-zero-false-positive signal: nothing legitimate has
any reason to transmit it anywhere. This needs no pattern-matching at all
to be trustworthy, which is what makes it the strongest detector in the
whole design.
"""
from __future__ import annotations

import secrets

CANARY_ENV_VAR_NAMES = (
    "NPM_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
)


def generate_canaries() -> dict[str, str]:
    return {name: f"canary_{secrets.token_hex(16)}" for name in CANARY_ENV_VAR_NAMES}


def find_leaked_canaries(haystack: str, canaries: dict[str, str]) -> list[str]:
    return [name for name, value in canaries.items() if value in haystack]
