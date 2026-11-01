"""Tripwire environment variables — realistic-looking secret names set to
unique per-run values. If a tripwire value is ever observed leaving the
sandbox, that's a near-zero-false-positive signal: nothing legitimate has
any reason to transmit it anywhere. This needs no pattern-matching at all
to be trustworthy, which is what makes it the strongest detector in the
whole design.
"""
from __future__ import annotations

import base64
import secrets
from urllib.parse import quote

CANARY_ENV_VAR_NAMES = (
    "NPM_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
)


def generate_canaries() -> dict[str, str]:
    return {name: f"canary_{secrets.token_hex(16)}" for name in CANARY_ENV_VAR_NAMES}


def _variants(value: str) -> tuple[str, ...]:
    """The forms malware commonly re-encodes a stolen value into before
    sending it: as-is, base64 (standard and URL-safe, with and without
    padding), hex, and percent-encoded."""
    raw = value.encode()
    b64 = base64.b64encode(raw).decode()
    b64url = base64.urlsafe_b64encode(raw).decode()
    found = [
        value,
        b64,
        b64.rstrip("="),
        b64url,
        b64url.rstrip("="),
        raw.hex(),
        quote(value, safe=""),
    ]
    # A value base64-encoded *inside* a larger blob (e.g. the whole
    # environment as JSON) lands at any of three alignments. Shifting the
    # value by 0-2 bytes and dropping the characters that mix with its
    # neighbours leaves the stable middle that appears in every such blob.
    for shift, drop_head in ((1, 2), (2, 3)):
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(b"\0" * shift + raw).decode()
            found.append(encoded[drop_head:-4])
    return tuple(found)


def find_leaked_canaries(haystack: str, canaries: dict[str, str]) -> list[str]:
    return [name for name, value in canaries.items() if any(v in haystack for v in _variants(value))]
