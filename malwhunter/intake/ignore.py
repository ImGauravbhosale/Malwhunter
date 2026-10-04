"""Reads a project's `.MHignore` policy file — a committed, reviewed
list of package@version findings to exclude from the fail-on gate.
Modeled on Snyk's `.snyk` ignore policy: every rule must carry a reason
(no silent suppression) and may carry an expiry, after which it stops
applying on its own rather than being ignored forever.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

IGNORE_FILENAME = ".MHignore"


class IgnoreFileError(Exception):
    """The `.MHignore` file exists but is malformed."""


@dataclass(frozen=True)
class IgnoreRule:
    package: str
    reason: str
    version: str | None = None
    expires: date | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, package: str, version: str) -> bool:
        if self.package != package:
            return False
        return self.version is None or self.version == version


def _parse_rule(raw: dict, index: int) -> IgnoreRule:
    package = raw.get("package")
    if not package:
        raise IgnoreFileError(f"{IGNORE_FILENAME} rule #{index}: missing required field 'package'")

    reason = raw.get("reason", "").strip()
    if not reason:
        raise IgnoreFileError(
            f"{IGNORE_FILENAME} rule #{index} ({package}): missing required field 'reason' — "
            f"every ignore rule must document why, so it stays a reviewed decision, not a silenced one"
        )

    expires_raw = raw.get("expires")
    expires = None
    if expires_raw is not None:
        try:
            expires = date.fromisoformat(expires_raw)
        except ValueError as exc:
            raise IgnoreFileError(
                f"{IGNORE_FILENAME} rule #{index} ({package}): 'expires' must be YYYY-MM-DD, got {expires_raw!r}"
            ) from exc

    return IgnoreRule(package=package, reason=reason, version=raw.get("version"), expires=expires)


def load_ignore_rules(project_dir: Path) -> list[IgnoreRule]:
    path = project_dir / IGNORE_FILENAME
    if not path.exists():
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IgnoreFileError(f"{IGNORE_FILENAME} is not valid JSON: {exc}") from exc

    if not isinstance(raw, list):
        raise IgnoreFileError(f"{IGNORE_FILENAME} must be a JSON array of ignore rules")

    return [_parse_rule(item, i) for i, item in enumerate(raw)]


@dataclass(frozen=True)
class IgnoreOutcome:
    """Result of matching ignore rules against the scanned dossiers."""

    matched: dict[str, IgnoreRule]  # dossier_key -> rule that suppressed it
    unused: list[IgnoreRule]  # rules that never matched anything scanned (likely stale)
    expired: list[IgnoreRule]  # rules present but past their `expires` date


def apply_ignore_rules(
    dossiers: list,
    rules: list[IgnoreRule],
    *,
    today: date | None = None,
) -> IgnoreOutcome:
    today = today or date.today()
    active = [r for r in rules if not r.is_expired(today)]
    expired = [r for r in rules if r.is_expired(today)]

    matched: dict[str, IgnoreRule] = {}
    used_rules: set[int] = set()
    for d in dossiers:
        for i, rule in enumerate(active):
            if rule.matches(d.package, d.version):
                matched[d.dossier_key] = rule
                used_rules.add(i)
                break

    unused = [r for i, r in enumerate(active) if i not in used_rules]
    return IgnoreOutcome(matched=matched, unused=unused, expired=expired)
