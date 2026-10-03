"""Decides whether a specific package is worth the cost of a full
Detonation pass — the thing that makes `scan .` practical to run in CI
against a real dependency tree instead of timing every build out.

Docker Detonation costs real wall-clock time per package (container
start, install-script execution, proxy teardown). A typical project has
a handful of genuinely new/obscure dependencies and a long tail of
well-established ones already installed by millions of people — burning
the same Detonation budget on left-pad as on a package published
yesterday buys nothing. This is a reputation-based *pre-filter*, not a
verdict: it only decides whether to look closer, never whether something
is clean. An established package with a HIGH/CRITICAL Recon finding
still gets detonated regardless of age or downloads.
"""
from __future__ import annotations

from dataclasses import dataclass

from malwhunter.dossier.model import Severity, Signal
from malwhunter.intake.registry import PackageReputation

DEFAULT_AGE_THRESHOLD_DAYS = 30
DEFAULT_DOWNLOADS_THRESHOLD = 1000

_ESCALATING_SEVERITIES = (Severity.HIGH, Severity.CRITICAL)


@dataclass(frozen=True)
class DetonationDecision:
    should_detonate: bool
    reason: str


def decide_detonation(
    reputation: PackageReputation,
    recon_signals: list[Signal],
    *,
    age_threshold_days: int = DEFAULT_AGE_THRESHOLD_DAYS,
    downloads_threshold: int = DEFAULT_DOWNLOADS_THRESHOLD,
) -> DetonationDecision:
    escalating = [s for s in recon_signals if s.severity in _ESCALATING_SEVERITIES]
    if escalating:
        return DetonationDecision(
            True, f"Recon already found {len(escalating)} high/critical signal(s) — always detonate"
        )

    if reputation.age_days is None or reputation.downloads_last_month is None:
        return DetonationDecision(True, "reputation lookup failed — can't prove it's safe to skip, detonate")

    if reputation.age_days < age_threshold_days:
        return DetonationDecision(
            True, f"published {reputation.age_days}d ago (< {age_threshold_days}d threshold) — too new to trust"
        )

    if reputation.downloads_last_month < downloads_threshold:
        return DetonationDecision(
            True,
            f"{reputation.downloads_last_month} downloads/month "
            f"(< {downloads_threshold} threshold) — too obscure to trust",
        )

    return DetonationDecision(
        False,
        f"established package ({reputation.age_days}d old, "
        f"{reputation.downloads_last_month} downloads/month) — skipping Detonation",
    )
