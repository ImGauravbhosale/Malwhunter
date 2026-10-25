"""Verdict combination — deterministic, given a Dossier's accumulated
Signals. Kept as a pure function separate from the Dossier itself so the
rules are independently testable without needing Recon/Detonation/Analyst
to actually run.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from malwhunter.dossier.model import Severity, Signal, SignalSource, VerdictLevel

if TYPE_CHECKING:
    from malwhunter.dossier.model import Dossier

_STRONG = (Severity.HIGH, Severity.CRITICAL)


def compute_verdict(signals: list[Signal]) -> VerdictLevel:
    # A single critical signal (canary/tripwire exfiltration) is
    # near-zero-false-positive on its own — no corroboration needed.
    if any(s.severity == Severity.CRITICAL for s in signals):
        return VerdictLevel.MALICIOUS

    recon = [s for s in signals if s.source == SignalSource.RECON]
    detonation = [s for s in signals if s.source == SignalSource.DETONATION]
    analyst = [s for s in signals if s.source == SignalSource.ANALYST]

    # A strong static shape AND an observed runtime behavior agreeing is
    # enough to confirm — MalwHunter's version of requiring independent
    # corroboration before a serious verdict. The static side must be
    # HIGH+: two weak hints (a typosquat-distance name plus a download
    # from an unlisted CDN, say) are common in perfectly normal packages
    # and only add up to "worth a look", not "malicious".
    if any(s.severity in _STRONG for s in recon) and detonation:
        return VerdictLevel.MALICIOUS

    if sum(1 for s in analyst if s.severity in _STRONG) >= 2:
        return VerdictLevel.MALICIOUS

    # LOW signals are context for a reader, not a reason to flag a package
    # on their own.
    if any(s.severity != Severity.LOW for s in signals):
        return VerdictLevel.SUSPICIOUS
    return VerdictLevel.CLEAN


def dossier_verdict(dossier: Dossier) -> VerdictLevel:
    """The verdict for a whole Dossier — what reports and the --fail-on
    gate use. A package that was never analyzed is UNSCANNED, never CLEAN
    for lack of signals."""
    if dossier.scan_error is not None:
        return VerdictLevel.UNSCANNED
    return compute_verdict(dossier.signals)
