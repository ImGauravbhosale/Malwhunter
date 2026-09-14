"""Verdict combination — deterministic, given a Dossier's accumulated
Signals. Kept as a pure function separate from the Dossier itself so the
rules are independently testable without needing Recon/Detonation/Analyst
to actually run.
"""
from __future__ import annotations

from malwhunter.dossier.model import Severity, Signal, SignalSource, VerdictLevel


def compute_verdict(signals: list[Signal]) -> VerdictLevel:
    if not signals:
        return VerdictLevel.CLEAN

    # A single critical signal (canary/tripwire exfiltration) is
    # near-zero-false-positive on its own — no corroboration needed.
    if any(s.severity == Severity.CRITICAL for s in signals):
        return VerdictLevel.MALICIOUS

    recon = [s for s in signals if s.source == SignalSource.RECON]
    detonation = [s for s in signals if s.source == SignalSource.DETONATION]
    analyst = [s for s in signals if s.source == SignalSource.ANALYST]

    # A static shape AND an observed runtime behavior agreeing is strong
    # enough to confirm — this is MalwHunter's version of requiring
    # independent corroboration before a serious verdict.
    if recon and detonation:
        return VerdictLevel.MALICIOUS

    high_confidence_analyst = [s for s in analyst if s.severity in (Severity.HIGH, Severity.CRITICAL)]
    if len(high_confidence_analyst) >= 2:
        return VerdictLevel.MALICIOUS

    return VerdictLevel.SUSPICIOUS
