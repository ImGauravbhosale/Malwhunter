"""The Dossier: MalwHunter's core artifact, one per package@version.

"No observation, no verdict" is enforced here as a data-model invariant,
the same way a finding needs proof — a Signal cannot exist without at
least one piece of Evidence backing it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    NPM = "npm"


class SignalSource(str, Enum):
    RECON = "recon"
    DETONATION = "detonation"
    ANALYST = "analyst"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True)
class Evidence:
    """A single observed fact backing a Signal. `file`/`line` apply to
    Recon evidence (a location in the unpacked package source);
    `detail` covers everything else (a network destination, a spawned
    process's command line, a canary value seen in transit)."""

    excerpt: str
    file: str | None = None
    line: int | None = None
    detail: str | None = None

    def to_dict(self) -> dict:
        return {
            "excerpt": self.excerpt,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
        }


@dataclass
class Signal:
    id: str
    source: SignalSource
    category: str
    severity: Severity
    description: str
    evidence: list[Evidence]

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(
                f"Signal {self.id!r} has no evidence — 'no observation, no "
                f"verdict' is enforced here, not just documented."
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source.value,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def signal_id(source: SignalSource, category: str, discriminator: str) -> str:
    digest = hashlib.sha1(f"{source.value}:{category}:{discriminator}".encode(), usedforsecurity=False)
    return digest.hexdigest()[:16]


@dataclass
class Dossier:
    package: str
    version: str
    ecosystem: Ecosystem = Ecosystem.NPM
    signals: list[Signal] = field(default_factory=list)
    detonated: bool = False
    detonation_decision_reason: str | None = None
    ignored: bool = False
    ignore_reason: str | None = None

    @property
    def dossier_key(self) -> str:
        return f"{self.ecosystem.value}:{self.package}@{self.version}"

    def add_signal(self, signal: Signal) -> None:
        self.signals.append(signal)

    def to_dict(self) -> dict:
        from malwhunter.dossier.verdict import compute_verdict

        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "detonated": self.detonated,
            "detonation_decision_reason": self.detonation_decision_reason,
            "ignored": self.ignored,
            "ignore_reason": self.ignore_reason,
            "verdict": compute_verdict(self.signals).value,
            "signals": [s.to_dict() for s in self.signals],
        }
