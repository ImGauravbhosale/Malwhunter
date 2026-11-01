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
    PYPI = "pypi"


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
    # The package was never actually analyzed (fetch/extract failed, or no
    # exact version to fetch). Deliberately not CLEAN: "we didn't look" must
    # never be reported the same way as "we looked and found nothing".
    UNSCANNED = "unscanned"


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

    @classmethod
    def from_dict(cls, data: dict) -> Evidence:
        return cls(
            excerpt=data["excerpt"], file=data.get("file"), line=data.get("line"), detail=data.get("detail")
        )


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

    @classmethod
    def from_dict(cls, data: dict) -> Signal:
        return cls(
            id=data["id"],
            source=SignalSource(data["source"]),
            category=data["category"],
            severity=Severity(data["severity"]),
            description=data["description"],
            evidence=[Evidence.from_dict(e) for e in data["evidence"]],
        )


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
    scan_error: str | None = None
    # What the Detonation run observed (scripts run, exit code, network
    # destinations, canary result), so a reader can see what happened even
    # when nothing was flagged. None when no container ran.
    detonation_summary: dict | None = None
    # Source excerpts around each piece of evidence, captured while the
    # unpacked package still exists. Used by the AI-review handoff; kept out
    # of the JSON report so reports stay small.
    code_context: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    @property
    def dossier_key(self) -> str:
        return f"{self.ecosystem.value}:{self.package}@{self.version}"

    def add_signal(self, signal: Signal) -> None:
        self.signals.append(signal)

    def to_dict(self) -> dict:
        from malwhunter.dossier.verdict import dossier_verdict

        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "detonated": self.detonated,
            "detonation_decision_reason": self.detonation_decision_reason,
            "ignored": self.ignored,
            "ignore_reason": self.ignore_reason,
            "scan_error": self.scan_error,
            "detonation_summary": self.detonation_summary,
            "verdict": dossier_verdict(self).value,
            "signals": [s.to_dict() for s in self.signals],
        }

    @classmethod
    def from_dict(cls, data: dict) -> Dossier:
        """Rebuilds a Dossier from `to_dict()` output (the delta cache).
        `verdict` is recomputed from signals, never trusted from disk."""
        return cls(
            package=data["package"],
            version=data["version"],
            ecosystem=Ecosystem(data.get("ecosystem", "npm")),
            signals=[Signal.from_dict(s) for s in data.get("signals", [])],
            detonated=bool(data.get("detonated", False)),
            detonation_decision_reason=data.get("detonation_decision_reason"),
            detonation_summary=data.get("detonation_summary"),
        )
