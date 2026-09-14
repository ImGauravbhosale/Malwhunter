"""Wires the Analyst into Recon's ambiguous case: a packed/high-entropy
string blob that matched nothing in the deterministic catalog. Two
independently-framed calls stand in for a second opinion — the `claude`
CLI exposes no sampling control to get independence from randomness, so
independence comes from asking the question two different ways instead,
matching the verdict-combination rule that two agreeing Analyst signals
are needed before this alone can call something malicious.
"""
from __future__ import annotations

from malwhunter.analyst.session import Analyst
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id

_SKEPTICAL_SYSTEM = (
    "You are reviewing a string literal found in an npm package's source "
    "code that a deterministic heuristic flagged as high-entropy/possibly "
    "packed or obfuscated. Your default assumption is that it is "
    "legitimate — minified code, a compiled asset, a hash, a font or "
    "image encoded as base64, a cryptographic key, or similar ordinary "
    "content are all common and NOT malicious. Only say malicious=true if "
    "you have a specific, concrete reason to believe this blob decodes to "
    "or represents credential-harvesting, backdoor, or remote-code-"
    "execution logic. Be conservative."
)

_SUSPICIOUS_SYSTEM = (
    "You are a malware analyst reviewing a string literal found in an "
    "npm package's source code that a deterministic heuristic flagged as "
    "high-entropy/possibly packed or obfuscated. Actively look for signs "
    "this is a disguised payload — a base64/hex-encoded script, an "
    "encoded URL or IP address, obfuscated credential-harvesting or "
    "backdoor logic. If you find a concrete, specific reason for concern, "
    "say malicious=true. If you genuinely find nothing suspicious after "
    "looking closely, concede malicious=false rather than guessing."
)


def _prompt(file: str, line: int | None, excerpt: str) -> str:
    location = f"{file}:{line}" if line else file
    return f"Location: {location}\n\nFlagged string (truncated):\n{excerpt}"


def judge_packed_blob(analyst: Analyst, *, file: str, line: int | None, excerpt: str) -> list[Signal]:
    """Runs both framings and returns 0, 1, or 2 ANALYST signals —
    verdict combination requires two agreeing before this alone reaches
    'malicious', so both calls' results are surfaced, not just a
    collapsed yes/no."""
    prompt = _prompt(file, line, excerpt)
    signals: list[Signal] = []

    for persona, system in (("skeptical", _SKEPTICAL_SYSTEM), ("suspicious", _SUSPICIOUS_SYSTEM)):
        verdict = analyst.ask(system=system, prompt=prompt)
        if not verdict.ok or not verdict.malicious:
            continue
        severity = Severity.HIGH if verdict.confidence >= 0.7 else Severity.MEDIUM
        signals.append(
            Signal(
                id=signal_id(SignalSource.ANALYST, "obfuscated-intent", f"{file}:{line}:{persona}"),
                source=SignalSource.ANALYST,
                category="obfuscated-intent",
                severity=severity,
                description=f"[{persona}] {verdict.rationale}",
                evidence=[Evidence(excerpt=excerpt, file=file, line=line)],
            )
        )

    return signals
