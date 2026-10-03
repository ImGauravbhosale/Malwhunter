"""Colorized terminal report. Plain ANSI, no dependency."""
from __future__ import annotations

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"

_VERDICT_STYLE = {
    "malicious": (_RED + _BOLD, "MALICIOUS"),
    "suspicious": (_YELLOW, "SUSPICIOUS"),
    "clean": (_GREEN, "CLEAN"),
}


def dossiers_to_terminal(dossiers: list[Dossier], target: str) -> str:
    lines: list[str] = []
    verdicts = [compute_verdict(d.signals).value for d in dossiers]
    malicious = verdicts.count("malicious")
    suspicious = verdicts.count("suspicious")
    clean = verdicts.count("clean")

    detonated_count = sum(1 for d in dossiers if d.detonated)
    skipped_count = len(dossiers) - detonated_count

    lines.append(f"{_BOLD}MALWHUNTER SCAN{_RESET}  {_DIM}{target}{_RESET}")
    lines.append(
        f"{_RED}{malicious} malicious{_RESET} · {_YELLOW}{suspicious} suspicious{_RESET} · "
        f"{_GREEN}{clean} clean{_RESET} · {_DIM}{len(dossiers)} total{_RESET}"
    )
    lines.append(
        f"{_DIM}detonated {detonated_count}/{len(dossiers)} "
        f"({skipped_count} skipped — established packages or detonation disabled){_RESET}"
    )
    lines.append("")

    notable = [d for d in dossiers if compute_verdict(d.signals).value != "clean"]
    if not notable:
        lines.append(f"{_GREEN}Nothing suspicious found.{_RESET}")
        return "\n".join(lines)

    for d in notable:
        verdict = compute_verdict(d.signals).value
        style, label = _VERDICT_STYLE[verdict]
        lines.append(f"{style}[{label}]{_RESET} {_BOLD}{d.package}@{d.version}{_RESET}")
        if d.detonation_decision_reason:
            lines.append(f"  {_DIM}detonation: {d.detonation_decision_reason}{_RESET}")
        for s in d.signals:
            lines.append(f"  {_CYAN}{s.category}{_RESET} {_DIM}({s.severity.value}, {s.source.value}){_RESET}")
            lines.append(f"    {_DIM}{s.description}{_RESET}")
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                if loc:
                    lines.append(f"    {_DIM}{loc}{_RESET}  {e.excerpt}")
                else:
                    lines.append(f"    {e.excerpt}")
        lines.append("")

    return "\n".join(lines)
