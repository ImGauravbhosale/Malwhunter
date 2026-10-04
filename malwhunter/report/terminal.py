"""Colorized terminal report. Plain ANSI, no dependency."""
from __future__ import annotations

import shutil

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_WHITE = "\033[97m"
_BLACK = "\033[30m"
_BG_RED = "\033[41m"
_BG_YELLOW = "\033[43m"
_BG_GREEN = "\033[42m"

_VERDICT_STYLE = {
    "malicious": (_RED + _BOLD, "MALICIOUS"),
    "suspicious": (_YELLOW, "SUSPICIOUS"),
    "clean": (_GREEN, "CLEAN"),
}

_BANNER_STYLE = {
    "malicious": (_BG_RED, _WHITE, "MALICIOUS PACKAGES FOUND"),
    "suspicious": (_BG_YELLOW, _BLACK, "SUSPICIOUS PACKAGES FOUND"),
    "clean": (_BG_GREEN, _BLACK, "ALL PACKAGES CLEAN"),
}

_MIN_WIDTH = 48
_MAX_WIDTH = 100


def _width() -> int:
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    return max(_MIN_WIDTH, min(cols, _MAX_WIDTH))


def _rule(char: str, width: int, color: str = _DIM) -> str:
    return f"{color}{char * width}{_RESET}"


def _bar(text: str, width: int, bg: str, fg: str) -> str:
    text = f" {text} "
    pad = max(width - len(text), 0)
    left = pad // 2
    right = pad - left
    return f"{bg}{fg}{_BOLD}{' ' * left}{text}{' ' * right}{_RESET}"


def _ignored_section(ignored: list[Dossier], width: int) -> list[str]:
    lines = [
        _rule("─", width),
        f"{_DIM}{_BOLD}IGNORED{_RESET}  {_DIM}({len(ignored)} via .MHignore — excluded from --fail-on){_RESET}",
        _rule("─", width),
        "",
    ]
    for d in ignored:
        verdict = compute_verdict(d.signals).value
        lines.append(f"{_DIM}[{verdict.upper()}, ignored]{_RESET} {_DIM}{_BOLD}{d.package}@{d.version}{_RESET}")
        lines.append(f"  {_DIM}reason: {d.ignore_reason}{_RESET}")
    return lines


def dossiers_to_terminal(dossiers: list[Dossier], target: str) -> str:
    width = _width()
    lines: list[str] = []

    active = [d for d in dossiers if not d.ignored]
    ignored = [d for d in dossiers if d.ignored]

    verdicts = [compute_verdict(d.signals).value for d in active]
    malicious = verdicts.count("malicious")
    suspicious = verdicts.count("suspicious")
    clean = verdicts.count("clean")

    detonated_count = sum(1 for d in dossiers if d.detonated)
    skipped_count = len(dossiers) - detonated_count

    overall = "malicious" if malicious else "suspicious" if suspicious else "clean"
    bg, fg, status_text = _BANNER_STYLE[overall]

    # Banner
    lines.append(_bar(f"MALWHUNTER — {status_text}", width, bg, fg))
    lines.append(f"{_DIM}scanning{_RESET} {target}")
    lines.append("")

    # Summary
    lines.append(
        f"  {_RED}{_BOLD}{malicious} malicious{_RESET}   "
        f"{_YELLOW}{_BOLD}{suspicious} suspicious{_RESET}   "
        f"{_GREEN}{_BOLD}{clean} clean{_RESET}   "
        f"{_DIM}{len(active)} total{_RESET}"
        + (f"   {_DIM}({len(ignored)} ignored via .MHignore){_RESET}" if ignored else "")
    )
    lines.append(
        f"  {_DIM}detonated {detonated_count}/{len(dossiers)} "
        f"({skipped_count} skipped — established packages or detonation disabled){_RESET}"
    )
    lines.append("")

    notable = [d for d in active if compute_verdict(d.signals).value != "clean"]
    if not notable:
        lines.append(_rule("─", width))
        lines.append(f"  {_GREEN}{_BOLD}✓ Nothing suspicious found.{_RESET}")
        if ignored:
            lines.append("")
            lines.extend(_ignored_section(ignored, width))
        return "\n".join(lines)

    lines.append(_rule("─", width))
    lines.append(f"{_BOLD}FINDINGS{_RESET}  {_DIM}({len(notable)} of {len(active)} packages){_RESET}")
    lines.append(_rule("─", width))
    lines.append("")

    for i, d in enumerate(notable):
        verdict = compute_verdict(d.signals).value
        style, label = _VERDICT_STYLE[verdict]
        lines.append(f"{style}[{label}]{_RESET} {_BOLD}{d.package}@{d.version}{_RESET}")
        if d.detonation_decision_reason:
            lines.append(f"  {_DIM}↳ detonation: {d.detonation_decision_reason}{_RESET}")
        for s in d.signals:
            lines.append(f"  {_CYAN}●{_RESET} {_CYAN}{s.category}{_RESET} {_DIM}({s.severity.value}, {s.source.value}){_RESET}")
            lines.append(f"      {_DIM}{s.description}{_RESET}")
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                if loc:
                    lines.append(f"      {_DIM}{loc}{_RESET}  {e.excerpt}")
                else:
                    lines.append(f"      {e.excerpt}")
        if i < len(notable) - 1:
            lines.append("")
            lines.append(_rule("·", width))
            lines.append("")
        else:
            lines.append("")

    if ignored:
        lines.extend(_ignored_section(ignored, width))

    return "\n".join(lines)
