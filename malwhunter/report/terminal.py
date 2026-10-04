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

_MIN_WIDTH = 60  # must fit the 59-col "MALWHUNTER" block-letter banner
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


# 5-row block-letter font, hand-drawn — only the letters MalwHunter's own
# name needs. Each glyph is a fixed 5-wide x 5-tall grid of █/space.
_GLYPHS = {
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "L": ["█    ", "█    ", "█    ", "█    ", "█████"],
    "W": ["█   █", "█   █", "█ █ █", "██ ██", "█   █"],
    "H": ["█   █", "█   █", "█████", "█   █", "█   █"],
    "U": ["█   █", "█   █", "█   █", "█   █", " ███ "],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "T": ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "R": ["████ ", "█   █", "████ ", "█ █  ", "█  █ "],
    " ": ["   ", "   ", "   ", "   ", "   "],
}


def _big_text(word: str, color: str, width: int) -> list[str]:
    rows = ["".join(_GLYPHS[ch][r] + " " for ch in word.upper()).rstrip() for r in range(5)]
    text_width = max(len(r) for r in rows)
    pad = max((width - text_width) // 2, 0)
    return [f"{' ' * pad}{color}{_BOLD}{r}{_RESET}" for r in rows]


def startup_banner(target: str) -> str:
    """Printed before analysis starts — the verdict isn't known yet, so this
    is a neutral brand banner, distinct from the colored verdict banner
    `dossiers_to_terminal` prints once results are in."""
    width = _width()
    lines = [
        _rule("═", width, _CYAN),
        "",
        *_big_text("MALWHUNTER", _CYAN, width),
        "",
        f"{' ' * max((width - len('npm supply-chain scanner')) // 2, 0)}{_DIM}npm supply-chain scanner{_RESET}",
        "",
        f"{_DIM}scanning{_RESET} {target}",
        _rule("═", width, _CYAN),
    ]
    return "\n".join(lines)


def analyzing_line(name: str, version: str) -> str:
    return f"{_DIM}▸ Analyzing{_RESET} {_BOLD}{name}@{version}{_RESET}..."


def done_line(name: str, version: str) -> str:
    return f"{_GREEN}✓ Done{_RESET}      {_BOLD}{name}@{version}{_RESET}"


def _clean_section(clean: list[Dossier], width: int) -> list[str]:
    lines = [
        _rule("─", width),
        f"{_GREEN}{_BOLD}CLEAN{_RESET}  {_DIM}({len(clean)} package(s)){_RESET}",
        _rule("─", width),
        "",
    ]
    for d in clean:
        lines.append(f"  {_GREEN}✓{_RESET} {d.package}@{d.version}")
    return lines


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
    clean_pkgs = [d for d in active if compute_verdict(d.signals).value == "clean"]
    if not notable:
        lines.append(_rule("─", width))
        lines.append(f"  {_GREEN}{_BOLD}✓ Nothing suspicious found.{_RESET}")
        if ignored:
            lines.append("")
            lines.extend(_ignored_section(ignored, width))
        if clean_pkgs:
            lines.append("")
            lines.extend(_clean_section(clean_pkgs, width))
        return "\n".join(lines)

    lines.append(_rule("─", width))
    lines.append(f"{_BOLD}FINDINGS{_RESET}  {_DIM}({len(notable)} of {len(active)} packages){_RESET}")
    lines.append(_rule("─", width))
    lines.append("")

    for i, d in enumerate(notable):
        verdict = compute_verdict(d.signals).value
        bg, fg, _ = _BANNER_STYLE[verdict]
        lines.append("")
        lines.append(_bar(f"[{verdict.upper()}]  {d.package}@{d.version}", width, bg, fg))
        if d.detonation_decision_reason:
            lines.append(f"  {_DIM}↳ detonation: {d.detonation_decision_reason}{_RESET}")
        lines.append("")
        for j, s in enumerate(d.signals, 1):
            lines.append(f"  {_BOLD}{j}. {s.description}{_RESET}")
            lines.append(
                f"     {_DIM}technical: {s.category} · {s.severity.value} severity · "
                f"detected by {s.source.value}{_RESET}"
            )
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                pkg_tag = f"{_DIM} (in {d.package}@{d.version}){_RESET}"
                if loc:
                    lines.append(f"     {_CYAN}{loc}{_RESET}{pkg_tag}  {e.excerpt}")
                else:
                    lines.append(f"     {e.excerpt}{pkg_tag}")
            if j < len(d.signals):
                lines.append("")
        if i < len(notable) - 1:
            lines.append("")
            lines.append(_rule("·", width))
    lines.append("")

    if ignored:
        lines.extend(_ignored_section(ignored, width))
        lines.append("")

    if clean_pkgs:
        lines.extend(_clean_section(clean_pkgs, width))

    return "\n".join(lines)
