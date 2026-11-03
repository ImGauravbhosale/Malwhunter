"""Colorized terminal report. Plain ANSI, no dependency."""
from __future__ import annotations

import os
import shutil

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.report.sanitize import sanitize_text as _clean

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
_MAGENTA = "\033[35m"
_BG_MAGENTA = "\033[45m"

_VERDICT_STYLE = {
    "malicious": (_RED + _BOLD, "MALICIOUS"),
    "suspicious": (_YELLOW, "SUSPICIOUS"),
    "clean": (_GREEN, "CLEAN"),
    "unscanned": (_MAGENTA, "UNSCANNED"),
}

_BANNER_STYLE = {
    "malicious": (_BG_RED, _WHITE, "MALICIOUS PACKAGES FOUND"),
    "suspicious": (_BG_YELLOW, _BLACK, "SUSPICIOUS PACKAGES FOUND"),
    "clean": (_BG_GREEN, _BLACK, "ALL PACKAGES CLEAN"),
    "unscanned": (_BG_MAGENTA, _WHITE, "SCAN INCOMPLETE"),
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
    lines = [*_logo(width)[:-1], f"{_DIM}scanning{_RESET} {target}", _rule("═", width, _CYAN)]
    return "\n".join(lines)


_TAGLINE = "Hunts the malware hiding in your dependencies"
_BIG_LOGO_COLUMNS = 92  # the big logo is 89 wide plus a 2-column margin; narrower terminals get the compact one

# The big wordmark, 6 rows tall. Drawn by hand (box-drawing "shadow" letters).
_SHADOW = {
    "M": ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "L": ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
    "W": ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
    "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
}
_GRADIENT = ((0, 212, 255), (62, 120, 255), (150, 80, 255), (255, 60, 140))  # cyan -> blue -> violet -> pink


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("malwhunter")
    except Exception:  # noqa: BLE001 - a missing version must never break the first screen
        return "dev"


def _truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


def _gradient_row(row: str) -> str:
    """One row of the logo, cyan to pink left to right. Terminals without
    24-bit colour get the plain cyan the logo always had."""
    if not _truecolor():
        return f"{_CYAN}{_BOLD}{row}{_RESET}"
    out, last = [], len(row) - 1 or 1
    span = len(_GRADIENT) - 1
    for i, ch in enumerate(row):
        pos = i / last * span
        k = min(int(pos), span - 1)
        a, b = _GRADIENT[k], _GRADIENT[k + 1]
        r, g, bl = (round(x + (y - x) * (pos - k)) for x, y in zip(a, b, strict=True))
        out.append(f"\033[38;2;{r};{g};{bl}m{ch}")
    return "".join(out) + _RESET


def _terminal_columns() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).columns


def _logo(width: int) -> list[str]:
    """The MALWHUNTER wordmark, then the three ways to run it with the
    version at the right edge, then the tagline. The big shadow-letter logo
    is used when the terminal is wide enough for it, the compact block logo
    otherwise (and in piped output / CI logs, where there is no width)."""
    if _terminal_columns() >= _BIG_LOGO_COLUMNS:
        rows = ["".join(_SHADOW[c][r] for c in "MALWHUNTER") for r in range(6)]
        margin = 2
        art = [" " * margin + _gradient_row(row) for row in rows]
        span = len(rows[0])
    else:
        art = _big_text("MALWHUNTER", _CYAN, width)
        span = max(len("".join(_GLYPHS[c][i] + " " for c in "MALWHUNTER").rstrip()) for i in range(5))
        margin = max((width - span) // 2, 0)

    pillars = (
        f"{_GREEN}●{_RESET} static analysis   {_YELLOW}●{_RESET} detonation   {_MAGENTA}●{_RESET} verifiable evidence"
    )
    pillars_len = len("● static analysis   ● detonation   ● verifiable evidence")
    version = f"v{_version()}"
    gap = max(span - pillars_len - len(version), 3)
    return [
        _rule("═", width, _CYAN),
        "",
        *art,
        "",
        f"{' ' * margin}{pillars}{' ' * gap}{_DIM}{version}{_RESET}",
        f"{' ' * margin}{_DIM}{_TAGLINE}{_RESET}",
        "",
        _rule("═", width, _CYAN),
    ]


# (what it does, command lines): copy-pasteable, shown by `malwhunter` and `malwhunter --help`.
# Shown as written, so tests check every flag in here against the real commands.
LOCAL_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Static analysis only: reads the code, runs nothing, no Docker",
     ("malwhunter scan . --mode static",)),
    ("Detonation only: runs install scripts in a sandbox (needs Docker)",
     ("malwhunter scan . --mode detonate-only",)),
    ("Static analysis + detonation, all in one",
     ("malwhunter scan . --mode full",)),
    ("One package (npm: name@version, PyPI: pypi:name==version)",
     ("malwhunter inspect left-pad@1.3.0 --mode full",
      "malwhunter inspect pypi:requests==2.31.0 --mode static")),
    ("Optional extras (off unless you ask): a brief to paste into any AI agent, or an AI second opinion",
     ("malwhunter scan . --mode static --format agent-prompt --out review.md",
      "malwhunter scan . --mode static --ai")),
)
CI_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Full scan: every dependency, nothing remembered between runs",
     ("malwhunter scan . --mode full --fail-on malicious --jobs 4 \\",
      "  --format json --out malwhunter-report.json")),
    ("Delta scan: only new or changed packages (persist the cache folder)",
     ("malwhunter scan . --mode auto --fail-on malicious --jobs 4 \\",
      "  --cache-dir .malwhunter-cache --format json --out malwhunter-report.json")),
)


def help_screen() -> str:
    width = _width()
    rule = _rule("─", width)

    def section(title: str, groups) -> list[str]:
        out = ["", rule, f"{_BOLD}{title}{_RESET}", rule]
        for what, commands in groups:
            out += ["", f"  {_DIM}{what}{_RESET}", *(f"    {_GREEN}{cmd}{_RESET}" for cmd in commands)]
        return out

    lines = [
        *_logo(width),
        "",
        f"{_BOLD}USAGE{_RESET}  malwhunter <command> [options]",
        "",
        f"{_BOLD}COMMANDS{_RESET}",
        f"  {_CYAN}{'scan <path>':<19}{_RESET}hunt malware in every dependency of a project",
        f"  {_CYAN}{'inspect <package>':<19}{_RESET}check a single package",
        *section("RUNNING LOCALLY", LOCAL_COMMANDS),
        *section("RUNNING IN CI/CD", CI_COMMANDS),
        "",
        rule,
        f"{_DIM}Exit code: 0 = nothing found, 1 = findings at or above --fail-on,{_RESET}",
        f"{_DIM}           2 = some package could not be scanned.{_RESET}",
        f"{_DIM}All options: malwhunter scan --help    malwhunter inspect --help{_RESET}",
        "",
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
        verdict = dossier_verdict(d).value
        lines.append(f"{_DIM}[{verdict.upper()}, ignored]{_RESET} {_DIM}{_BOLD}{d.package}@{d.version}{_RESET}")
        lines.append(f"  {_DIM}reason: {_clean(d.ignore_reason or '')}{_RESET}")
    return lines


def _detonation_section(dossiers: list[Dossier], width: int) -> list[str]:
    """What the sandbox saw for every package that was actually detonated,
    including the ones that came out clean (which otherwise appear only as
    a name in the CLEAN list)."""
    ran = [d for d in dossiers if d.detonated and d.detonation_summary]
    if not ran:
        return []
    lines = [
        _rule("─", width),
        f"{_BOLD}DETONATION RESULTS{_RESET}  {_DIM}({len(ran)} package(s) run in the sandbox){_RESET}",
        _rule("─", width),
        "",
    ]
    for d in ran:
        sm = d.detonation_summary or {}
        style, label = _VERDICT_STYLE[dossier_verdict(d).value]
        status = "timed out" if sm.get("timed_out") else f"exit code {sm.get('exit_code')}"
        lines.append(
            f"{style}[{label}]{_RESET} {_BOLD}{_clean(d.package)}@{_clean(d.version)}{_RESET}  "
            f"{_DIM}{status}, {sm.get('seconds')}s{_RESET}"
        )
        for step, command in (sm.get("scripts_run") or {}).items():
            lines.append(f"  {_DIM}ran {step}:{_RESET} {_clean(command)}")
        https = sm.get("https_hosts") or {}
        http = sm.get("plain_http_hosts") or {}
        expected = sorted(set(https.get("expected", []) + http.get("expected", [])))
        unexpected = sorted(set(https.get("unexpected", []) + http.get("unexpected", [])))
        lines.append(f"  {_DIM}expected hosts contacted:{_RESET} {_clean(', '.join(expected)) or 'none'}")
        color = _YELLOW if unexpected else _DIM
        lines.append(f"  {_DIM}unexpected hosts contacted:{_RESET} {color}{_clean(', '.join(unexpected)) or 'none'}{_RESET}")
        if sm.get("blocked_internal_attempts"):
            lines.append(f"  {_RED}blocked internal-network attempts:{_RESET} {_clean(', '.join(sm['blocked_internal_attempts']))}")
        tr = sm.get("tracing") or {}
        if tr.get("enabled"):
            procs = tr.get("processes") or []
            lines.append(f"  {_DIM}processes started:{_RESET} {_clean('; '.join(procs[:6])) or 'none'}{_DIM}{' …' if len(procs) > 6 else ''}{_RESET}")
            if tr.get("sensitive_or_persistent_files"):
                lines.append(f"  {_RED}sensitive files touched:{_RESET} {_clean(', '.join(tr['sensitive_or_persistent_files']))}")
            if tr.get("direct_connection_attempts"):
                lines.append(f"  {_YELLOW}direct connections (bypassing the proxy):{_RESET} {_clean(', '.join(tr['direct_connection_attempts']))}")
        elif tr.get("note"):
            lines.append(f"  {_DIM}runtime trace: {_clean(tr['note'])}{_RESET}")
        leaked = sm.get("canaries_leaked") or []
        if leaked:
            lines.append(f"  {_RED}{_BOLD}canary secrets leaked: {_clean(', '.join(leaked))}{_RESET}")
        else:
            lines.append(
                f"  {_GREEN}canary secrets leaked: none{_RESET} {_DIM}(of {len(sm.get('canaries_planted', []))} planted){_RESET}"
            )
        for key in ("stdout_tail", "stderr_tail"):
            if sm.get(key, "").strip():
                lines.append(f"  {_DIM}{key.split('_')[0]}:{_RESET} {_clean(sm[key].strip())[-300:]}")
        lines.append("")
    limits = "; ".join(dict.fromkeys(x for d in ran for x in (d.detonation_summary or {}).get("limits", [])))
    lines.append(f"  {_DIM}limits: {limits}{_RESET}")
    lines.append("")
    return lines


def dossiers_to_terminal(dossiers: list[Dossier], target: str) -> str:
    width = _width()
    lines: list[str] = []

    active = [d for d in dossiers if not d.ignored]
    ignored = [d for d in dossiers if d.ignored]

    verdicts = [dossier_verdict(d).value for d in active]
    malicious = verdicts.count("malicious")
    suspicious = verdicts.count("suspicious")
    clean = verdicts.count("clean")
    unscanned = verdicts.count("unscanned")

    detonated_count = sum(1 for d in dossiers if d.detonated)
    skipped_count = len(dossiers) - detonated_count

    overall = (
        "malicious" if malicious else "suspicious" if suspicious else "unscanned" if unscanned else "clean"
    )
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
        + (f"{_MAGENTA}{_BOLD}{unscanned} unscanned{_RESET}   " if unscanned else "")
        + f"{_DIM}{len(active)} total{_RESET}"
        + (f"   {_DIM}({len(ignored)} ignored via .MHignore){_RESET}" if ignored else "")
    )
    lines.append(
        f"  {_DIM}detonated {detonated_count}/{len(dossiers)} "
        f"({skipped_count} skipped — established packages or detonation disabled){_RESET}"
    )
    lines.append("")

    notable = [d for d in active if dossier_verdict(d).value != "clean"]
    clean_pkgs = [d for d in active if dossier_verdict(d).value == "clean"]
    if not notable:
        lines.append(_rule("─", width))
        lines.append(f"  {_GREEN}{_BOLD}✓ Nothing suspicious found.{_RESET}")
        if ignored:
            lines.append("")
            lines.extend(_ignored_section(ignored, width))
        det = _detonation_section(dossiers, width)
        if det:
            lines.append("")
            lines.extend(det)
        if clean_pkgs:
            lines.append("")
            lines.extend(_clean_section(clean_pkgs, width))
        return "\n".join(lines)

    lines.append(_rule("─", width))
    lines.append(f"{_BOLD}FINDINGS{_RESET}  {_DIM}({len(notable)} of {len(active)} packages){_RESET}")
    lines.append(_rule("─", width))
    lines.append("")

    for i, d in enumerate(notable):
        verdict = dossier_verdict(d).value
        bg, fg, _ = _BANNER_STYLE[verdict]
        lines.append("")
        lines.append(_bar(f"[{verdict.upper()}]  {d.package}@{d.version}", width, bg, fg))
        if d.scan_error:
            lines.append(f"  {_MAGENTA}↳ not scanned: {_clean(d.scan_error)}{_RESET}")
        if d.detonation_decision_reason:
            lines.append(f"  {_DIM}↳ detonation: {_clean(d.detonation_decision_reason)}{_RESET}")
        lines.append("")
        for j, s in enumerate(d.signals, 1):
            lines.append(f"  {_BOLD}{j}. {_clean(s.description)}{_RESET}")
            lines.append(
                f"     {_DIM}technical: {s.category} · {s.severity.value} severity · "
                f"detected by {s.source.value}{_RESET}"
            )
            for e in s.evidence:
                loc = _clean(f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or ""))
                excerpt = _clean(e.excerpt)
                pkg_tag = f"{_DIM} (in {d.package}@{d.version}){_RESET}"
                if loc:
                    lines.append(f"     {_CYAN}{loc}{_RESET}{pkg_tag}  {excerpt}")
                else:
                    lines.append(f"     {excerpt}{pkg_tag}")
            if j < len(d.signals):
                lines.append("")
        if i < len(notable) - 1:
            lines.append("")
            lines.append(_rule("·", width))
    lines.append("")

    if ignored:
        lines.extend(_ignored_section(ignored, width))
        lines.append("")

    lines.extend(_detonation_section(dossiers, width))

    if clean_pkgs:
        lines.extend(_clean_section(clean_pkgs, width))

    return "\n".join(lines)
