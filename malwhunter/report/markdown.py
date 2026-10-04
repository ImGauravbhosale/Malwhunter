from __future__ import annotations

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict


def dossiers_to_markdown(dossiers: list[Dossier], target: str) -> str:
    active = [d for d in dossiers if not d.ignored]
    ignored = [d for d in dossiers if d.ignored]

    detonated_count = sum(1 for d in dossiers if d.detonated)
    lines = [
        "# MalwHunter Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Packages analyzed:** {len(active)}"
        + (f" ({len(ignored)} ignored via `.MHignore`)" if ignored else ""),
        f"**Detonated:** {detonated_count}/{len(dossiers)} "
        f"({len(dossiers) - detonated_count} skipped — established packages or detonation disabled)",
        "",
    ]

    notable = [d for d in active if compute_verdict(d.signals).value != "clean"]
    clean_pkgs = [d for d in active if compute_verdict(d.signals).value == "clean"]
    lines.append(f"**Notable:** {len(notable)} package(s) not clean")
    lines.append("")

    if not notable:
        lines.append("No suspicious or malicious packages found.")
        if ignored:
            lines.append("")
            lines.extend(_ignored_section(ignored))
        if clean_pkgs:
            lines.append("")
            lines.extend(_clean_section(clean_pkgs))
        return "\n".join(lines)

    for d in notable:
        verdict = compute_verdict(d.signals).value
        lines.append(f"## {d.package}@{d.version} — `{verdict.upper()}`")
        lines.append("")
        if d.detonation_decision_reason:
            lines.append(f"*Detonation: {d.detonation_decision_reason}*")
            lines.append("")
        for i, s in enumerate(d.signals, 1):
            lines.append(f"{i}. **{s.description}**")
            lines.append(f"   - *technical: {s.category} · {s.severity.value} severity · detected by {s.source.value}*")
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                lines.append(f"   - `{loc}` (in `{d.package}@{d.version}`): {e.excerpt}")
        lines.append("")

    if ignored:
        lines.extend(_ignored_section(ignored))

    if clean_pkgs:
        lines.extend(_clean_section(clean_pkgs))

    return "\n".join(lines)


def _ignored_section(ignored: list[Dossier]) -> list[str]:
    lines = [f"## Ignored ({len(ignored)} via `.MHignore` — excluded from `--fail-on`)", ""]
    for d in ignored:
        verdict = compute_verdict(d.signals).value
        lines.append(f"- **{d.package}@{d.version}** (`{verdict.upper()}`) — {d.ignore_reason}")
    lines.append("")
    return lines


def _clean_section(clean: list[Dossier]) -> list[str]:
    lines = [f"## Clean ({len(clean)} package(s))", ""]
    for d in clean:
        lines.append(f"- {d.package}@{d.version}")
    lines.append("")
    return lines


def write_markdown_report(dossiers: list[Dossier], target: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dossiers_to_markdown(dossiers, target))
