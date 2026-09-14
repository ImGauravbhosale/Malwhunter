from __future__ import annotations

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict


def dossiers_to_markdown(dossiers: list[Dossier], target: str) -> str:
    lines = [f"# MalwHunter Scan Report", "", f"**Target:** `{target}`", f"**Packages analyzed:** {len(dossiers)}", ""]

    notable = [d for d in dossiers if compute_verdict(d.signals).value != "clean"]
    lines.append(f"**Notable:** {len(notable)} package(s) not clean")
    lines.append("")

    if not notable:
        lines.append("No suspicious or malicious packages found.")
        return "\n".join(lines)

    for d in notable:
        verdict = compute_verdict(d.signals).value
        lines.append(f"## {d.package}@{d.version} — `{verdict.upper()}`")
        lines.append("")
        for s in d.signals:
            lines.append(f"- **[{s.source.value}] {s.category}** ({s.severity.value}): {s.description}")
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                lines.append(f"  - `{loc}`: {e.excerpt}")
        lines.append("")

    return "\n".join(lines)


def write_markdown_report(dossiers: list[Dossier], target: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dossiers_to_markdown(dossiers, target))
