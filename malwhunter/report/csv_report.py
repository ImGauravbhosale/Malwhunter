"""CSV output: one row per piece of evidence, plus one row for each package
with no findings (so clean and unscanned packages are still listed). Opens
in Excel, Sheets or any script."""
from __future__ import annotations

import csv
import io

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.report.sanitize import sanitize_text

COLUMNS = (
    "package", "version", "ecosystem", "verdict", "ignored", "severity", "source",
    "category", "description", "file", "line", "evidence", "detail", "scan_error",
)


def _cell(value: object) -> str:
    """Attacker-controlled text must not run as a spreadsheet formula."""
    text = sanitize_text("" if value is None else str(value)).replace("\n", " ")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def dossiers_to_csv_str(dossiers: list[Dossier]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for d in dossiers:
        base = [d.package, d.version, d.ecosystem.value, dossier_verdict(d).value, "yes" if d.ignored else "no"]
        rows = [
            [s.severity.value, s.source.value, s.category, s.description, e.file, e.line, e.excerpt, e.detail, d.scan_error]
            for s in d.signals
            for e in s.evidence
        ] or [["", "", "", "", "", "", "", "", d.scan_error]]
        for row in rows:
            writer.writerow([_cell(v) for v in base + row])
    return out.getvalue()


def write_csv_report(dossiers: list[Dossier], path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(dossiers_to_csv_str(dossiers))
