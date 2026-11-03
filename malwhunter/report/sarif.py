"""SARIF 2.1.0 output, so findings show up in GitHub code scanning, VS Code
and other SARIF viewers. One rule per finding category; one result per
piece of evidence. Packages that were never analyzed are reported as notes,
never silently dropped, so "unscanned" cannot pass as "clean"."""
from __future__ import annotations

import json
from pathlib import Path

from malwhunter.dossier.model import Dossier, Severity, Signal
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.report.sanitize import sanitize_text
from malwhunter.report.terminal import _version

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
UNSCANNED_RULE = "unscanned-package"
_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# security-severity (0-10) is what GitHub uses to rank code-scanning alerts
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}
_MANIFESTS = ("package-lock.json", "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt")
_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def find_manifest_uri(project_dir: str | Path) -> str:
    """The dependency file results are attached to when the evidence is not
    a source file (a network connection, say). Relative to the project."""
    for name in _MANIFESTS:
        if (Path(project_dir) / name).is_file():
            return name
    return "package-lock.json"


def _location(uri: str, line: int | None, package: str) -> dict:
    physical: dict = {"artifactLocation": {"uri": uri}}
    physical["region"] = {"startLine": line if line and line > 0 else 1}
    return {"physicalLocation": physical, "logicalLocations": [{"name": package, "kind": "package"}]}


def _evidence_text(evidence) -> str:
    text = sanitize_text(evidence.excerpt)
    return f"{text} ({sanitize_text(evidence.detail)})" if evidence.detail else text


def _result(d: Dossier, signal: Signal, manifest_uri: str) -> list[dict]:
    package = f"{d.package}@{d.version}"
    results = []
    for index, ev in enumerate(signal.evidence):
        uri = f"{d.ecosystem.value}/{package}/{ev.file}" if ev.file else manifest_uri
        result = {
            "ruleId": signal.category,
            "level": _LEVEL[signal.severity],
            "message": {"text": sanitize_text(f"{package}: {signal.description}. Evidence: {_evidence_text(ev)}")},
            "locations": [_location(uri, ev.line if ev.file else None, package)],
            "partialFingerprints": {"malwhunterSignal/v1": f"{d.dossier_key}:{signal.id}:{index}"},
            "properties": {
                "package": d.package,
                "version": d.version,
                "ecosystem": d.ecosystem.value,
                "source": signal.source.value,
                "verdict": dossier_verdict(d).value,
            },
        }
        if d.ignored:
            result["suppressions"] = [
                {"kind": "external", "status": "accepted", "justification": sanitize_text(d.ignore_reason or "")}
            ]
        results.append(result)
    return results


def dossiers_to_sarif(dossiers: list[Dossier], manifest_uri: str = "package-lock.json") -> dict:
    rules: dict[str, dict] = {}
    worst: dict[str, Severity] = {}
    results: list[dict] = []

    for d in dossiers:
        for signal in d.signals:
            results.extend(_result(d, signal, manifest_uri))
            if signal.category not in worst or _ORDER.index(signal.severity) > _ORDER.index(worst[signal.category]):
                worst[signal.category] = signal.severity
            rules.setdefault(
                signal.category,
                {
                    "id": signal.category,
                    "name": signal.category,
                    "shortDescription": {"text": signal.category.replace("-", " ")},
                    "helpUri": "https://github.com/ImGauravbhosale/Malwhunter",
                },
            )
        if d.scan_error is not None and not d.ignored:
            rules.setdefault(
                UNSCANNED_RULE,
                {
                    "id": UNSCANNED_RULE,
                    "name": UNSCANNED_RULE,
                    "shortDescription": {"text": "package was not analyzed (never treated as clean)"},
                    "properties": {"security-severity": "3.0"},
                },
            )
            results.append(
                {
                    "ruleId": UNSCANNED_RULE,
                    "level": "note",
                    "message": {"text": sanitize_text(f"{d.package}@{d.version} was not scanned: {d.scan_error}")},
                    "locations": [_location(manifest_uri, None, f"{d.package}@{d.version}")],
                    "partialFingerprints": {"malwhunterSignal/v1": f"{d.dossier_key}:unscanned"},
                    "properties": {"verdict": "unscanned"},
                }
            )

    for category, severity in worst.items():
        rules[category]["defaultConfiguration"] = {"level": _LEVEL[severity]}
        rules[category]["properties"] = {"security-severity": _SECURITY_SEVERITY[severity], "tags": ["security", "supply-chain"]}

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MalwHunter",
                        "version": _version(),
                        "informationUri": "https://github.com/ImGauravbhosale/Malwhunter",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def dossiers_to_sarif_str(dossiers: list[Dossier], manifest_uri: str = "package-lock.json") -> str:
    return json.dumps(dossiers_to_sarif(dossiers, manifest_uri), indent=2)


def write_sarif_report(dossiers: list[Dossier], path: str, manifest_uri: str = "package-lock.json") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dossiers_to_sarif_str(dossiers, manifest_uri))
