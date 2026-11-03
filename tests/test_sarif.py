import json

from click.testing import CliRunner

from malwhunter.cli import cli
from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource
from malwhunter.report.sarif import dossiers_to_sarif, find_manifest_uri


def _dossier() -> Dossier:
    return Dossier(
        package="evil",
        version="1.0.0",
        signals=[
            Signal(
                id="s1", source=SignalSource.RECON, category="env-exfiltration", severity=Severity.HIGH,
                description="reads env and posts it",
                evidence=[Evidence(excerpt="fetch(url, process.env)", file="index.js", line=7)],
            ),
            Signal(
                id="s2", source=SignalSource.DETONATION, category="canary-exfiltration", severity=Severity.CRITICAL,
                description="sent a tripwire secret",
                evidence=[Evidence(excerpt="POST https://x.test/", detail="destination=x.test")],
            ),
        ],
    )


def test_sarif_structure_and_levels():
    sarif = dossiers_to_sarif([_dossier()], "uv.lock")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "MalwHunter"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"env-exfiltration", "canary-exfiltration"}
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["env-exfiltration"]["level"] == "error"
    loc = by_rule["env-exfiltration"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "npm/evil@1.0.0/index.js"
    assert loc["region"]["startLine"] == 7
    # evidence without a source file is attached to the dependency file
    loc2 = by_rule["canary-exfiltration"]["locations"][0]["physicalLocation"]
    assert loc2["artifactLocation"]["uri"] == "uv.lock"
    assert loc2["region"]["startLine"] == 1
    assert by_rule["canary-exfiltration"]["properties"]["verdict"] == "malicious"


def test_sarif_reports_unscanned_and_suppresses_ignored():
    unscanned = Dossier(package="flask", version="", scan_error="no exact version")
    ignored = _dossier()
    ignored.ignored, ignored.ignore_reason = True, "reviewed by us"
    results = dossiers_to_sarif([unscanned, ignored])["runs"][0]["results"]
    assert any(r["ruleId"] == "unscanned-package" and r["level"] == "note" for r in results)
    suppressed = [r for r in results if "suppressions" in r]
    assert suppressed and suppressed[0]["suppressions"][0]["justification"] == "reviewed by us"


def test_sarif_strips_terminal_escapes():
    d = _dossier()
    d.signals[0].evidence = [Evidence(excerpt="\x1b[31mred\x1b[0m", file="a.js", line=1)]
    text = json.dumps(dossiers_to_sarif([d]))
    assert "\\u001b" not in text


def test_find_manifest_uri(tmp_path):
    assert find_manifest_uri(tmp_path) == "package-lock.json"
    (tmp_path / "poetry.lock").write_text("")
    assert find_manifest_uri(tmp_path) == "poetry.lock"


def test_cli_accepts_sarif_format():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert "sarif" in result.output


def test_csv_rows_and_formula_guard():
    import csv
    import io

    from malwhunter.report.csv_report import dossiers_to_csv_str

    d = _dossier()
    d.signals[0].evidence = [Evidence(excerpt="=HYPERLINK(\"http://x\")", file="index.js", line=7)]
    clean = Dossier(package="ok", version="1.0.0")
    rows = list(csv.DictReader(io.StringIO(dossiers_to_csv_str([d, clean, Dossier(package="f", version="", scan_error="no exact version")]))))
    assert len(rows) == 4  # 2 findings + clean + unscanned
    assert rows[0]["evidence"].startswith("'=")
    assert {r["package"]: r["verdict"] for r in rows}["f"] == "unscanned"
    assert [r for r in rows if r["package"] == "ok"][0]["category"] == ""
