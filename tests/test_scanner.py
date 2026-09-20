import json
from pathlib import Path

from malwhunter.recon.scanner import run_recon

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "npm-fixtures"


def _run(fixture_name: str):
    pkg_dir = FIXTURES / fixture_name
    package_json = json.loads((pkg_dir / "package.json").read_text())
    return run_recon(pkg_dir, package_json["name"], package_json)


def test_malicious_postinstall_is_flagged():
    signals = _run("malicious-postinstall")
    categories = {s.category for s in signals}
    assert "lifecycle-script-abuse" in categories


def test_env_exfil_pattern_is_flagged():
    signals = _run("env-exfil")
    categories = {s.category for s in signals}
    assert "sensitive-data-network-cooccurrence" in categories


def test_benign_package_has_no_signals():
    signals = _run("benign-pkg")
    assert signals == []


def test_every_signal_has_evidence():
    for fixture in ("malicious-postinstall", "env-exfil"):
        for signal in _run(fixture):
            assert len(signal.evidence) > 0
            for e in signal.evidence:
                assert e.excerpt


def test_env_harvester_triggers_all_three_new_signals():
    """Modeled on the real MAL-2026-7003 (searchresults@999.0.0) technique:
    a postinstall that isn't a raw curl|sh one-liner, so lifecycle-script-
    abuse alone would miss it entirely — the new signals exist to catch
    exactly this shape."""
    signals = _run("env-harvester")
    categories = {s.category for s in signals}
    assert "bulk-env-enumeration" in categories
    assert "known-exfil-channel" in categories
    assert "command-exec-computed-arg" in categories
    # and confirm the gap this fixture demonstrates:
    assert "lifecycle-script-abuse" not in categories
