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
