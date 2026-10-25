from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource
from malwhunter.dossier.verdict import compute_verdict


def _signal(source, category, severity, discriminator="x") -> Signal:
    return Signal(
        id=f"{source.value}-{category}-{discriminator}",
        source=source,
        category=category,
        severity=severity,
        description="test signal",
        evidence=[Evidence(excerpt="evidence")],
    )


def test_no_signals_is_clean():
    assert compute_verdict([]).value == "clean"


def test_single_critical_signal_is_malicious_alone():
    signals = [_signal(SignalSource.DETONATION, "canary-exfiltration", Severity.CRITICAL)]
    assert compute_verdict(signals).value == "malicious"


def test_recon_alone_is_suspicious_not_malicious():
    signals = [_signal(SignalSource.RECON, "lifecycle-script-abuse", Severity.HIGH)]
    assert compute_verdict(signals).value == "suspicious"


def test_detonation_alone_is_suspicious_not_malicious():
    signals = [_signal(SignalSource.DETONATION, "unexpected-network-destination", Severity.HIGH)]
    assert compute_verdict(signals).value == "suspicious"


def test_recon_and_detonation_together_is_malicious():
    signals = [
        _signal(SignalSource.RECON, "lifecycle-script-abuse", Severity.HIGH),
        _signal(SignalSource.DETONATION, "unexpected-network-destination", Severity.HIGH),
    ]
    assert compute_verdict(signals).value == "malicious"


def test_single_analyst_signal_is_suspicious():
    signals = [_signal(SignalSource.ANALYST, "obfuscated-intent", Severity.HIGH)]
    assert compute_verdict(signals).value == "suspicious"


def test_two_agreeing_analyst_signals_is_malicious():
    signals = [
        _signal(SignalSource.ANALYST, "obfuscated-intent", Severity.HIGH, "call1"),
        _signal(SignalSource.ANALYST, "obfuscated-intent", Severity.HIGH, "call2"),
    ]
    assert compute_verdict(signals).value == "malicious"


def test_one_low_severity_analyst_signal_stays_suspicious():
    signals = [
        _signal(SignalSource.ANALYST, "obfuscated-intent", Severity.LOW, "call1"),
        _signal(SignalSource.ANALYST, "obfuscated-intent", Severity.MEDIUM, "call2"),
    ]
    assert compute_verdict(signals).value == "suspicious"


def test_weak_recon_plus_detonation_is_only_suspicious():
    # Found by probing the old rule: a typosquat-distance false positive
    # (vite -> vue) plus a binary download from an unlisted CDN — both
    # MEDIUM, both common in normal packages — used to add up to MALICIOUS.
    signals = [
        _signal(SignalSource.RECON, "typosquat-candidate", Severity.MEDIUM),
        _signal(SignalSource.DETONATION, "unexpected-network-destination", Severity.MEDIUM),
    ]
    assert compute_verdict(signals).value == "suspicious"


def test_strong_recon_plus_any_detonation_is_malicious():
    signals = [
        _signal(SignalSource.RECON, "lifecycle-script-abuse", Severity.HIGH),
        _signal(SignalSource.DETONATION, "unexpected-network-destination", Severity.MEDIUM),
    ]
    assert compute_verdict(signals).value == "malicious"


def test_low_signals_alone_stay_clean():
    signals = [_signal(SignalSource.RECON, "some-context", Severity.LOW)]
    assert compute_verdict(signals).value == "clean"


def test_unscanned_dossier_is_never_clean():
    from malwhunter.dossier.model import Dossier
    from malwhunter.dossier.verdict import dossier_verdict

    dossier = Dossier(package="x", version="1.0.0", scan_error="registry returned 503")
    assert dossier.signals == []
    assert dossier_verdict(dossier).value == "unscanned"
    assert dossier.to_dict()["verdict"] == "unscanned"
    assert dossier.to_dict()["scan_error"] == "registry returned 503"


def test_scanned_dossier_with_no_signals_is_clean():
    from malwhunter.dossier.model import Dossier
    from malwhunter.dossier.verdict import dossier_verdict

    assert dossier_verdict(Dossier(package="x", version="1.0.0")).value == "clean"
