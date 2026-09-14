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
