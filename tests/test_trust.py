from malwhunter.chamber.trust import decide_detonation
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.intake.registry import PackageReputation


def _signal(severity: Severity) -> Signal:
    return Signal(
        id=signal_id(SignalSource.RECON, "test", "x"),
        source=SignalSource.RECON,
        category="test",
        severity=severity,
        description="test signal",
        evidence=[Evidence(excerpt="x")],
    )


def test_established_package_skips_detonation():
    rep = PackageReputation(age_days=1000, downloads_last_month=1_000_000)
    decision = decide_detonation(rep, [])
    assert decision.should_detonate is False
    assert "established" in decision.reason


def test_new_package_always_detonates():
    rep = PackageReputation(age_days=1, downloads_last_month=1_000_000)
    decision = decide_detonation(rep, [])
    assert decision.should_detonate is True
    assert "too new" in decision.reason


def test_low_download_package_always_detonates():
    rep = PackageReputation(age_days=1000, downloads_last_month=5)
    decision = decide_detonation(rep, [])
    assert decision.should_detonate is True
    assert "too obscure" in decision.reason


def test_unknown_reputation_fails_open_to_detonating():
    rep = PackageReputation(age_days=None, downloads_last_month=None)
    decision = decide_detonation(rep, [])
    assert decision.should_detonate is True
    assert "reputation lookup failed" in decision.reason


def test_high_severity_recon_signal_always_detonates_even_if_established():
    rep = PackageReputation(age_days=1000, downloads_last_month=1_000_000)
    decision = decide_detonation(rep, [_signal(Severity.HIGH)])
    assert decision.should_detonate is True
    assert "already found" in decision.reason


def test_critical_severity_recon_signal_always_detonates():
    rep = PackageReputation(age_days=1000, downloads_last_month=1_000_000)
    decision = decide_detonation(rep, [_signal(Severity.CRITICAL)])
    assert decision.should_detonate is True


def test_low_severity_recon_signal_does_not_override_established_skip():
    rep = PackageReputation(age_days=1000, downloads_last_month=1_000_000)
    decision = decide_detonation(rep, [_signal(Severity.LOW)])
    assert decision.should_detonate is False


def test_custom_thresholds_respected():
    rep = PackageReputation(age_days=50, downloads_last_month=500)
    # With default thresholds (30 days, 1000 downloads) this would detonate
    # (downloads too low); with looser custom thresholds it should skip.
    decision = decide_detonation(rep, [], age_threshold_days=10, downloads_threshold=100)
    assert decision.should_detonate is False
