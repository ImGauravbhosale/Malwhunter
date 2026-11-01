"""Runtime tracing of a detonated package: what the install scripts did to the
machine, not only what they sent over the network.

Inside the sandbox the scripts run under `strace -f`, logging process
launches, file opens, renames/deletes and socket connects. This module reads
that log back and turns it into Signals plus a plain-data summary. It sees
what the proxy cannot:

* a script reading `~/.ssh`, cloud credential files, browser or wallet data;
* a script writing itself into shell startup files, cron or `authorized_keys`
  (persistence);
* a connection that bypasses the proxy (raw sockets, a tool that ignores the
  proxy settings): the sandbox network has no route out, so it fails, but the
  attempt is evidence of intent that no proxy log would ever contain;
* the processes that were started, which shows a `curl | sh` chain end to end.

The log is written by `strace` inside the container as the same user as the
package, so a hostile script could delete or truncate it. A normal run always
has the opening `execve` records; a log that is missing or has none is itself
reported (`trace-interference`) rather than read as "nothing happened".
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.report.sanitize import sanitize_text

TRACE_DIR_IN_CONTAINER = "/trace"
TRACE_FILE = "trace.log"
UNAVAILABLE_MARKER = "unavailable"  # written by the wrapper when strace can't run here
_MAX_TRACE_BYTES = 20 * 1024 * 1024
_MAX_LISTED = 40

_PROBE_TOOLS = frozenset({"lsb_release", "uname", "getconf", "ldconfig"})
SYSCALL_FILTER = "execve,connect,openat,openat2,unlink,unlinkat,rename,renameat,renameat2"

# The wrapper the sandbox runs. It probes with the *same* filter first: if
# strace can't trace here (ptrace blocked by the host's seccomp/Yama policy),
# the script still runs, untraced, and the summary says so, instead of the
# whole run silently doing nothing.
WRAPPER = (
    f"if strace -f -qq -o /dev/null -e trace={SYSCALL_FILTER} true >/dev/null 2>&1; then "
    f"exec strace -f -qq -s 256 -o {TRACE_DIR_IN_CONTAINER}/{TRACE_FILE} -e trace={SYSCALL_FILTER} "
    '-- sh -c "$MH_SCRIPT"; '
    f"else : > {TRACE_DIR_IN_CONTAINER}/{UNAVAILABLE_MARKER}; exec sh -c \"$MH_SCRIPT\"; fi"
)

# Credential and secret stores a dependency has no business opening.
_CREDENTIAL_PATHS = re.compile(
    r"/\.ssh/|/\.aws/|/\.azure/|/\.config/gcloud|/\.kube/|/\.docker/config\.json|/\.git-credentials|/\.netrc\b|"
    r"/etc/shadow|/\.gnupg/|/\.password-store|/\.config/(?:google-chrome|chromium|BraveSoftware)/|"
    r"/\.mozilla/firefox/|/Login Data|/Cookies$|/wallet\.dat|/\.ethereum/keystore|/\.bitcoin/|/\.config/solana|"
    r"/\.electrum/|/Local Storage/leveldb|/\.config/Exodus|/\.config/gh/hosts\.yml|/\.pypirc|/\.terraform\.d/credentials",
    re.IGNORECASE,
)
_DOCKER_SOCKET = re.compile(r"/docker\.sock|/containerd\.sock|/podman\.sock")
_OTHER_PROCESS_ENV = re.compile(r"^/proc/(?!self/|thread-self/)\d+/(?:environ|cmdline|mem)$")
_HISTORY_FILES = re.compile(r"/\.(?:bash|zsh|python|node_repl)_history$|/\.psql_history$|/\.mysql_history$")
# Writing here makes code run again later: shell startup, cron, SSH access, services.
_PERSISTENCE_PATHS = re.compile(
    r"/\.(?:bashrc|bash_profile|profile|zshrc|zprofile|zshenv)$|/\.ssh/authorized_keys2?$|"
    r"^/etc/(?:cron|crontab|rc\.local|profile|bash\.bashrc|ld\.so\.preload|sudoers)|/var/spool/cron|"
    r"/\.config/(?:systemd/user|autostart)/|/\.config/fish/config\.fish$|^/etc/systemd/",
    re.IGNORECASE,
)
_WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC")

_LINE = re.compile(r"^(?:\[pid\s+)?(?P<pid>\d+)\]?\s+(?P<call>\w+)\((?P<args>.*)$")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_INET = re.compile(r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\).*?(?:inet_addr|inet_pton\(AF_INET6,)\s*\(?"([^"]+)"')
_UNIX = re.compile(r'sa_family=AF_UNIX, sun_path="([^"]*)"')


@dataclass
class Trace:
    available: bool = False  # strace actually ran and produced a log
    interference: bool = False  # the log is missing or empty although strace was running
    processes: list[str] = field(default_factory=list)
    files_of_interest: list[str] = field(default_factory=list)
    direct_connects: list[str] = field(default_factory=list)
    events: int = 0
    signals: list[Signal] = field(default_factory=list)


def _signal(name: str, category: str, severity: Severity, description: str, line: str, detail: str) -> Signal:
    return Signal(
        id=signal_id(SignalSource.DETONATION, category, f"{name}:{detail}"),
        source=SignalSource.DETONATION,
        category=category,
        severity=severity,
        description=description,
        evidence=[Evidence(excerpt=sanitize_text(line.strip())[:300], detail=sanitize_text(detail)[:200])],
    )


def parse_trace(
    name: str,
    trace_dir: Path,
    *,
    proxy_port: int,
    tracing_expected: bool = True,
) -> Trace:
    """Reads the log the sandbox wrote. `tracing_expected` is False when the
    run was started without a tracer (so a missing log means nothing)."""
    trace = Trace()
    if not tracing_expected:
        return trace
    if (trace_dir / UNAVAILABLE_MARKER).exists():
        return trace  # strace could not run on this host: reported as "tracing unavailable", not as clean

    path = trace_dir / TRACE_FILE
    try:
        raw = path.read_bytes()[:_MAX_TRACE_BYTES]
    except OSError:
        raw = b""
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not any(ln for ln in lines if " execve(" in ln):
        # strace always logs the wrapper's own execve first; none means the log was removed or emptied
        trace.interference = True
        trace.signals.append(
            _signal(
                name, "trace-interference", Severity.MEDIUM,
                "the runtime trace of this install is missing or empty — a script that deletes or truncates its "
                "own trace is hiding what it did",
                "(no trace records)", "trace-missing",
            )
        )
        return trace

    trace.available = True
    seen: set[tuple[str, str]] = set()
    exe_by_pid: dict[str, str] = {}

    def once(category: str, key: str) -> bool:
        if (category, key) in seen:
            return False
        seen.add((category, key))
        return True

    for line in lines:
        m = _LINE.match(line)
        if not m:
            continue
        trace.events += 1
        pid, call, args = m.group("pid"), m.group("call"), m.group("args")

        if call == "execve":
            strings = _QUOTED.findall(args)
            if strings and strings[0].rsplit("/", 1)[-1] in _PROBE_TOOLS:
                continue  # pip asking the OS what it is: not something the package did
            if strings:
                exe_by_pid[pid] = strings[0]
                command = " ".join(strings[1:])[:200] or strings[0]
                entry = sanitize_text(f"{strings[0]}: {command}" if command != strings[0] else strings[0])[:110]
                if entry not in trace.processes and len(trace.processes) < _MAX_LISTED:
                    trace.processes.append(entry)
            continue

        if call in ("openat", "openat2", "unlink", "unlinkat", "rename", "renameat", "renameat2"):
            paths = _QUOTED.findall(args)
            if not paths:
                continue
            target = paths[0]
            writing = bool(_WRITE_FLAGS.search(args)) and call in ("openat", "openat2")
            if target.startswith(TRACE_DIR_IN_CONTAINER) and call != "openat":
                if once("trace-interference", target):
                    trace.signals.append(
                        _signal(name, "trace-interference", Severity.MEDIUM,
                                "an install script tried to remove or rename the runtime trace", line, target)
                    )
                continue
            if _PERSISTENCE_PATHS.search(target) and (writing or call != "openat"):
                if once("persistence-attempt", target):
                    trace.files_of_interest.append(f"write {target}")
                    trace.signals.append(
                        _signal(name, "persistence-attempt", Severity.HIGH,
                                f"install script modified a file that makes code run later: {target}", line, target)
                    )
                continue
            if _CREDENTIAL_PATHS.search(target) or _DOCKER_SOCKET.search(target):
                if once("sensitive-file-access", target):
                    trace.files_of_interest.append(f"open {target}")
                    trace.signals.append(
                        _signal(name, "sensitive-file-access", Severity.HIGH,
                                f"install script tried to open a credential or secret store: {target}", line, target)
                    )
            elif _OTHER_PROCESS_ENV.match(target) or _HISTORY_FILES.search(target):
                if once("sensitive-file-access", target):
                    trace.files_of_interest.append(f"open {target}")
                    trace.signals.append(
                        _signal(name, "sensitive-file-access", Severity.MEDIUM,
                                f"install script read data about the user or other processes: {target}", line, target)
                    )
            continue

        if call == "connect":
            unix = _UNIX.search(args)
            if unix:
                sock = unix.group(1)
                if _DOCKER_SOCKET.search(sock) and once("sensitive-file-access", sock):
                    trace.files_of_interest.append(f"connect {sock}")
                    trace.signals.append(
                        _signal(name, "sensitive-file-access", Severity.HIGH,
                                f"install script tried to reach the container runtime socket: {sock}", line, sock)
                    )
                continue
            inet = _INET.search(args)
            if not inet:
                continue
            port, address = int(inet.group(1)), inet.group(2)
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if (port == proxy_port and ip.is_private) or ip.is_loopback or ip.is_unspecified:
                continue  # the proxy itself, Docker's embedded DNS (127.0.0.11), loopback
            destination = f"{address}:{port}"
            if destination not in trace.direct_connects and len(trace.direct_connects) < _MAX_LISTED:
                trace.direct_connects.append(destination)
            if once("proxy-bypass-attempt", destination):
                trace.signals.append(
                    _signal(name, "proxy-bypass-attempt", Severity.MEDIUM,
                            f"install script tried to open a direct connection to {destination}, bypassing the "
                            "recording proxy (the sandbox has no route out, so it failed)", line, destination)
                )
    return trace
