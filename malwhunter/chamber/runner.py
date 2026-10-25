"""Orchestrates the Detonation pass: runs a package's install lifecycle
scripts for real, inside a locked-down, single-use Docker container, with
outbound traffic routed through the Wiretap recording proxy and canary
tripwire env vars injected. Observes rather than trusts — nothing here
decides a package is malicious from reputation, only from what actually
happened during the run.

Network layout, per run:

    sandbox ──(sandbox net: --internal, gateway isolated)── wiretap ──(egress net)── internet

The sandbox's network has no route out and, in Docker's `isolated`
gateway mode, no host address on it either — the only thing the package
under analysis can reach is the Wiretap proxy container. The proxy alone
sits on a second, ordinary network to reach the internet, and refuses to
relay to any internal/private address (see wiretap/proxy.py).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.intake.manifest import get_lifecycle_scripts
from malwhunter.wiretap.canary import find_leaked_canaries, generate_canaries
from malwhunter.wiretap.proxy import CapturedBlocked, CapturedConnect, CapturedHttpRequest

_DOCKERFILE_DIR = Path(__file__).parent
_WIRETAP_DOCKERFILE_DIR = Path(__file__).parent.parent / "wiretap"


def _content_tag(repo: str, context_dir: Path, files: tuple[str, ...]) -> str:
    """Images are tagged by a hash of what they're built from, so a
    changed Dockerfile or proxy.py gets a new tag and is rebuilt on next
    use — with a fixed `:latest` tag, an image cached by an older version
    would silently keep running old sandbox/proxy code forever."""
    digest = hashlib.sha256()
    for name in files:
        digest.update(name.encode() + b"\0" + (context_dir / name).read_bytes())
    return f"{repo}:{digest.hexdigest()[:12]}"


CONTAINER_IMAGE = _content_tag("malwhunter-sandbox", _DOCKERFILE_DIR, ("Dockerfile",))
WIRETAP_IMAGE = _content_tag("malwhunter-wiretap", _WIRETAP_DOCKERFILE_DIR, ("Dockerfile", "proxy.py", "serve.py"))
CONTAINER_TIMEOUT_SECONDS = 30
# The sandbox's unprivileged user — node:20-slim ships a `node` user at
# uid/gid 1000, so install scripts never run as root inside the container.
CONTAINER_USER = "node"
# How the sandbox reaches the proxy: by network alias, resolved by Docker's
# embedded DNS on the sandbox network (which resolves nothing external).
WIRETAP_ALIAS = "wiretap"
WIRETAP_PORT = 8080
WIRETAP_READY_TIMEOUT_SECONDS = 15

# Destinations a legitimate install commonly needs — anything else is
# flagged as "unexpected," not "confirmed malicious": plenty of real
# packages fetch prebuilt binaries from CDNs we haven't listed. Applied to
# both HTTPS CONNECT tunnels and plain HTTP requests — a `curl|sh`
# postinstall dropper (one of the most common real malware patterns) uses
# plain HTTP as often as HTTPS, and both need the same check.
ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
}


class DetonationUnavailable(Exception):
    """Raised when the sandbox can't run at all — Docker missing/not
    running. Callers degrade (skip Detonation, keep Recon results) rather
    than crash the scan."""


def _docker_available() -> bool:
    try:
        # "docker" resolved via PATH, not attacker-influenced input; list form, no shell=True
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)  # nosec B603 B607
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _docker(*args: str, timeout: float = 15) -> subprocess.CompletedProcess:
    # "docker" resolved via PATH, not attacker-influenced input; list form, no shell=True
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout)  # nosec B603 B607


def _ensure_image(tag: str, context_dir: Path) -> None:
    if _docker("image", "inspect", tag, timeout=5).returncode == 0:
        return
    result = _docker("build", "-t", tag, str(context_dir), timeout=300)
    if result.returncode != 0:
        raise DetonationUnavailable(f"could not build {tag}: {result.stderr.decode(errors='replace')[-500:]}")


def _ensure_images() -> None:
    """Builds both images on first use; Docker caches them afterwards.
    The sandbox image (chamber/Dockerfile) exists because plain
    node:20-slim has no curl or wget, so a `curl | sh` dropper (a common
    real pattern) would silently no-op and produce a false-clean result.
    The Wiretap image (wiretap/Dockerfile) is the proxy itself."""
    _ensure_image(CONTAINER_IMAGE, _DOCKERFILE_DIR)
    _ensure_image(WIRETAP_IMAGE, _WIRETAP_DOCKERFILE_DIR)


class _SandboxNetworks:
    """The two single-use networks one Detonation run needs.

    `sandbox`: --internal (no route out) *and* gateway mode `isolated`
    (Docker 28+), which gives the host no address on the network at all.
    --internal alone still puts the host on the network at the gateway IP
    — found by live-testing: a service listening on the host's 0.0.0.0
    was reachable from inside the sandbox through it. Proxy env vars are
    only a request, not a boundary (Node's http/https/fetch, raw sockets
    and DNS all ignore them), so the network itself has to be.

    `egress`: an ordinary bridge network only the Wiretap proxy joins.
    """

    def __init__(self, run_id: str) -> None:
        self.sandbox = f"malwhunter-net-{run_id}"
        self.egress = f"malwhunter-egress-{run_id}"
        self._created: list[str] = []

    def create(self) -> None:
        result = _docker(
            "network", "create", "--internal",
            "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
            "-o", "com.docker.network.bridge.gateway_mode_ipv6=isolated",
            self.sandbox,
        )
        if result.returncode != 0:
            raise DetonationUnavailable(
                f"could not create isolated sandbox network (needs Docker 28+): "
                f"{result.stderr.decode(errors='replace')[-300:]}"
            )
        self._created.append(self.sandbox)

        # Verify rather than trust the option: an older daemon may accept
        # it and still give the host a gateway address on the network.
        inspect = _docker("network", "inspect", "-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}", self.sandbox)
        if inspect.returncode != 0 or inspect.stdout.decode(errors="replace").split():
            self.remove()
            raise DetonationUnavailable(
                "this Docker version doesn't support isolated gateway mode (needs Docker 28+) — "
                "the sandbox network would expose the host, so Detonation is refused"
            )

        result = _docker("network", "create", self.egress)
        if result.returncode != 0:
            self.remove()
            raise DetonationUnavailable(f"could not create egress network: {result.stderr.decode(errors='replace')[-300:]}")
        self._created.append(self.egress)

    def remove(self) -> None:
        for name in reversed(self._created):
            try:
                _docker("network", "rm", name)
            except (subprocess.TimeoutExpired, OSError):
                pass  # best-effort cleanup; a leftover empty network is inert
        self._created.clear()


def _force_remove_container(container_name: str) -> None:
    """`subprocess.run(timeout=...)` only kills the local `docker` client
    process — the container itself keeps running without it. `rm -f`
    kills and removes it synchronously, so nothing the package started
    outlives the Detonation run (or the proxy that was recording it)."""
    try:
        _docker("rm", "-f", container_name, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _make_writable_by_sandbox_user(root: Path) -> None:
    """The scratch copy is owned by whoever runs the scan, but install
    scripts run as the container's unprivileged user and often write
    into the package dir (build output, downloaded binaries). Opening up
    the copy's modes is safe: its parent is a mkdtemp 0700 dir, so no
    other host user can reach it — only the bind mount can."""
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o777)  # nosec B103
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if not os.path.islink(fpath):
                executable = os.stat(fpath).st_mode & 0o111
                os.chmod(fpath, 0o777 if executable else 0o666)  # nosec B103


@dataclass
class _Capture:
    """What the Wiretap container recorded — the same shape as an
    in-process WiretapProxy's lists, read back from its JSON-lines log."""

    http_requests: list[CapturedHttpRequest] = field(default_factory=list)
    connects: list[CapturedConnect] = field(default_factory=list)
    blocked: list[CapturedBlocked] = field(default_factory=list)


def _read_capture(log_path: Path) -> _Capture:
    capture = _Capture()
    if not log_path.exists():
        return capture
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
            kind = event.pop("kind")
            if kind == "http":
                event["body"] = base64.b64decode(event.get("body") or "")
                capture.http_requests.append(CapturedHttpRequest(**event))
            elif kind == "connect":
                capture.connects.append(CapturedConnect(**event))
            elif kind == "blocked":
                capture.blocked.append(CapturedBlocked(**event))
        except (ValueError, KeyError, TypeError):
            continue  # a line cut short by the container being killed mid-write
    return capture


class _Wiretap:
    """The proxy container for one run: on the egress network for the
    internet, and on the sandbox network under the `wiretap` alias."""

    def __init__(self, run_id: str, capture_dir: Path) -> None:
        self.name = f"malwhunter-wiretap-{run_id}"
        self.capture_dir = capture_dir

    def start(self, networks: _SandboxNetworks) -> None:
        result = _docker(
            "run", "-d", "--name", self.name,
            "--network", networks.egress,
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=128m", "--cpus=1",
            # runs as the scanning user, so it can write the capture log
            # into our own mkdtemp dir without opening up its permissions
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{self.capture_dir}:/out",
            WIRETAP_IMAGE, "--port", str(WIRETAP_PORT), "--out", "/out",
        )
        if result.returncode != 0:
            raise DetonationUnavailable(f"could not start the Wiretap proxy: {result.stderr.decode(errors='replace')[-300:]}")
        result = _docker("network", "connect", "--alias", WIRETAP_ALIAS, networks.sandbox, self.name)
        if result.returncode != 0:
            raise DetonationUnavailable(f"could not attach the Wiretap proxy: {result.stderr.decode(errors='replace')[-300:]}")

        deadline = time.monotonic() + WIRETAP_READY_TIMEOUT_SECONDS
        while not (self.capture_dir / "ready").exists():
            if time.monotonic() > deadline:
                logs = _docker("logs", "--tail", "20", self.name)
                raise DetonationUnavailable(
                    f"Wiretap proxy didn't become ready: {logs.stderr.decode(errors='replace')[-300:]}"
                )
            time.sleep(0.1)

    def stop(self) -> None:
        _force_remove_container(self.name)

    def capture(self) -> _Capture:
        return _read_capture(self.capture_dir / "capture.jsonl")


def _build_docker_command(
    scratch_path: Path,
    canaries: dict[str, str],
    script_chain: str,
    *,
    network: str,
    container_name: str,
) -> list[str]:
    proxy_url = f"http://{WIRETAP_ALIAS}:{WIRETAP_PORT}"
    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--network", network,
        # Both cases, deliberately: curl only honors lowercase http_proxy
        # for plain http:// requests (its documented httpoxy-related
        # behavior — HTTP_PROXY uppercase is ignored on purpose), while
        # other tools expect uppercase. Found by live-testing a real
        # curl|sh dropper against this sandbox and getting zero signals
        # because curl was silently bypassing the proxy entirely.
        "-e", f"HTTP_PROXY={proxy_url}",
        "-e", f"http_proxy={proxy_url}",
        "-e", f"HTTPS_PROXY={proxy_url}",
        "-e", f"https_proxy={proxy_url}",
    ]
    for key, value in canaries.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [
        # path *inside* the container, not a host temp dir
        "--read-only", "--tmpfs", "/tmp",  # nosec B108
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=128", "--memory=256m", "--cpus=1",
        "--user", CONTAINER_USER,
        # the image's real HOME is on the read-only root fs; npm and
        # friends need somewhere writable for caches and config
        "-e", "HOME=/tmp",
        "-v", f"{scratch_path}:/pkg",
        "-w", "/pkg",
        CONTAINER_IMAGE,
        "sh", "-c", script_chain,
    ]
    return cmd


def detonate_package(name: str, version: str, package_dir: Path, package_json: dict) -> list[Signal]:
    scripts = get_lifecycle_scripts(package_json)
    if not scripts:
        return []

    if not _docker_available():
        raise DetonationUnavailable("Docker daemon is not reachable (is Docker running?)")
    _ensure_images()

    canaries = generate_canaries()
    run_id = secrets.token_hex(6)
    container_name = f"malwhunter-chamber-{run_id}"
    script_chain = " && ".join(
        f"({scripts[step]})" for step in ("preinstall", "install", "postinstall") if step in scripts
    )

    networks = _SandboxNetworks(run_id)
    networks.create()
    try:
        with tempfile.TemporaryDirectory(prefix="malwhunter-chamber-") as scratch:
            capture_dir = Path(scratch) / "capture"
            capture_dir.mkdir()
            wiretap = _Wiretap(run_id, capture_dir)
            try:
                wiretap.start(networks)
                scratch_path = Path(scratch) / "pkg"
                shutil.copytree(package_dir, scratch_path, symlinks=True)
                _make_writable_by_sandbox_user(scratch_path)

                docker_cmd = _build_docker_command(
                    scratch_path, canaries, script_chain, network=networks.sandbox, container_name=container_name
                )
                try:
                    # list form, no shell=True; args are our own flags plus a scratch copy of the
                    # package under analysis — this *is* the sandboxed execution the tool exists to do
                    subprocess.run(docker_cmd, capture_output=True, timeout=CONTAINER_TIMEOUT_SECONDS)  # nosec B603
                except subprocess.TimeoutExpired:
                    pass  # a slow install isn't itself a signal — only what it did during that time is
                finally:
                    # always, not only on timeout: if anything interrupted the
                    # run, the container must not be left running unobserved
                    _force_remove_container(container_name)
            finally:
                wiretap.stop()
            capture = wiretap.capture()
    finally:
        networks.remove()

    return _signals_from_capture(name, capture, canaries)


def _signals_from_capture(name: str, proxy: _Capture, canaries: dict[str, str]) -> list[Signal]:
    signals: list[Signal] = []

    for req in proxy.http_requests:
        haystack = req.url + " " + " ".join(req.headers.values()) + " " + req.body.decode("utf-8", errors="replace")
        leaked = find_leaked_canaries(haystack, canaries)
        if leaked:
            signals.append(
                Signal(
                    id=signal_id(SignalSource.DETONATION, "canary-exfiltration", f"{name}:{req.host}:{req.url}"),
                    source=SignalSource.DETONATION,
                    category="canary-exfiltration",
                    severity=Severity.CRITICAL,
                    description=(
                        f"install script sent a tripwire secret ({', '.join(leaked)}) to {req.host} — "
                        "nothing legitimate had any reason to know this value"
                    ),
                    evidence=[Evidence(excerpt=f"{req.method} {req.url}", detail=f"destination={req.host}")],
                )
            )

        req_host = req.host.rpartition(":")[0] or req.host  # strip ":port" if present
        if req_host and req_host not in ALLOWED_HOSTS:
            signals.append(
                Signal(
                    id=signal_id(SignalSource.DETONATION, "unexpected-network-destination", f"{name}:{req_host}:{req.url}"),
                    source=SignalSource.DETONATION,
                    category="unexpected-network-destination",
                    severity=Severity.MEDIUM,
                    description=f"install script made a plain-HTTP request to an unrecognized host: {req_host}",
                    evidence=[Evidence(excerpt=f"{req.method} {req.url}", detail=f"destination={req_host}")],
                )
            )

    for connect in proxy.connects:
        if connect.host not in ALLOWED_HOSTS:
            signals.append(
                Signal(
                    id=signal_id(
                        SignalSource.DETONATION,
                        "unexpected-network-destination",
                        f"{name}:{connect.host}:{connect.port}",
                    ),
                    source=SignalSource.DETONATION,
                    category="unexpected-network-destination",
                    severity=Severity.MEDIUM,
                    description=f"install script connected to an unrecognized host: {connect.host}:{connect.port}",
                    evidence=[
                        Evidence(
                            excerpt=f"CONNECT {connect.host}:{connect.port}",
                            detail="HTTPS — contents not inspected in v1",
                        )
                    ],
                )
            )

    # The proxy refused these, so nothing was reached — but an install
    # script reaching for localhost, the LAN, or the cloud metadata
    # endpoint is probing for something it has no business touching.
    for blocked in proxy.blocked:
        signals.append(
            Signal(
                id=signal_id(SignalSource.DETONATION, "internal-network-probe", f"{name}:{blocked.host}:{blocked.port}"),
                source=SignalSource.DETONATION,
                category="internal-network-probe",
                severity=Severity.HIGH,
                description=(
                    f"install script tried to reach an internal or non-public address through the sandbox proxy: "
                    f"{blocked.host}:{blocked.port} (resolves to {blocked.address}) — refused"
                ),
                evidence=[Evidence(excerpt=f"{blocked.host}:{blocked.port}", detail=f"resolved={blocked.address}")],
            )
        )

    return signals
