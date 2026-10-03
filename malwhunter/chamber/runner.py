"""Orchestrates the Detonation pass: runs a package's install lifecycle
scripts for real, inside a locked-down, single-use Docker container, with
outbound traffic routed through the Wiretap recording proxy and canary
tripwire env vars injected. Observes rather than trusts — nothing here
decides a package is malicious from reputation, only from what actually
happened during the run.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.intake.manifest import get_lifecycle_scripts
from malwhunter.wiretap.canary import find_leaked_canaries, generate_canaries
from malwhunter.wiretap.proxy import WiretapProxy

CONTAINER_IMAGE = "malwhunter-sandbox:latest"
CONTAINER_TIMEOUT_SECONDS = 30
_DOCKERFILE_DIR = Path(__file__).parent

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
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _sandbox_image_exists() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", CONTAINER_IMAGE], capture_output=True, timeout=5
    )
    return result.returncode == 0


def _ensure_sandbox_image() -> None:
    """Builds the sandbox image from chamber/Dockerfile on first use —
    plain node:20-slim doesn't include curl or wget, so a package that
    droppers malware via `curl | sh` (a common real pattern) would
    silently no-op inside it and produce a false-clean result. Docker
    caches the build, so this is a no-op after the first run."""
    if _sandbox_image_exists():
        return
    result = subprocess.run(
        ["docker", "build", "-t", CONTAINER_IMAGE, str(_DOCKERFILE_DIR)],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise DetonationUnavailable(
            f"could not build the sandbox image: {result.stderr.decode(errors='replace')[-500:]}"
        )


class _ProxyThread:
    """Runs the asyncio WiretapProxy on a background thread with its own
    event loop, so it can sit alongside the CLI's synchronous click
    commands without restructuring the whole CLI as async."""

    def __init__(self) -> None:
        self.proxy = WiretapProxy()
        self.port: int | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self) -> int:
        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            self.port = loop.run_until_complete(self.proxy.start())
            self._ready.set()
            loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)
        assert self.port is not None
        return self.port

    def stop(self) -> None:
        if self._loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.proxy.stop(), self._loop).result(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)


def _build_docker_command(
    scratch_path: Path, proxy_port: int, canaries: dict[str, str], script_chain: str
) -> list[str]:
    proxy_url = f"http://host.docker.internal:{proxy_port}"
    cmd = [
        "docker", "run", "--rm",
        "--add-host=host.docker.internal:host-gateway",
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
        "--read-only", "--tmpfs", "/tmp",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=128", "--memory=256m", "--cpus=1",
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
        raise DetonationUnavailable("Docker daemon is not reachable (is Docker Desktop running?)")
    _ensure_sandbox_image()

    canaries = generate_canaries()
    proxy_thread = _ProxyThread()
    proxy_port = proxy_thread.start()

    script_chain = " && ".join(
        f"({scripts[step]})" for step in ("preinstall", "install", "postinstall") if step in scripts
    )

    with tempfile.TemporaryDirectory(prefix="malwhunter-chamber-") as scratch:
        scratch_path = Path(scratch) / "pkg"
        shutil.copytree(package_dir, scratch_path)

        docker_cmd = _build_docker_command(scratch_path, proxy_port, canaries, script_chain)
        try:
            subprocess.run(docker_cmd, capture_output=True, timeout=CONTAINER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            pass  # a slow install isn't itself a signal — only what it did during that time is
        finally:
            proxy_thread.stop()

    return _signals_from_capture(name, proxy_thread.proxy, canaries)


def _signals_from_capture(name: str, proxy: WiretapProxy, canaries: dict[str, str]) -> list[Signal]:
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

    return signals
