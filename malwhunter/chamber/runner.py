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

from malwhunter.chamber.trace import TRACE_DIR_IN_CONTAINER, WRAPPER, Trace, parse_trace
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.intake.manifest import get_lifecycle_scripts
from malwhunter.report.sanitize import sanitize_text
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
PYTHON_IMAGE = _content_tag("malwhunter-sandbox-py", _DOCKERFILE_DIR, ("Dockerfile.python",))
WIRETAP_IMAGE = _content_tag("malwhunter-wiretap", _WIRETAP_DOCKERFILE_DIR, ("Dockerfile", "proxy.py", "serve.py", "tls_intercept.py"))
CONTAINER_TIMEOUT_SECONDS = 30
# pip has to download its build backend through the proxy before it builds anything
PYTHON_TIMEOUT_SECONDS = 120
# The sandbox's unprivileged user — node:20-slim ships a `node` user at
# uid/gid 1000, so install scripts never run as root inside the container.
CONTAINER_USER = "node"
# How the sandbox reaches the proxy: by network alias, resolved by Docker's
# embedded DNS on the sandbox network (which resolves nothing external).
WIRETAP_ALIAS = "wiretap"
WIRETAP_PORT = 8080
WIRETAP_READY_TIMEOUT_SECONDS = 15
CA_MOUNT_PATH = "/etc/malwhunter/ca.pem"

# Destinations a legitimate install commonly needs — anything else is
# flagged as "unexpected," not "confirmed malicious": plenty of real
# packages fetch prebuilt binaries from CDNs we haven't listed. Applied to
# both HTTPS CONNECT tunnels and plain HTTP requests — a `curl|sh`
# postinstall dropper (one of the most common real malware patterns) uses
# plain HTTP as often as HTTPS, and both need the same check.
ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "nodejs.org",  # node-gyp fetches Node headers from here
    "github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
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


def _ensure_image(tag: str, context_dir: Path, dockerfile: str | None = None) -> None:
    if _docker("image", "inspect", tag, timeout=5).returncode == 0:
        return
    extra = ["-f", str(context_dir / dockerfile)] if dockerfile else []
    result = _docker("build", "-t", tag, *extra, str(context_dir), timeout=300)
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


def _ensure_python_image() -> None:
    _ensure_image(PYTHON_IMAGE, _DOCKERFILE_DIR, "Dockerfile.python")


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


def _reclaim_scratch(scratch: Path, image: str) -> None:
    """Hands the scratch directory back to the user running the scan.

    Whatever the install scripts create (a build folder, an `.egg-info`, a
    deliberately private directory) is owned by the sandbox user's uid. When
    that is not the uid running the scan (CI runners, other machines, any
    account that is not uid 1000) the scan user cannot delete it, and the
    cleanup that follows would raise, losing the whole result. A hostile
    package could use that on purpose.

    So a throwaway container, run as root with only the two capabilities
    needed (override ownership and read/write permissions), opens up the
    permissions of everything under the scratch directory. It touches only
    regular files and directories (`find -type`, never following symlinks),
    has no network, and mounts nothing but the scratch directory."""
    try:
        _docker(
            "run", "--rm", "--network", "none", "--user", "root", "--read-only",
            "--cap-drop=ALL", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE", "--security-opt=no-new-privileges",
            "--pids-limit=32", "--memory=128m",
            "-v", f"{scratch}:/scratch",
            image,
            "sh", "-c",
            "find /scratch -xdev -type d -exec chmod a+rwx {} + ; find /scratch -xdev -type f -exec chmod a+rw {} +",
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass  # best effort: the cleanup below tolerates what is left


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

    def __init__(self, run_id: str, capture_dir: Path, *, tls_inspect: bool = True) -> None:
        self.name = f"malwhunter-wiretap-{run_id}"
        self.capture_dir = capture_dir
        self.tls_inspect = tls_inspect

    @property
    def ca_path(self) -> Path | None:
        """The per-run CA certificate, when the proxy is reading HTTPS."""
        path = self.capture_dir / "ca.pem"
        return path if self.tls_inspect and path.exists() else None

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
            # the proxy writes each host's certificate to a temp file to load it
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",  # nosec B108
            WIRETAP_IMAGE, "--port", str(WIRETAP_PORT), "--out", "/out",
            *(["--tls-inspect"] if self.tls_inspect else []),
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
    ca_path: Path | None = None,
    trace_dir: Path | None = None,
    image: str = CONTAINER_IMAGE,
    user: str = CONTAINER_USER,
    extra_env: dict[str, str] | None = None,
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
        # Node's http/https/fetch ignore the proxy variables unless told to
        # (v22.21+ / v24+). Without this a Node script's traffic bypasses the
        # recording proxy entirely and the run looks clean.
        "-e", "NODE_USE_ENV_PROXY=1",
    ]
    for key, value in canaries.items():
        cmd += ["-e", f"{key}={value}"]
    if ca_path is not None:
        # The sandbox trusts the proxy's per-run CA *certificate* (never its
        # key), so its HTTPS tools accept the proxy and the proxy can read
        # what they send. Every tool family has its own variable.
        for var in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
                    "GIT_SSL_CAINFO", "npm_config_cafile"):
            cmd += ["-e", f"{var}={CA_MOUNT_PATH}"]
        cmd += ["-e", f"PIP_CERT={CA_MOUNT_PATH}"]
    for key, value in (extra_env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    if trace_dir is not None:
        # the install runs under strace; its log lands in this mounted directory
        cmd += ["-e", f"MH_SCRIPT={script_chain}"]
    cmd += [
        # path *inside* the container, not a host temp dir
        "--read-only", "--tmpfs", "/tmp",  # nosec B108
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=128", "--memory=256m", "--cpus=1",
        "--user", user,
        # the image's real HOME is on the read-only root fs; npm and
        # friends need somewhere writable for caches and config
        "-e", "HOME=/tmp",
        "-v", f"{scratch_path}:/pkg",
        *(["-v", f"{ca_path}:{CA_MOUNT_PATH}:ro"] if ca_path is not None else []),
        *(["-v", f"{trace_dir}:{TRACE_DIR_IN_CONTAINER}"] if trace_dir is not None else []),
        "-w", "/pkg",
        image,
        "sh", "-c", WRAPPER if trace_dir is not None else script_chain,
    ]
    return cmd


_OUTPUT_TAIL_CHARS = 2000


def _tail(data: bytes | str | None) -> str:
    """The last bit of a script's output, made safe to print: the package
    under analysis controls every byte of it."""
    if data is None:
        return ""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return sanitize_text(text[-_OUTPUT_TAIL_CHARS:])


def _tracing_summary(trace: Trace | None, requested: bool) -> dict:
    if not requested:
        return {"enabled": False, "note": "runtime tracing was switched off for this run"}
    if trace is None or not (trace.available or trace.interference):
        return {"enabled": False, "note": "runtime tracing was unavailable on this host (the script ran untraced)"}
    return {
        "enabled": trace.available,
        "interference": trace.interference,
        "events": trace.events,
        "processes": trace.processes,
        "sensitive_or_persistent_files": trace.files_of_interest,
        "direct_connection_attempts": trace.direct_connects,
    }


def _summarize_run(
    scripts: dict[str, str],
    canaries: dict[str, str],
    capture: _Capture,
    *,
    exit_code: int | None,
    timed_out: bool,
    seconds: float,
    stdout: bytes | str | None,
    stderr: bytes | str | None,
    tls_inspected: bool = False,
    trace: Trace | None = None,
    tracing_requested: bool = False,
    time_limit: int = CONTAINER_TIMEOUT_SECONDS,
) -> dict:
    """A plain-data record of what the run observed — including the benign
    parts — so a reader can see what happened, not only what was flagged."""
    leaked: set[str] = set()
    for req in capture.http_requests:
        haystack = req.url + " " + " ".join(req.headers.values()) + " " + req.body.decode("utf-8", errors="replace")
        leaked.update(find_leaked_canaries(haystack, canaries))

    def _split(hosts: list[str]) -> dict[str, list[str]]:
        unique = sorted(set(hosts))
        return {
            "expected": [h for h in unique if h in ALLOWED_HOSTS],
            "unexpected": [h for h in unique if h not in ALLOWED_HOSTS],
        }

    plain = [r for r in capture.http_requests if getattr(r, "scheme", "http") == "http"]
    encrypted = [r for r in capture.http_requests if getattr(r, "scheme", "http") == "https"]
    http_hosts = [r.host.rpartition(":")[0] or r.host for r in plain if r.host]
    return {
        "scripts_run": (
            {**scripts, "import": "import the package's top-level modules (runs its __init__)"}
            if "pip install" in scripts
            else {step: scripts[step] for step in ("preinstall", "install", "postinstall") if step in scripts}
        ),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "seconds": round(seconds, 1),
        "time_limit_seconds": time_limit,
        "plain_http_requests": len(plain),
        "https_requests_inspected": len(encrypted),
        "tls_inspected": tls_inspected,
        "plain_http_hosts": _split(http_hosts),
        "https_hosts": _split([c.host for c in capture.connects]),
        "blocked_internal_attempts": [f"{b.host}:{b.port}" for b in capture.blocked],
        "tracing": _tracing_summary(trace, tracing_requested),
        "canaries_planted": sorted(canaries),
        "canaries_leaked": sorted(leaked),
        "stdout_tail": _tail(stdout),
        "stderr_tail": _tail(stderr),
        "limits": [
            (
                "HTTPS requests are read through a per-run proxy certificate; a tool that pins certificates "
                "or ignores the sandbox's CA settings fails its handshake and is seen only as a connection attempt"
                if tls_inspected
                else "HTTPS request contents are not inspected — only the destination host"
            ),
            f"observation window is {time_limit}s; later behaviour is not seen",
            (
                "only the package's own install and first import are run, not code that runs when it is used later"
                if "pip install" in scripts
                else "only preinstall/install/postinstall scripts are run, not code loaded at require() time"
            ),
            "the runtime trace is written by a tool running as the same user as the package, so it is "
            "best-effort evidence, not tamper-proof",
        ],
    }


def detonate_package(
    name: str,
    version: str,
    package_dir: Path,
    package_json: dict,
    *,
    summary: dict | None = None,
    tls_inspect: bool = True,
    trace: bool = True,
) -> list[Signal]:
    """Runs an npm package's install scripts in the sandbox and returns the
    Signals it produced. When `summary` is given it is filled in-place with
    a plain-data record of what the run observed (see `_summarize_run`)."""
    scripts = get_lifecycle_scripts(package_json)
    if not scripts:
        return []
    script_chain = " && ".join(
        f"({scripts[step]})" for step in ("preinstall", "install", "postinstall") if step in scripts
    )
    return _run_detonation(
        name, scripts, script_chain, package_dir,
        summary=summary, tls_inspect=tls_inspect, trace=trace,
    )


def python_install_commands(name: str, install_target: str) -> dict[str, str]:
    """What a user's `pip install` and first `import` would run, as the two
    steps the sandbox executes: build/install (setup.py, build backend, .pth
    files), then import the package's top-level modules (runs `__init__`)."""
    import shlex

    imports = (
        "import importlib, importlib.metadata as m\n"
        "try:\n"
        f"    mods = (m.distribution({name!r}).read_text('top_level.txt') or '').split()[:3]\n"
        "except Exception:\n"
        "    mods = []\n"
        "for t in mods:\n"
        "    try:\n"
        "        importlib.import_module(t)\n"
        "    except BaseException as e:\n"
        "        print('import', t, 'failed:', type(e).__name__)\n"
    )
    return {
        "pip install": f"pip install --no-deps --no-cache-dir --disable-pip-version-check --user {shlex.quote(install_target)}",
        "import": f"python -c {shlex.quote(imports)}",
    }


def detonate_pypi_package(
    name: str,
    version: str,
    install_dir: Path,
    install_target: str,
    *,
    summary: dict | None = None,
    tls_inspect: bool = True,
    trace: bool = True,
) -> list[Signal]:
    """Installs a PyPI release with pip inside the sandbox and imports it.
    `install_dir` is mounted at /pkg; `install_target` is what pip is given,
    relative to /pkg (the source tree itself, or a wheel file inside it)."""
    commands = python_install_commands(name, f"/pkg/{install_target}".rstrip("/"))
    # `;` not `&&`: a failed build must not stop the import step from running what did get installed
    script_chain = "; ".join(commands.values())
    return _run_detonation(
        name, commands, script_chain, install_dir,
        summary=summary, tls_inspect=tls_inspect, trace=trace,
        image=PYTHON_IMAGE, user="sandbox", timeout=PYTHON_TIMEOUT_SECONDS, python=True,
    )


def _run_detonation(
    name: str,
    scripts: dict[str, str],
    script_chain: str,
    package_dir: Path,
    *,
    summary: dict | None,
    tls_inspect: bool,
    trace: bool,
    image: str = CONTAINER_IMAGE,
    user: str = CONTAINER_USER,
    timeout: int = CONTAINER_TIMEOUT_SECONDS,
    python: bool = False,
) -> list[Signal]:
    if not _docker_available():
        raise DetonationUnavailable("Docker daemon is not reachable (is Docker running?)")
    _ensure_images()
    if python:
        _ensure_python_image()

    canaries = generate_canaries()
    run_id = secrets.token_hex(6)
    container_name = f"malwhunter-chamber-{run_id}"
    exit_code: int | None = None
    timed_out = False
    stdout: bytes | str | None = None
    stderr: bytes | str | None = None
    started = time.monotonic()
    tls_inspected = False
    trace_result: Trace | None = None

    networks = _SandboxNetworks(run_id)
    networks.create()
    try:
        with tempfile.TemporaryDirectory(prefix="malwhunter-chamber-", ignore_cleanup_errors=True) as scratch:
            capture_dir = Path(scratch) / "capture"
            capture_dir.mkdir()
            wiretap = _Wiretap(run_id, capture_dir, tls_inspect=tls_inspect)
            try:
                wiretap.start(networks)
                scratch_path = Path(scratch) / "pkg"
                shutil.copytree(package_dir, scratch_path, symlinks=True)
                _make_writable_by_sandbox_user(scratch_path)
                trace_dir: Path | None = None
                if trace:
                    trace_dir = Path(scratch) / "trace"
                    trace_dir.mkdir()
                    # the sandbox user must be able to write the log; its parent is a private mkdtemp dir
                    os.chmod(trace_dir, 0o777)  # nosec B103

                docker_cmd = _build_docker_command(
                    scratch_path, canaries, script_chain, network=networks.sandbox, container_name=container_name,
                    ca_path=wiretap.ca_path, trace_dir=trace_dir,
                    image=image, user=user,
                    extra_env={"PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"} if python else None,
                )
                try:
                    # list form, no shell=True; args are our own flags plus a scratch copy of the
                    # package under analysis — this *is* the sandboxed execution the tool exists to do
                    completed = subprocess.run(docker_cmd, capture_output=True, timeout=timeout)  # nosec B603
                    exit_code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
                except subprocess.TimeoutExpired as exc:
                    # a slow install isn't itself a signal — only what it did during that time is
                    timed_out = True
                    stdout, stderr = exc.stdout, exc.stderr
                finally:
                    # always, not only on timeout: if anything interrupted the
                    # run, the container must not be left running unobserved
                    _force_remove_container(container_name)
            finally:
                wiretap.stop()
                _reclaim_scratch(Path(scratch), image)
            capture = wiretap.capture()
            tls_inspected = wiretap.ca_path is not None
            trace_result = parse_trace(name, trace_dir, proxy_port=WIRETAP_PORT) if trace_dir is not None else None
    finally:
        networks.remove()

    if summary is not None:
        summary.update(
            _summarize_run(
                scripts, canaries, capture,
                exit_code=exit_code, timed_out=timed_out, seconds=time.monotonic() - started,
                stdout=stdout, stderr=stderr, tls_inspected=tls_inspected, trace=trace_result, tracing_requested=trace,
                time_limit=timeout,
            )
        )
    signals = _signals_from_capture(name, capture, canaries)
    if trace_result is not None:
        signals.extend(trace_result.signals)
    # an install can run the same code several times (pip builds metadata, then the wheel, then installs):
    # one finding per distinct observation, not one per repetition
    return list({s.id: s for s in signals}.values())


def _short(text: str, limit: int = 300) -> str:
    """Request URLs can carry a whole exfiltrated environment; keep the
    evidence readable. The leak itself is already established by then."""
    text = sanitize_text(text)
    return text if len(text) <= limit else text[:limit] + f"… (+{len(text) - limit} chars)"


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
                    evidence=[Evidence(excerpt=_short(f"{req.method} {req.url}"), detail=f"destination={req.host}")],
                )
            )

        req_host = req.host.rpartition(":")[0] or req.host  # strip ":port" if present
        # an inspected HTTPS request was already reported through its CONNECT below
        if getattr(req, "scheme", "http") == "http" and req_host and req_host not in ALLOWED_HOSTS:
            signals.append(
                Signal(
                    id=signal_id(SignalSource.DETONATION, "unexpected-network-destination", f"{name}:{req_host}:{req.url}"),
                    source=SignalSource.DETONATION,
                    category="unexpected-network-destination",
                    severity=Severity.MEDIUM,
                    description=f"install script made a plain-HTTP request to an unrecognized host: {req_host}",
                    evidence=[Evidence(excerpt=_short(f"{req.method} {req.url}"), detail=f"destination={req_host}")],
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
                            detail="HTTPS tunnel",
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
