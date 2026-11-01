"""Hostile-input and fail-safe behaviour: what a malicious package (or a bad
download) must not be able to do to the scanner or its reports."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import click
import httpx
import pytest

from malwhunter import cli
from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource
from malwhunter.intake import registry
from malwhunter.intake.manifest import get_lifecycle_scripts
from malwhunter.intake.registry import PackageFetchError, fetch_tarball
from malwhunter.recon.scanner import run_recon
from malwhunter.report.markdown import dossiers_to_markdown
from malwhunter.report.sanitize import escape_markdown_inline, sanitize_text
from malwhunter.report.terminal import dossiers_to_terminal
from malwhunter.wiretap.canary import find_leaked_canaries

# ---------- scripts / package.json shape ----------

@pytest.mark.parametrize(
    "package_json",
    [
        {"scripts": {"postinstall": 123}},
        {"scripts": {"postinstall": ["a", "b"]}},
        {"scripts": ["not", "a", "dict"]},
        {"scripts": None},
        [],
        "just a string",
        None,
    ],
)
def test_malformed_package_json_never_crashes_lifecycle_handling(package_json):
    assert get_lifecycle_scripts(package_json) == {}


def test_recon_survives_non_string_scripts(tmp_path: Path):
    (tmp_path / "index.js").write_text("module.exports = 1;\n")
    assert run_recon(tmp_path, "weird", {"scripts": {"postinstall": 123}}) == []


def test_non_object_package_json_is_treated_as_no_metadata(tmp_path, monkeypatch):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "package.json").write_text("[1, 2, 3]")
    (package_dir / "index.js").write_text("module.exports = 1;\n")
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: tmp_path / "x.tgz")
    monkeypatch.setattr(cli, "extract_tarball", lambda *a, **k: package_dir)
    dossier = cli._analyze_package(
        "weird", "1.0.0", tmp_path, detonate_mode="never", age_threshold_days=30, downloads_threshold=1000, analyst=None
    )
    assert dossier.scan_error is None


def test_unexpected_error_in_one_package_becomes_unscanned_not_a_crash(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("scanner bug")

    monkeypatch.setattr(cli, "_analyze_package", boom)
    dossier = cli._analyze_safely("x", "1.0.0", tmp_path, detonate_mode="never")
    assert dossier.scan_error and "RuntimeError" in dossier.scan_error
    assert dossier.to_dict()["verdict"] == "unscanned"


# ---------- output sanitising ----------

def test_sanitize_strips_ansi_osc_and_control_characters():
    hostile = "ok\x1b[2J\x1b[31mred\x1b]0;pwned\x07\x00\x08 end\x9b"
    assert sanitize_text(hostile) == "okred end"


def test_markdown_escape_neutralises_links_html_and_fences():
    out = escape_markdown_inline("[click](http://evil) <img src=x> `code`")
    for ch in "[]()<>`":
        assert ch not in out.replace("\\" + ch, "")


def _flagged_dossier(excerpt: str) -> Dossier:
    d = Dossier(package="pkg", version="1.0.0")
    d.add_signal(
        Signal(
            id="1", source=SignalSource.RECON, category="eval-computed-arg", severity=Severity.HIGH,
            description="desc \x1b[31m", evidence=[Evidence(excerpt=excerpt, file="a.js", line=3)],
        )
    )
    return d


def test_terminal_report_does_not_pass_package_escape_codes_through():
    out = dossiers_to_terminal([_flagged_dossier("x\x1b[2Jx\x1b]0;title\x07")], "t")
    assert "\x1b[2J" not in out and "title" not in out.replace("\x1b[", "")


def test_markdown_report_escapes_package_controlled_text():
    out = dossiers_to_markdown([_flagged_dossier("[a](http://evil.example) <script>")], "t")
    assert "[a](http://evil.example)" not in out and "<script>" not in out


# ---------- tarball integrity and size ----------

def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _client(dist: dict, body: bytes) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".tgz"):
            return httpx.Response(200, content=body)
        return httpx.Response(200, json={"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz", **dist}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_tarball_matching_registry_integrity_is_accepted(tmp_path):
    body = _tgz({"package/package.json": b"{}"})
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
    assert fetch_tarball("x", "1.0.0", tmp_path, client=_client({"integrity": integrity}, body)).exists()


def test_tarball_not_matching_registry_integrity_is_refused(tmp_path):
    body = _tgz({"package/package.json": b"{}"})
    wrong = "sha512-" + base64.b64encode(hashlib.sha512(b"something else").digest()).decode()
    with pytest.raises(PackageFetchError, match="integrity"):
        fetch_tarball("x", "1.0.0", tmp_path, client=_client({"integrity": wrong}, body))


def test_tarball_not_matching_legacy_shasum_is_refused(tmp_path):
    body = _tgz({"package/package.json": b"{}"})
    with pytest.raises(PackageFetchError, match="shasum"):
        fetch_tarball("x", "1.0.0", tmp_path, client=_client({"shasum": "0" * 40}, body))


def test_metadata_without_any_digest_is_still_accepted(tmp_path):
    body = _tgz({"package/package.json": b"{}"})
    assert fetch_tarball("x", "1.0.0", tmp_path, client=_client({}, body)).exists()


def test_oversized_download_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "MAX_TARBALL_BYTES", 100)
    with pytest.raises(PackageFetchError, match="larger than"):
        fetch_tarball("x", "1.0.0", tmp_path, client=_client({}, b"x" * 500))


def test_tarball_that_expands_past_the_limit_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "MAX_EXTRACTED_BYTES", 10)
    tarball = tmp_path / "bomb.tgz"
    tarball.write_bytes(_tgz({"package/big.js": b"a" * 100}))
    with pytest.raises(PackageFetchError, match="safety limit"):
        registry.extract_tarball(tarball, tmp_path / "out")


# ---------- scanner coverage and cost limits ----------

def test_bin_file_without_js_extension_is_scanned(tmp_path: Path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "run").write_text("eval(Buffer.from(process.argv[2], 'base64').toString())\n")
    signals = run_recon(tmp_path, "tool", {"bin": {"tool": "bin/run"}})
    assert any(s.category == "eval-computed-arg" for s in signals)


def test_bin_path_cannot_point_outside_the_package(tmp_path: Path):
    outside = tmp_path / "outside.js"
    outside.write_text("eval(x)\n")
    package = tmp_path / "pkg"
    package.mkdir()
    assert run_recon(package, "tool", {"bin": "../outside.js"}) == []


def test_oversized_source_file_is_reported_as_a_coverage_gap(tmp_path: Path, monkeypatch):
    from malwhunter.recon import scanner

    monkeypatch.setattr(scanner, "_MAX_FILE_SIZE", 10)
    (tmp_path / "big.js").write_text("x" * 100)
    gaps = [s for s in run_recon(tmp_path, "p", {}) if s.category == "scan-coverage-gap"]
    assert gaps and gaps[0].severity == Severity.LOW
    assert "big.js" in gaps[0].evidence[0].excerpt


def test_bundled_dependencies_are_reported_as_a_coverage_gap(tmp_path: Path):
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text("eval(x)\n")
    signals = run_recon(tmp_path, "p", {"bundledDependencies": ["dep"]})
    assert [s.category for s in signals] == ["scan-coverage-gap"]


def test_coverage_gaps_never_change_the_verdict(tmp_path: Path, monkeypatch):
    from malwhunter.dossier.verdict import compute_verdict
    from malwhunter.recon import scanner

    monkeypatch.setattr(scanner, "_MAX_FILE_SIZE", 10)
    (tmp_path / "big.js").write_text("x" * 100)
    assert compute_verdict(run_recon(tmp_path, "p", {})).value == "clean"


def test_analyst_calls_per_package_are_capped(tmp_path: Path, monkeypatch):
    from malwhunter.analyst.session import Verdict
    from malwhunter.recon import scanner

    calls = []

    class Counting:
        def ask(self, *, system, prompt):
            calls.append(1)
            return Verdict(ok=True, malicious=False, confidence=0.1, rationale="")

    monkeypatch.setattr(scanner, "_ANALYST_CALL_BUDGET", 4)
    blob = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6" * 2
    (tmp_path / "bundle.js").write_text("\n".join(f"var s{i} = '{blob}{i}';" for i in range(30)))
    run_recon(tmp_path, "p", {}, analyst=Counting())
    assert len(calls) == 4


# ---------- canary encodings ----------

CANARIES = {"NPM_TOKEN": "canary_0123456789abcdef0123456789abcdef"}


@pytest.mark.parametrize(
    "encode",
    [
        lambda v: v,
        lambda v: base64.b64encode(v.encode()).decode(),
        lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
        lambda v: v.encode().hex(),
        lambda v: base64.b64encode(json.dumps({"NPM_TOKEN": v}).encode()).decode(),  # inside a larger blob
        lambda v: base64.b64encode(b"xx" + json.dumps({"a": v}).encode()).decode(),  # different alignment
        lambda v: base64.b64encode(b"x" + json.dumps({"a": v}).encode()).decode(),
    ],
)
def test_canary_is_found_in_common_encodings(encode):
    assert find_leaked_canaries("GET /c?d=" + encode(CANARIES["NPM_TOKEN"]), CANARIES) == ["NPM_TOKEN"]


def test_unrelated_data_is_not_a_canary_leak():
    assert find_leaked_canaries("GET /c?d=" + base64.b64encode(b"hello world").decode(), CANARIES) == []


def test_click_usage_error_for_conflicting_modes():
    with pytest.raises(click.UsageError):
        cli._resolve_detonate_mode(True, False, "detonate")
    with pytest.raises(click.UsageError):
        cli._resolve_detonate_mode(False, True, "static")
    assert cli._resolve_detonate_mode(False, False, "static") == "never"
    assert cli._resolve_detonate_mode(False, False, "detonate") == "always"
    assert cli._resolve_detonate_mode(False, False, "auto") == "smart"
    assert cli._resolve_detonate_mode(True, False, "static") == "never"
