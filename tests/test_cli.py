import tarfile

import httpx
import pytest

from malwhunter import cli
from malwhunter.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    _analyze_package,
    _render_and_exit,
    _resolve_detonate_mode,
)
from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource
from malwhunter.intake.registry import PackageFetchError


def test_render_and_exit_with_out_path_still_prints_terminal_view(tmp_path, capsys):
    # Writing a report to a file shouldn't make the CLI go silent — the
    # human-readable view should still show up in the terminal, in
    # addition to (not instead of) the file write.
    out_path = tmp_path / "report.md"
    dossiers = [Dossier(package="left-pad", version="1.3.0")]

    with pytest.raises(SystemExit):
        _render_and_exit(dossiers, ".", "markdown", str(out_path), "none")

    captured = capsys.readouterr()
    assert "MALWHUNTER" in captured.out
    assert f"Wrote markdown report with 1 package(s) to {out_path}" in captured.out
    assert out_path.read_text().startswith("# MalwHunter Scan Report")


def test_resolve_detonate_mode_defaults_to_smart():
    assert _resolve_detonate_mode(no_detonate=False, always_detonate=False) == "smart"


def test_resolve_detonate_mode_no_detonate_wins_even_if_always_also_set():
    # --no-detonate is the hard "never touch Docker" override — it must
    # win regardless of what else is passed, since it's also the flag
    # used to mean "no Docker available at all."
    assert _resolve_detonate_mode(no_detonate=True, always_detonate=True) == "never"


def test_resolve_detonate_mode_always_detonate():
    assert _resolve_detonate_mode(no_detonate=False, always_detonate=True) == "always"


def _analyze(tmp_path, name="left-pad", version="1.3.0"):
    return _analyze_package(
        name, version, tmp_path,
        detonate_mode="never", age_threshold_days=30, downloads_threshold=1000, analyst=None,
    )


@pytest.mark.parametrize(
    "failure",
    [
        PackageFetchError("left-pad@1.3.0: registry returned 503"),
        httpx.ConnectError("network unreachable"),
        tarfile.ReadError("not a gzip file"),
    ],
)
def test_fetch_or_extract_failure_is_unscanned_not_clean(tmp_path, monkeypatch, failure):
    # Before: any of these returned an empty Dossier, which reported as
    # CLEAN — "we couldn't look" was indistinguishable from "we looked".
    # httpx/tarfile errors weren't caught at all and crashed the whole scan.
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(cli, "fetch_tarball", fail)
    dossier = _analyze(tmp_path)
    assert dossier.scan_error is not None
    assert dossier.to_dict()["verdict"] == "unscanned"


@pytest.mark.parametrize("version", ["^1.2.0", "~3.0.0", "latest", "*", "github:user/repo", ">=1.0.0 <2.0.0"])
def test_non_exact_version_is_unscanned_without_fetching(tmp_path, monkeypatch, version):
    # The no-lockfile fallback reads package.json ranges; fetching "^1.2.0"
    # as if it were a version 404s (→ used to be "clean") or worse.
    def must_not_fetch(*args, **kwargs):
        raise AssertionError("a non-exact version must not be fetched")

    monkeypatch.setattr(cli, "fetch_tarball", must_not_fetch)
    dossier = _analyze(tmp_path, version=version)
    assert dossier.to_dict()["verdict"] == "unscanned"
    assert "package-lock.json" in dossier.scan_error


@pytest.mark.parametrize("version", ["1.3.0", "0.0.1", "2.0.0-beta.1", "1.0.0+build.5"])
def test_exact_versions_are_fetched(tmp_path, monkeypatch, version):
    fetched = []

    def record(name, ver, workdir):
        fetched.append(ver)
        raise PackageFetchError("stop here")

    monkeypatch.setattr(cli, "fetch_tarball", record)
    _analyze(tmp_path, version=version)
    assert fetched == [version]


def _exit_code(dossiers, fail_on):
    with pytest.raises(SystemExit) as exc:
        _render_and_exit(dossiers, ".", "json", None, fail_on)
    return exc.value.code


def _suspicious_dossier():
    d = Dossier(package="sus", version="1.0.0")
    d.add_signal(Signal("s", SignalSource.RECON, "packed-string-blob", Severity.MEDIUM, "x", [Evidence(excerpt="x")]))
    return d


@pytest.mark.parametrize("fail_on", ["malicious", "suspicious", "none"])
def test_unscanned_package_fails_the_gate_with_error_code(fail_on, capsys):
    dossiers = [Dossier(package="ok", version="1.0.0"), Dossier(package="x", version="1.0.0", scan_error="503")]
    assert _exit_code(dossiers, fail_on) == EXIT_ERROR
    assert "could not be scanned" in capsys.readouterr().err


def test_findings_take_precedence_over_unscanned():
    dossiers = [_suspicious_dossier(), Dossier(package="x", version="1.0.0", scan_error="503")]
    assert _exit_code(dossiers, "suspicious") == EXIT_FINDINGS


def test_ignored_unscanned_package_does_not_fail_the_gate():
    d = Dossier(package="x", version="1.0.0", scan_error="503", ignored=True, ignore_reason="private mirror")
    assert _exit_code([d], "malicious") == EXIT_OK


def test_all_scanned_and_clean_exits_ok():
    assert _exit_code([Dossier(package="ok", version="1.0.0")], "suspicious") == EXIT_OK



def _fake_fetched_package(monkeypatch, tmp_path, name):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(f'{{"name": "{name}", "version": "1.0.0"}}')
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: tmp_path / "x.tgz")
    monkeypatch.setattr(cli, "extract_tarball", lambda *a, **k: package_dir)


@pytest.mark.parametrize("downloads,expected", [(2_000_000, "clean"), (12, "suspicious"), (None, "suspicious")])
def test_typosquat_verdict_depends_on_the_packages_own_popularity(tmp_path, monkeypatch, downloads, expected):
    from malwhunter.intake.registry import PackageReputation

    _fake_fetched_package(monkeypatch, tmp_path, "axioss")
    lookups = []

    def reputation(name, version):
        lookups.append(name)
        return PackageReputation(age_days=900, downloads_last_month=downloads)

    monkeypatch.setattr(cli, "fetch_package_reputation", reputation)
    dossier = _analyze(tmp_path, name="axioss", version="1.0.0")
    assert dossier.to_dict()["verdict"] == expected
    assert lookups == ["axioss"]  # even with detonation off, and only once


def test_no_reputation_lookup_when_detonation_off_and_no_typosquat(tmp_path, monkeypatch):
    _fake_fetched_package(monkeypatch, tmp_path, "my-internal-thing")

    def must_not_lookup(*a, **k):
        raise AssertionError("no reason to hit the registry for reputation here")

    monkeypatch.setattr(cli, "fetch_package_reputation", must_not_lookup)
    assert _analyze(tmp_path, name="my-internal-thing", version="1.0.0").to_dict()["verdict"] == "clean"



def _analyze_detonating(tmp_path, monkeypatch, package_json, detonate):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    import json as _json

    (package_dir / "package.json").write_text(_json.dumps(package_json))
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: tmp_path / "x.tgz")
    monkeypatch.setattr(cli, "extract_tarball", lambda *a, **k: package_dir)
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_package", detonate)
    return _analyze_package(
        package_json["name"], "1.0.0", tmp_path,
        detonate_mode="always", age_threshold_days=30, downloads_threshold=1000, analyst=None,
    )


def test_package_without_install_scripts_is_not_reported_as_detonated(tmp_path, monkeypatch):
    # Found running `inspect left-pad@1.3.0 --always-detonate`: left-pad has
    # only test/bench scripts, no container ran, yet the report said
    # "detonated 1/1".
    def must_not_run(*a, **k):
        raise AssertionError("nothing to detonate")

    dossier = _analyze_detonating(
        tmp_path, monkeypatch, {"name": "left-pad", "scripts": {"test": "node test"}}, must_not_run
    )
    assert dossier.detonated is False
    assert "nothing ran" in dossier.detonation_decision_reason


def test_package_with_install_script_is_detonated(tmp_path, monkeypatch):
    calls = []
    dossier = _analyze_detonating(
        tmp_path, monkeypatch, {"name": "x", "scripts": {"postinstall": "node setup.js"}},
        lambda *a, **k: calls.append(a) or [],
    )
    assert dossier.detonated is True
    assert len(calls) == 1


def test_unavailable_detonation_is_explained_in_the_reason(tmp_path, monkeypatch):
    from malwhunter.chamber.runner import DetonationUnavailable

    def unavailable(*a, **k):
        raise DetonationUnavailable("Docker daemon is not reachable")

    dossier = _analyze_detonating(
        tmp_path, monkeypatch, {"name": "x", "scripts": {"postinstall": "node setup.js"}}, unavailable
    )
    assert dossier.detonated is False
    assert "unavailable: Docker daemon is not reachable" in dossier.detonation_decision_reason
