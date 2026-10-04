import pytest

from malwhunter.cli import _render_and_exit, _resolve_detonate_mode
from malwhunter.dossier.model import Dossier


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
