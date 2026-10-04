import json
from pathlib import Path

from malwhunter.recon.catalog import COMMAND_EXEC_CALL
from malwhunter.recon.scanner import _is_regexp_exec_false_positive, run_recon

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "npm-fixtures"


def _run(fixture_name: str):
    pkg_dir = FIXTURES / fixture_name
    package_json = json.loads((pkg_dir / "package.json").read_text())
    return run_recon(pkg_dir, package_json["name"], package_json)


def test_malicious_postinstall_is_flagged():
    signals = _run("malicious-postinstall")
    categories = {s.category for s in signals}
    assert "lifecycle-script-abuse" in categories


def test_env_exfil_pattern_is_flagged():
    signals = _run("env-exfil")
    categories = {s.category for s in signals}
    assert "sensitive-data-network-cooccurrence" in categories


def test_benign_package_has_no_signals():
    signals = _run("benign-pkg")
    assert signals == []


def test_every_signal_has_evidence():
    for fixture in ("malicious-postinstall", "env-exfil"):
        for signal in _run(fixture):
            assert len(signal.evidence) > 0
            for e in signal.evidence:
                assert e.excerpt


def test_env_harvester_triggers_all_three_new_signals():
    """Modeled on the real MAL-2026-7003 (searchresults@999.0.0) technique:
    a postinstall that isn't a raw curl|sh one-liner, so lifecycle-script-
    abuse alone would miss it entirely — the new signals exist to catch
    exactly this shape."""
    signals = _run("env-harvester")
    categories = {s.category for s in signals}
    assert "bulk-env-enumeration" in categories
    assert "known-exfil-channel" in categories
    assert "command-exec-computed-arg" in categories
    # and confirm the gap this fixture demonstrates:
    assert "lifecycle-script-abuse" not in categories


def _match(line: str):
    return COMMAND_EXEC_CALL.search(line)


def test_regexp_exec_on_arbitrary_object_is_suppressed_when_file_has_no_child_process_import():
    # The exact false positive found live-benchmarking against ms@2.1.3:
    # a regex literal's .exec() call, not child_process.
    line = "var match = /^(-?\\d+)/.exec(str)"
    m = _match(line)
    assert m is not None
    assert _is_regexp_exec_false_positive(line, m, file_imports_child_process=False) is True


def test_dotted_exec_is_not_suppressed_when_file_imports_child_process():
    # Same dotted shape as the regex case, but the file genuinely uses
    # child_process somewhere — checked at the file level, not by
    # matching the literal variable name, so this also covers aliases
    # like `cp`/`childProcess` that don't literally say "child_process.".
    line = "cp.exec(userCmd, cb)"
    m = _match(line)
    assert m is not None
    assert _is_regexp_exec_false_positive(line, m, file_imports_child_process=True) is False


def test_dotted_literal_child_process_exec_is_not_suppressed():
    line = "child_process.exec(userCmd, cb)"
    m = _match(line)
    assert m is not None
    assert _is_regexp_exec_false_positive(line, m, file_imports_child_process=True) is False


def test_bare_destructured_exec_is_not_suppressed_even_without_import_detected():
    # const { exec } = require('child_process'); exec(cmd) — no dot at
    # all, so the ambiguity with RegExp.exec() doesn't apply here,
    # regardless of whether the import was detected.
    line = "exec(inspectCmd, (err, stdout) => {})"
    m = _match(line)
    assert m is not None
    assert _is_regexp_exec_false_positive(line, m, file_imports_child_process=False) is False


def test_spawn_on_arbitrary_object_is_still_flagged():
    # Only bare "exec" collides with a real built-in method name —
    # spawn/execFile/etc. have no such legitimate namesake, so a dotted
    # call to one of those is never suppressed, even in a file with no
    # child_process import at all.
    line = "someWrapper.spawn(binaryPath)"
    m = _match(line)
    assert m is not None
    assert _is_regexp_exec_false_positive(line, m, file_imports_child_process=False) is False


def test_ms_style_regexp_exec_produces_no_signal_end_to_end(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "index.js").write_text(
        "var match = /^(-?(?:\\d+)?\\.?\\d+) *(ms|seconds?)?$/i.exec(str);\n"
    )
    signals = run_recon(pkg_dir, "ms-like", {"name": "ms-like"})
    assert "command-exec-computed-arg" not in {s.category for s in signals}


def test_aliased_child_process_exec_still_produces_a_signal_end_to_end(tmp_path):
    # The gap in the first version of this fix: a real child_process
    # user whose import is aliased to anything other than the literal
    # string "child_process" (very common — `cp`, `childProcess`, etc.)
    # must still be flagged. File-level import detection, not matching
    # the variable name, is what makes this work.
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "index.js").write_text(
        "const cp = require('child_process');\n"
        "function run(userInput) { cp.exec(userInput); }\n"
    )
    signals = run_recon(pkg_dir, "aliased-cp", {"name": "aliased-cp"})
    assert "command-exec-computed-arg" in {s.category for s in signals}
