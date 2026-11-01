"""JavaScript syntax-tree analysis for Recon.

The line-by-line regexes in scanner.py cannot tell `exec(cmd)` from
child_process from `exec(regex, text)` in core-js, miss a call split across
lines, and are blind to `require('child' + '_process')`. This reads the file
as code instead: it works out what each name is bound to (`const { exec: run }
= require('child_process')`, `import cp from 'node:child_process'`,
`promisify(cp.exec)`), folds constant string expressions, and reports only
calls that really reach a dangerous API.

It adds precision; it never removes coverage. `analyze()` returns None when
the parser isn't installed, the file doesn't parse cleanly (TypeScript, Flow,
a shell script with no extension), or it is very large, and the scanner then
runs its regex rules on that file exactly as before.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

try:  # the parser is a hard dependency, but a missing wheel must degrade, not crash
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser

    _PARSER: Parser | None = Parser(Language(_tsjs.language()))
except Exception:  # noqa: BLE001 - any import/ABI failure means "no AST", never "no scan"
    _PARSER = None

_MAX_AST_BYTES = 600_000
_MAX_DEPTH = 60
_MAX_FOLDED_LEN = 4096

CHILD_PROCESS_FUNCS = frozenset({"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "-command", "-encodedcommand", "/k"})
# Modules whose name nobody has a reason to assemble out of pieces.
SENSITIVE_MODULES = frozenset(
    {"child_process", "net", "http", "https", "http2", "dgram", "dns", "tls", "vm", "worker_threads", "cluster"}
)
_GLOBAL_OBJECTS = frozenset({"global", "globalThis", "window", "self"})
_VM_EVAL = frozenset({"runInNewContext", "runInContext", "runInThisContext"})


@dataclass(frozen=True)
class AstFinding:
    kind: str  # "command-exec" | "eval" | "obfuscated-module-load" | "shell-pipe"
    line: int
    name: str  # the API reached, e.g. "exec", "eval", "child_process"
    detail: str = ""


def available() -> bool:
    return _PARSER is not None


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _named(node) -> list:
    return [c for c in node.children if c.is_named and c.type != "comment"]


class _Analysis:
    def __init__(self, root) -> None:
        self.root = root
        # name -> (module, member|None): what an identifier is bound to
        self.bound: dict[str, tuple[str, str | None]] = {}
        # name -> folded constant string, for single-assignment consts
        self.consts: dict[str, str] = {}
        self.declared: set[str] = set()  # names the file itself defines (shadowing eval, Function, ...)
        self.has_dynamic_require = False
        self.findings: list[AstFinding] = []

    # ---- walking ----
    def walk(self):
        stack = [self.root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    # ---- constant folding ----
    def fold(self, node, depth: int = 0) -> str | None:
        if node is None or depth > _MAX_DEPTH:
            return None
        t = node.type
        if t == "string":
            if any(c.type == "escape_sequence" for c in node.children):
                return _unescape(_text(node)[1:-1])
            return "".join(_text(c) for c in node.children if c.type == "string_fragment")
        if t == "template_string":
            if any(c.type == "template_substitution" for c in node.children):
                parts = []
                for c in node.children:
                    if c.type == "template_substitution":
                        inner = _named(c)
                        folded = self.fold(inner[0], depth + 1) if inner else None
                        if folded is None:
                            return None
                        parts.append(folded)
                    elif c.type in ("string_fragment", "escape_sequence"):
                        parts.append(_text(c))
                return "".join(parts)
            return _text(node)[1:-1]
        if t == "parenthesized_expression":
            inner = _named(node)
            return self.fold(inner[0], depth + 1) if len(inner) == 1 else None
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and _text(op) == "+":
                left = self.fold(node.child_by_field_name("left"), depth + 1)
                right = self.fold(node.child_by_field_name("right"), depth + 1)
                if left is not None and right is not None and len(left) + len(right) <= _MAX_FOLDED_LEN:
                    return left + right
            return None
        if t == "identifier":
            return self.consts.get(_text(node))
        if t == "call_expression":
            return self._fold_call(node, depth)
        return None

    def _fold_call(self, node, depth: int) -> str | None:
        fn = node.child_by_field_name("function")
        args = _named(node.child_by_field_name("arguments")) if node.child_by_field_name("arguments") else []
        if fn is None:
            return None
        fn_text = _text(fn)
        if fn_text == "atob" and len(args) == 1:
            raw = self.fold(args[0], depth + 1)
            return _b64decode(raw) if raw is not None else None
        if fn_text == "String.fromCharCode":
            codes = []
            for a in args:
                if a.type != "number":
                    return None
                try:
                    codes.append(int(_text(a), 0))
                except ValueError:
                    return None
            try:
                return "".join(chr(c) for c in codes)
            except (ValueError, OverflowError):
                return None
        if fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            if prop is not None and _text(prop) == "toString" and obj is not None and obj.type == "call_expression":
                # Buffer.from('<b64>', 'base64').toString()
                inner_fn = obj.child_by_field_name("function")
                inner_args = _named(obj.child_by_field_name("arguments")) if obj.child_by_field_name("arguments") else []
                if (
                    inner_fn is not None
                    and _text(inner_fn) == "Buffer.from"
                    and len(inner_args) == 2
                    and self.fold(inner_args[1], depth + 1) in ("base64", "hex")
                ):
                    data = self.fold(inner_args[0], depth + 1)
                    if data is None:
                        return None
                    return _b64decode(data) if self.fold(inner_args[1], depth + 1) == "base64" else _hexdecode(data)
            if prop is not None and _text(prop) == "join" and obj is not None and obj.type == "array":
                sep = self.fold(args[0], depth + 1) if args else ","
                items = [self.fold(e, depth + 1) for e in _named(obj)]
                if sep is not None and all(i is not None for i in items):
                    return sep.join(items)  # type: ignore[arg-type]
        return None

    # ---- bindings ----
    def collect(self) -> None:
        # Two passes so `const a = require('x'); const { b } = a;` resolves
        # regardless of declaration order within the file.
        for _ in range(2):
            for node in self.walk():
                t = node.type
                if t == "variable_declarator":
                    self._bind(node.child_by_field_name("name"), node.child_by_field_name("value"))
                elif t == "assignment_expression":
                    self._bind(node.child_by_field_name("left"), node.child_by_field_name("right"))
                elif t == "import_statement":
                    self._bind_import(node)
                elif t in ("function_declaration", "class_declaration", "generator_function_declaration"):
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self.declared.add(_text(name))
                elif t in ("formal_parameters",):
                    for p in node.children:
                        if p.type == "identifier":
                            self.declared.add(_text(p))

    def _module_of(self, node, depth: int = 0) -> tuple[str, str | None] | None:
        """(module, member) when `node` evaluates to a module or one of its members."""
        if node is None or depth > _MAX_DEPTH:
            return None
        t = node.type
        if t == "identifier":
            return self.bound.get(_text(node))
        if t in ("parenthesized_expression", "await_expression"):
            inner = _named(node)
            return self._module_of(inner[0], depth + 1) if inner else None
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            args = _named(args_node) if args_node is not None else []
            if fn is None:
                return None
            fn_text = _text(fn)
            if fn_text == "require" and len(args) == 1:
                name = self.fold(args[0])
                if name is None:
                    if args[0].type != "string":
                        self.has_dynamic_require = True
                    return None
                return (_strip_node_prefix(name), None)
            if fn_text in ("promisify", "util.promisify") and len(args) == 1:
                return self._module_of(args[0], depth + 1)  # promisify(cp.exec) is still cp.exec
            return None
        if t == "member_expression":
            base = self._module_of(node.child_by_field_name("object"), depth + 1)
            prop = node.child_by_field_name("property")
            if base is not None and base[1] is None and prop is not None:
                return (base[0], _text(prop))
            return None
        if t == "subscript_expression":
            base = self._module_of(node.child_by_field_name("object"), depth + 1)
            member = self.fold(node.child_by_field_name("index"), depth + 1)
            if base is not None and base[1] is None and member is not None:
                return (base[0], member)
        return None

    def _bind(self, target, value) -> None:
        if target is None or value is None:
            return
        if target.type == "identifier":
            name = _text(target)
            self.declared.add(name)
            folded = self.fold(value)
            if folded is not None:
                self.consts[name] = folded
            mod = self._module_of(value)
            if mod is not None:
                self.bound[name] = mod
        elif target.type == "object_pattern":
            base = self._module_of(value)
            if base is None or base[1] is not None:
                return
            for child in target.children:
                if child.type == "shorthand_property_identifier_pattern":
                    self.bound[_text(child)] = (base[0], _text(child))
                elif child.type == "pair_pattern":
                    key, val = child.child_by_field_name("key"), child.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        member = self.fold(key) if key.type in ("string", "computed_property_name") else _text(key)
                        if member is not None:
                            self.bound[_text(val)] = (base[0], member)

    def _bind_import(self, node) -> None:
        source = node.child_by_field_name("source")
        module = self.fold(source) if source is not None else None
        if module is None:
            return
        module = _strip_node_prefix(module)
        for child in node.children:
            if child.type != "import_clause":
                continue
            for part in child.children:
                if part.type == "identifier":  # import cp from 'child_process'
                    self.bound[_text(part)] = (module, None)
                elif part.type == "namespace_import":  # import * as cp from ...
                    ids = [c for c in part.children if c.type == "identifier"]
                    if ids:
                        self.bound[_text(ids[0])] = (module, None)
                elif part.type == "named_imports":  # import { exec as run } from ...
                    for spec in part.children:
                        if spec.type != "import_specifier":
                            continue
                        name, alias = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                        if name is not None:
                            self.bound[_text(alias if alias is not None else name)] = (module, _text(name))

    # ---- detection ----
    def detect(self) -> None:
        for node in self.walk():
            t = node.type
            if t == "call_expression":
                self._check_call(node)
            elif t == "new_expression":
                self._check_new(node)

    def _args(self, node) -> list:
        args = node.child_by_field_name("arguments")
        return _named(args) if args is not None else []

    def _check_call(self, node) -> None:
        fn = node.child_by_field_name("function")
        if fn is None:
            return
        line = node.start_point[0] + 1
        args = self._args(node)

        # --- require('chi' + 'ld_process'): a sensitive module named in pieces ---
        if fn.type == "identifier" and _text(fn) == "require" and args and args[0].type != "string":
            name = self.fold(args[0])
            if name is not None and _strip_node_prefix(name) in SENSITIVE_MODULES:
                self.findings.append(AstFinding("obfuscated-module-load", line, _strip_node_prefix(name)))
            return

        # --- eval(x) / Function(x) / vm.runIn*(x) ---
        eval_name = self._eval_callee(fn)
        if eval_name is not None:
            if args and self.fold(args[0]) is None:
                self.findings.append(AstFinding("eval", line, eval_name))
            return

        # --- child_process.* ---
        resolved = self._child_process_member(fn)
        if resolved is None:
            return
        member = resolved
        if not args:
            return
        first = self.fold(args[0])
        if first is None:
            self.findings.append(AstFinding("command-exec", line, member))
            return
        # A literal first argument: only suspicious as a shell pipeline or as `sh -c <computed>`
        from malwhunter.recon.catalog import SHELL_ABUSE_PATTERN

        if SHELL_ABUSE_PATTERN.search(first):
            self.findings.append(AstFinding("shell-pipe", line, member, first[:120]))
            return
        if first.rsplit("/", 1)[-1].lower() in _SHELLS and member in ("spawn", "spawnSync", "execFile", "execFileSync"):
            rest = args[1] if len(args) > 1 else None
            if rest is not None and rest.type == "array":
                items = _named(rest)
                for i, item in enumerate(items[:-1] if items else []):
                    flag = self.fold(item)
                    if flag is not None and flag.lower() in _SHELL_FLAGS and self.fold(items[i + 1]) is None:
                        self.findings.append(AstFinding("command-exec", line, member, f"{first} {flag} <computed>"))
                        return

    def _check_new(self, node) -> None:
        ctor = node.child_by_field_name("constructor")
        args = self._args(node)
        if ctor is not None and ctor.type == "identifier" and _text(ctor) == "Function" and "Function" not in self.declared:
            if args and self.fold(args[-1]) is None:
                self.findings.append(AstFinding("eval", node.start_point[0] + 1, "Function"))

    def _eval_callee(self, fn) -> str | None:
        if fn.type == "identifier":
            name = _text(fn)
            if name in ("eval", "Function") and name not in self.declared:
                return name
            return None
        if fn.type == "parenthesized_expression":  # (0, eval)(x) — indirect eval
            inner = _named(fn)
            if len(inner) == 1 and inner[0].type == "sequence_expression":
                last = _named(inner[0])[-1]
                if last.type == "identifier" and _text(last) == "eval" and "eval" not in self.declared:
                    return "eval"
            return None
        if fn.type == "member_expression":
            obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            prop_name = _text(prop)
            if prop_name == "eval" and obj.type == "identifier" and _text(obj) in _GLOBAL_OBJECTS:
                return "eval"
            base = self._module_of(obj)
            if base == ("vm", None) and prop_name in _VM_EVAL:
                return f"vm.{prop_name}"
        return None

    def _child_process_member(self, fn) -> str | None:
        """The child_process function a callee resolves to, or None."""
        resolved = self._module_of(fn)
        if resolved is not None and resolved[0] == "child_process" and resolved[1] in CHILD_PROCESS_FUNCS:
            return resolved[1]
        # A module we could not resolve (require(x)): don't lose a `.exec(cmd)` / `.spawn(cmd)` on it
        if self.has_dynamic_require and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop is not None and _text(prop) in CHILD_PROCESS_FUNCS and _text(prop) != "exec":
                return _text(prop)
        return None


def _strip_node_prefix(name: str) -> str:
    return name[5:] if name.startswith("node:") else name


def _b64decode(raw: str) -> str | None:
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False).decode("utf-8", errors="replace")[:_MAX_FOLDED_LEN]
    except (binascii.Error, ValueError):
        return None


def _hexdecode(raw: str) -> str | None:
    try:
        return bytes.fromhex(raw).decode("utf-8", errors="replace")[:_MAX_FOLDED_LEN]
    except ValueError:
        return None


_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`"}


def _unescape(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "x" and len(body[i + 2 : i + 4]) == 2 and _is_hex(body[i + 2 : i + 4]):
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
        elif nxt == "u" and _is_hex(body[i + 2 : i + 6]) and len(body[i + 2 : i + 6]) == 4:
            out.append(chr(int(body[i + 2 : i + 6], 16)))
            i += 6
        else:
            out.append(_SIMPLE_ESCAPES.get(nxt, nxt))
            i += 2
    return "".join(out)


def _is_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)


def analyze(source: str) -> list[AstFinding] | None:
    """Findings for one JavaScript file, or None when the AST can't be used
    (no parser, parse errors, too large) and the caller should use regexes."""
    if _PARSER is None:
        return None
    data = source.encode("utf-8", errors="replace")
    if len(data) > _MAX_AST_BYTES:
        return None
    try:
        tree = _PARSER.parse(data)
    except Exception:  # noqa: BLE001 - a parser fault on hostile input must fall back, not crash
        return None
    if tree.root_node.has_error:
        return None
    analysis = _Analysis(tree.root_node)
    try:
        analysis.collect()
        analysis.detect()
    except RecursionError:
        return None
    return analysis.findings
