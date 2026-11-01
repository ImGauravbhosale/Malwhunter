"""Recon for Python packages, read as code with the standard library's `ast`.

Where the code runs decides how suspicious it is. A library may legitimately
shell out, read the environment or open a socket somewhere in its tree, but
the same call in `setup.py`, a top-level `__init__.py` or a `.pth` file runs
the moment the package is installed or first imported. So:

* "install-time" files (setup.py, a build backend that lives in the sdist,
  top-level `__init__.py`, `.pth`, `sitecustomize.py`): dynamic `exec`, shell
  commands, environment dumps, credential-file paths and network use are HIGH;
* anywhere in the package: only things with essentially no honest use are
  HIGH: decoding a payload straight into `exec`, building the name of
  `os`/`subprocess` out of pieces, `curl ... | sh`, a known exfiltration
  endpoint.

Files that don't parse (Python 2 sources) fall back to a few regexes, and
anything skipped for size is recorded so a report never implies full coverage.
"""
from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from malwhunter.analyst.session import Analyst
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.recon.catalog import (
    EXFIL_CHANNEL_PATTERN,
    PACKED_STRING_CANDIDATE,
    SHELL_ABUSE_PATTERN,
    looks_like_alphabet,
    shannon_entropy,
)

_MAX_FILE_SIZE = 1_500_000
_ENTROPY_THRESHOLD = 4.6
_MAX_DEPTH = 40
_MAX_FOLDED = 4096
_SKIP_DIR_PARTS = {".git", "__pycache__", "node_modules"}
_NON_PRODUCTION_PARTS = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks"}

_IMPORT_TIME_NAMES = {"setup.py", "sitecustomize.py", "usercustomize.py"}
SENSITIVE_MODULES = frozenset({"os", "subprocess", "socket", "ctypes", "pty", "shutil", "urllib", "requests", "http", "ftplib", "smtplib", "telnetlib"})
_DECODER_CALLS = frozenset(
    {"base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.urlsafe_b64decode", "base64.b85decode",
     "base64.a85decode", "binascii.a2b_base64", "binascii.unhexlify", "bytes.fromhex", "zlib.decompress",
     "gzip.decompress", "bz2.decompress", "lzma.decompress", "marshal.loads", "codecs.decode", "pickle.loads"}
)
_EXEC_BUILTINS = frozenset({"exec", "eval"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "-command", "-encodedcommand", "/k"})
_INSTALL_HOOK_COMMANDS = frozenset({"install", "develop", "egg_info", "install_lib", "install_scripts", "easy_install", "install_egg_info"})
_SHELL_CALLS = frozenset(
    {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
     "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"}
)
_NETWORK_CALLS = (
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib2.urlopen", "urllib.urlopen", "urllib.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "httplib.HTTPSConnection", "socket.socket",
    "socket.create_connection", "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL",
)
_NETWORK_PREFIXES = ("requests.", "httpx.", "aiohttp.")
_CREDENTIAL_STRING = re.compile(
    r"\.ssh[/\\]|\.aws[/\\]credentials|\.pypirc|\.npmrc|\.git-credentials|\.netrc\b|\.docker[/\\]config\.json|"
    r"\.kube[/\\]config|/etc/shadow|\.config[/\\]gcloud|wallet\.dat|Login Data|\.gnupg",
    re.IGNORECASE,
)
_KNOWN_GOOD_BACKENDS = frozenset(
    {"setuptools.build_meta", "setuptools.build_meta:__legacy__", "hatchling.build", "flit_core.buildapi",
     "poetry.core.masonry.api", "pdm.backend", "maturin", "scikit_build_core.build", "mesonpy", "sipbuild.api",
     "uv_build", "flit.buildapi", "setuptools_scm.build_meta"}
)
_GENERATED_NAMES = re.compile(r"(?:^|_)_?version(?:s)?\.py$|_build_info\.py$|_generated|_ext\.py$", re.IGNORECASE)
# regexes for files that don't parse (Python 2) — only the highest-value patterns
_FALLBACK_OBFUSCATED_EXEC = re.compile(r"\b(?:exec|eval)\s*\(.*?(?:b64decode|decompress|unhexlify|marshal\.loads|fromhex)", re.DOTALL)


@dataclass(frozen=True)
class _Target:
    root: Path
    label: str  # "sdist" or "wheel": keeps paths unambiguous when both are scanned


def _sig(category: str, severity: Severity, description: str, label_path: str, line: int, excerpt: str, detail: str | None = None) -> Signal:
    return Signal(
        id=signal_id(SignalSource.RECON, category, f"{label_path}:{line}"),
        source=SignalSource.RECON,
        category=category,
        severity=severity,
        description=description,
        evidence=[Evidence(excerpt=excerpt.strip()[:300], file=label_path, line=line, detail=detail)],
    )


def _is_import_time(rel: Path, label: str, build_dirs: frozenset[str] = frozenset()) -> bool:
    name = rel.name
    if _NON_PRODUCTION_PARTS & set(rel.parts[:-1]):
        return False  # a tests/ or docs/ tree is never installed, whatever it is named inside
    if name in _IMPORT_TIME_NAMES or name.endswith(".pth"):
        return True
    # an in-tree build backend (pyproject backend-path) runs during `pip install`, so it gets the strict rules
    if name.endswith(".py") and any(
        d == "." and len(rel.parts) == 1 or d != "." and (rel.parts[: len(Path(d).parts)] == Path(d).parts)
        for d in build_dirs
    ):
        return True
    # a top-level package's __init__.py (pkg/__init__.py or src/pkg/__init__.py) runs on first import
    parts = rel.parts
    return name == "__init__.py" and (len(parts) == 2 or (len(parts) == 3 and parts[0] == "src"))


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: str, rel: str, import_time: bool, *, whole_script: bool = True) -> None:
        self.lines = source.split("\n")
        self.rel = rel
        self._file_import_time = import_time
        # setup.py / sitecustomize.py run top to bottom. A package's __init__.py is different: a function body
        # only runs at import if something calls it there, so code inside a never-called function is not
        # install-time behaviour (pkg_resources' run_script() execs a script, but only when asked to).
        self._whole_script = whole_script
        self._deferred_depth = 0
        self._called_at_module_level: set[str] = set()
        self.aliases: dict[str, str] = {}  # local name -> dotted origin
        self.consts: dict[str, str] = {}
        self.signals: list[Signal] = []
        self.sensitive_read_line: int | None = None
        self.network_line: int | None = None
        self._seen: set[tuple[str, int]] = set()

    @property
    def import_time(self) -> bool:
        return self._file_import_time and (self._whole_script or self._deferred_depth == 0)

    def prepare(self, tree: ast.Module) -> None:
        """Names of functions the module itself calls while importing."""
        stack = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self._called_at_module_level.add(node.func.id)
            stack.extend(c for c in ast.iter_child_nodes(node) if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)))

    def _visit_deferred(self, node: ast.AST, name: str | None) -> None:
        deferred = name is None or name not in self._called_at_module_level
        self._deferred_depth += int(deferred)
        self.generic_visit(node)
        self._deferred_depth -= int(deferred)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_deferred(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_deferred(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_deferred(node, None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_deferred(node, None)

    # ---- helpers ----
    def excerpt(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def add(self, category: str, severity: Severity, description: str, line: int, detail: str | None = None) -> None:
        if (category, line) in self._seen:
            return
        self._seen.add((category, line))
        self.signals.append(_sig(category, severity, description, self.rel, line, self.excerpt(line), detail))

    def dotted(self, node: ast.AST) -> str | None:
        """`a.b.c` for a name/attribute chain, resolved through import aliases."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        head = self.aliases.get(node.id, node.id)
        return ".".join([head, *reversed(parts)])

    def fold(self, node: ast.AST | None, depth: int = 0) -> str | None:
        if node is None or depth > _MAX_DEPTH:
            return None
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.fold(node.left, depth + 1), self.fold(node.right, depth + 1)
            return left + right if left is not None and right is not None and len(left) + len(right) <= _MAX_FOLDED else None
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                piece = self.fold(v.value if isinstance(v, ast.FormattedValue) else v, depth + 1)
                if piece is None:
                    return None
                out.append(piece)
            return "".join(out)
        if isinstance(node, ast.Call):
            fn = self.dotted(node.func)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and node.args:
                sep = self.fold(node.func.value, depth + 1)
                items = node.args[0]
                if sep is not None and isinstance(items, (ast.List, ast.Tuple)):
                    parts = [self.fold(e, depth + 1) for e in items.elts]
                    if all(p is not None for p in parts):
                        return sep.join(parts)  # type: ignore[arg-type]
            if fn == "chr" and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                try:
                    return chr(node.args[0].value)
                except (ValueError, OverflowError):
                    return None
            if fn in ("base64.b64decode", "base64.urlsafe_b64decode") and node.args:
                import base64

                raw = self.fold(node.args[0], depth + 1)
                if raw is not None:
                    try:
                        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", errors="replace")[:_MAX_FOLDED]
                    except ValueError:
                        return None
        return None

    def is_file_read(self, node: ast.AST, depth: int = 0) -> bool:
        """`f.read()`, `path.read_text()`, `compile(f.read(), ...)`: running a file that ships in the package
        (the usual way setup.py reads `__version__`). That file is scanned as code in its own right, so
        flagging the idiom itself would only be noise."""
        if depth > 5 or not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "read_text", "read_bytes"):
            return True
        return (self.dotted(node.func) or "") == "compile" and bool(node.args) and self.is_file_read(node.args[0], depth + 1)

    def has_decoder(self, node: ast.AST) -> bool:
        """True when the expression decodes, decompresses or unmarshals something."""
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self.dotted(child.func) or ""
            if name in _DECODER_CALLS:
                return True
            # "...".decode("hex") / .decode("base64") / .decode("zlib")
            if isinstance(child.func, ast.Attribute) and child.func.attr == "decode":
                if any(isinstance(a, ast.Constant) and a.value in ("hex", "base64", "base64_codec", "zlib", "zlib_codec", "rot13") for a in child.args):
                    return True
        return False

    # ---- visiting ----
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{node.module or ''}.{alias.name}".lstrip(".")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        folded = self.fold(node.value)
        if folded is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.consts[target.id] = folded
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and self.import_time and _CREDENTIAL_STRING.search(node.value):
            self.add("credential-file-access", Severity.HIGH,
                     "install- or import-time code names a credential or secret store", node.lineno)
            self.sensitive_read_line = self.sensitive_read_line or node.lineno

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.dotted(node) == "os.environ" and self.sensitive_read_line is None:
            self.sensitive_read_line = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.dotted(node.func) or ""
        line = node.lineno
        first = node.args[0] if node.args else None

        # exec / eval
        if name in _EXEC_BUILTINS or name in ("builtins.exec", "builtins.eval"):
            if first is not None and self.has_decoder(first):
                self.add("obfuscated-exec", Severity.HIGH,
                         f"`{name}` runs a payload that is decoded or decompressed at runtime", line)
            elif first is not None and self.fold(first) is None and self.import_time and not self.is_file_read(first):
                self.add("exec-computed-arg", Severity.HIGH,
                         f"`{name}` called with a computed argument in code that runs at install or import", line)

        # os / subprocess
        if name in _SHELL_CALLS or name.startswith(("os.exec", "os.spawn")):
            command = self.fold(first)
            joined = command if command is not None else (self.fold_list(first) if first is not None else None)
            if joined is not None and (SHELL_ABUSE_PATTERN.search(joined) or re.search(r"(?:curl|wget)\s[^|;]*\|\s*(?:sh|bash)", joined)):
                self.add("command-exec-shell-pipe", Severity.HIGH,
                         f"`{name}` runs a command that pipes a remote or decoded payload into a shell", line)
            elif first is not None and self.has_decoder(first):
                self.add("obfuscated-exec", Severity.HIGH,
                         f"`{name}` runs a command that is decoded or decompressed at runtime", line)
            elif joined is None and self.import_time and self.command_is_computed(first, node):
                self.add("command-exec-computed-arg", Severity.HIGH,
                         f"`{name}` called with a computed command in code that runs at install or import", line)

        # __import__('o'+'s') / importlib.import_module(...)
        if name in ("__import__", "importlib.import_module") and first is not None and not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            module = self.fold(first)
            if module is not None and module.split(".")[0] in SENSITIVE_MODULES:
                self.add("obfuscated-module-load", Severity.HIGH,
                         f"loads the module '{module}' from a string assembled at runtime", line)

        # network use
        if name in _NETWORK_CALLS or name.startswith(_NETWORK_PREFIXES):
            self.network_line = self.network_line or line
        # `dict(os.environ)` / `.copy()` is how a build script hands its environment to a child process, so a
        # bare copy says nothing; serializing or iterating the whole thing does. A copy that is then sent
        # anywhere is caught by the sensitive-read + network rule below.
        if self.import_time and (
            name == "os.environ.items"
            or (name in ("json.dumps", "str", "repr", "pickle.dumps") and first is not None and self.dotted(first) == "os.environ")
        ):
            self.add("bulk-env-enumeration", Severity.HIGH,
                     "enumerates the entire environment rather than reading a specific named variable", line)

        # setup(cmdclass={...}) overrides what `pip install` runs
        if name.rsplit(".", 1)[-1] == "setup":
            for keyword in node.keywords:
                if keyword.arg == "cmdclass":
                    self.check_cmdclass(keyword.value, line)
        self.generic_visit(node)

    def check_cmdclass(self, value: ast.AST, line: int) -> None:
        """Overriding `install`/`develop`/`egg_info` is how a package gets code to run during `pip install`.
        `build_ext`, `test` and friends are routine (Cython, pytest runners), so they are only context."""
        keys: list[str] = []
        if isinstance(value, ast.Dict):
            keys = [k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        hooked = [k for k in keys if k in _INSTALL_HOOK_COMMANDS]
        if hooked:
            self.add("custom-install-command", Severity.MEDIUM,
                     f"setup() overrides {', '.join(hooked)} — custom code runs while the package installs", line)
        elif keys or not isinstance(value, ast.Dict):
            self.add("custom-install-command", Severity.LOW,
                     "setup() customizes build commands (cmdclass)", line)

    def visit_For(self, node: ast.For) -> None:
        if self.import_time and self.dotted(node.iter) == "os.environ":
            self.add("bulk-env-enumeration", Severity.HIGH,
                     "enumerates the entire environment rather than reading a specific named variable", node.lineno)
        self.generic_visit(node)

    def command_is_computed(self, node: ast.AST | None, call: ast.Call | None = None) -> bool:
        """Whether a command is really assembled at runtime, in the way that matters. An argv list that starts
        with a fixed tool (`["git", "rev-parse", ref]`, `[sys.executable, "setup.py", "build"]`) is ordinary
        build tooling even though one argument varies; it only counts when the program itself is not fixed, or
        a shell/interpreter is handed a computed script (`sh -c <computed>`, `python -c <computed>`)."""
        if node is None:
            return True
        if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
            if isinstance(node, ast.Name) and node.id not in self.consts:
                return False  # a variable holding an argv list we cannot see into: not evidence of anything
            # a string command: computed unless it folds to a constant
            return self.fold(node) is None
        head = node.elts[0]
        program = "python" if self.dotted(head) == "sys.executable" else self.fold(head)
        if program is None:
            return False  # build scripts pick compilers and tools by variable all the time
        program = program.rsplit("/", 1)[-1].lower()
        if program not in _SHELLS and not program.startswith(("python", "node", "perl", "ruby", "php")):
            return False
        flags = [self.fold(e) for e in node.elts[1:]]
        for i, flag in enumerate(flags[:-1]):
            if flag is not None and flag.lower() in _SHELL_FLAGS | {"-e", "-c"} and self.fold(node.elts[i + 2]) is None:
                return True
        return False

    def fold_list(self, node: ast.AST) -> str | None:
        if isinstance(node, (ast.List, ast.Tuple)):
            parts = [self.fold(e) for e in node.elts]
            return " ".join(parts) if all(p is not None for p in parts) else None  # type: ignore[arg-type]
        return None

    def finish(self) -> list[Signal]:
        if self.import_time and self.sensitive_read_line and self.network_line:
            self.signals.append(
                _sig("sensitive-data-network-cooccurrence", Severity.HIGH,
                     "install- or import-time code reads the environment or credential paths and also makes network calls",
                     self.rel, self.network_line, self.excerpt(self.network_line),
                     detail=f"sensitive read near line {self.sensitive_read_line}")
            )
        elif self.import_time and self.network_line:
            self.add("install-time-network", Severity.MEDIUM,
                     "code that runs at install or import makes network calls", self.network_line)
        return self.signals


def _text_signals(text: str, rel: str, production: bool, analyst: Analyst | None) -> list[Signal]:
    """Rules that read lines, not syntax: exfiltration endpoints and packed blobs."""
    signals: list[Signal] = []
    if not production:
        return signals
    for lineno, line in enumerate(text.split("\n"), start=1):
        if EXFIL_CHANNEL_PATTERN.search(line):
            signals.append(_sig("known-exfil-channel", Severity.HIGH,
                                "references a known exfiltration/C2 channel (webhook, paste service, bare IP, or .onion address) — rarely legitimate in a dependency",
                                rel, lineno, line))
        blob = PACKED_STRING_CANDIDATE.search(line)
        if blob and shannon_entropy(blob.group(1)) >= _ENTROPY_THRESHOLD and not looks_like_alphabet(blob.group(1)):
            excerpt = blob.group(1)[:80] + "..."
            signals.append(_sig("packed-string-blob", Severity.MEDIUM, "high-entropy string literal — possible packed/obfuscated payload", rel, lineno, excerpt))
            if analyst is not None:
                from malwhunter.analyst.judge import judge_packed_blob

                signals.extend(judge_packed_blob(analyst, file=rel, line=lineno, excerpt=excerpt))
    return signals


def _scan_py_file(
    text: str, rel: Path, label: str, analyst: Analyst | None, build_dirs: frozenset[str] = frozenset()
) -> list[Signal]:
    shown = f"{label}:{rel}"
    import_time = _is_import_time(rel, label, build_dirs)
    production = not (_NON_PRODUCTION_PARTS & set(rel.parts[:-1]))
    signals: list[Signal] = _text_signals(text, shown, production, analyst)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        if _FALLBACK_OBFUSCATED_EXEC.search(text):
            line = next((i for i, ln in enumerate(text.split("\n"), 1) if re.search(r"\b(?:exec|eval)\s*\(", ln)), 1)
            signals.append(_sig("obfuscated-exec", Severity.HIGH, "`exec`/`eval` runs a payload that is decoded at runtime (file did not parse; matched by pattern)", shown, line, text.split("\n")[line - 1]))
        return signals
    visitor = _Visitor(text, shown, import_time, whole_script=rel.name != "__init__.py")
    try:
        visitor.prepare(tree)
        visitor.visit(tree)
    except RecursionError:
        return signals
    return signals + visitor.finish()


_PTH_DANGER = re.compile(r"exec|eval|base64|subprocess|\.system\(|\.popen\(|urllib|socket|marshal|compile\(|ctypes|requests|http", re.IGNORECASE)


def _scan_pth(text: str, rel: Path, label: str) -> list[Signal]:
    """A .pth line that starts with `import` is executed at every interpreter start."""
    shown = f"{label}:{rel}"
    signals = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        if line.startswith(("import ", "import\t")) and _PTH_DANGER.search(line):
            signals.append(_sig("pth-startup-code", Severity.HIGH,
                                "a .pth file runs code every time Python starts, and this one does something other than add a path",
                                shown, lineno, line))
    return signals


def _scan_pyproject(text: str, label: str) -> list[Signal]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    build = data.get("build-system") or {}
    backend, in_tree = build.get("build-backend"), build.get("backend-path")
    out = []
    # Context, not a verdict: the code it runs is scanned with the install-time rules (see build_backend_dirs),
    # and a third-party backend is a dependency whose own release is what would be malicious.
    if in_tree:
        out.append(_sig("custom-build-backend", Severity.LOW,
                        "the build backend lives inside the package itself (backend-path) — its code runs during installation",
                        f"{label}:pyproject.toml", 1, f"backend-path = {in_tree!r}"))
    elif backend and backend not in _KNOWN_GOOD_BACKENDS:
        out.append(_sig("custom-build-backend", Severity.LOW,
                        f"unrecognized build backend '{backend}' — it runs during installation",
                        f"{label}:pyproject.toml", 1, f"build-backend = {backend!r}"))
    return out


def build_backend_dirs(root: Path) -> frozenset[str]:
    """Directories named by pyproject's backend-path: code there is the build backend."""
    path = root / "pyproject.toml"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace")) if path.is_file() else {}
    except (tomllib.TOMLDecodeError, OSError):
        return frozenset()
    entries = (data.get("build-system") or {}).get("backend-path") or []
    return frozenset(str(Path(e)) for e in entries if isinstance(e, str) and ".." not in Path(e).parts)


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if path.is_symlink() or not path.is_file() or _SKIP_DIR_PARTS & set(rel.parts):
            continue
        yield path, rel


def run_python_recon(targets: list[tuple[Path, str]], package_name: str, *, analyst: Analyst | None = None) -> list[Signal]:
    """`targets` is [(directory, "sdist"|"wheel"), ...]: every unpacked artifact of one release."""
    from malwhunter.recon.scanner import _BudgetedAnalyst  # shared per-package cap on Analyst calls

    if analyst is not None:
        analyst = _BudgetedAnalyst(analyst, 20)  # type: ignore[assignment]

    signals: list[Signal] = []
    skipped: list[str] = []
    import_time_by_label: dict[str, set[str]] = {}
    any_special_by_label: dict[str, set[str]] = {}
    for root, label in targets:
        build_dirs = build_backend_dirs(root)
        import_time_by_label[label] = set()
        any_special_by_label[label] = set()
        for path, rel in _iter_files(root):
            suffix = path.suffix.lower()
            if suffix not in (".py", ".pth", ".toml") and rel.name not in _IMPORT_TIME_NAMES:
                continue
            if suffix == ".toml" and rel.name != "pyproject.toml":
                continue
            try:
                if path.stat().st_size > _MAX_FILE_SIZE:
                    skipped.append(f"{label}:{rel}")
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if suffix == ".pth":
                signals.extend(_scan_pth(text, rel, label))
                import_time_by_label[label].add(rel.name)
                any_special_by_label[label].add(rel.name)
            elif suffix == ".toml":
                signals.extend(_scan_pyproject(text, label))
            else:
                signals.extend(_scan_py_file(text, rel, label, analyst, build_dirs))
                key = "/".join(rel.parts[-2:]) if rel.name == "__init__.py" else rel.name
                if rel.name == "__init__.py" or rel.name in _IMPORT_TIME_NAMES:
                    any_special_by_label[label].add(key)
                if _is_import_time(rel, label, build_dirs):
                    import_time_by_label[label].add(key)
                # only a file at the root of site-packages is imported at start-up; one buried inside a package is not
                if rel.name in ("sitecustomize.py", "usercustomize.py") and label == "wheel" and len(rel.parts) == 1:
                    signals.append(_sig("startup-hook-file", Severity.MEDIUM,
                                        f"ships {rel.name}, which Python imports at every start-up", f"{label}:{rel}", 1, rel.name))

    # code present in the wheel's import-time files but absent from the sdist is a way to ship something the source review never saw
    if "sdist" in import_time_by_label and "wheel" in import_time_by_label:
        missing = sorted(import_time_by_label["wheel"] - any_special_by_label["sdist"] - {"setup.py"})
        missing = [m for m in missing if not _GENERATED_NAMES.search(m)]
        code = [m for m in missing if m.endswith(".py")]
        pth = [m for m in missing if m.endswith(".pth")]
        # code that runs on import and never appeared in the source is the worrying case; a .pth is
        # routinely written by the build itself (setuptools' own distutils-precedence.pth), so only context
        for names, severity in ((code, Severity.MEDIUM), (pth, Severity.LOW)):
            if names:
                signals.append(_sig("wheel-sdist-mismatch", severity,
                                    "the wheel contains start-up/import-time files that the source distribution does not",
                                    "wheel", 1, ", ".join(names[:8])))
    if skipped:
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "scan-coverage-gap", "py-oversized"),
                source=SignalSource.RECON, category="scan-coverage-gap", severity=Severity.LOW,
                description=f"{len(skipped)} Python file(s) over {_MAX_FILE_SIZE // 1_000_000} MB were not scanned",
                evidence=[Evidence(excerpt=", ".join(skipped[:5]), detail="skipped: file too large for Recon")],
            )
        )
    return signals
