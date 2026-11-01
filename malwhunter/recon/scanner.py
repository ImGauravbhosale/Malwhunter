"""Walks an extracted package and package.json against the catalog,
producing Signals. Every Signal is source=RECON and carries real
evidence — a file, a line, an excerpt — never a bare verdict.
"""
from __future__ import annotations

import re
from pathlib import Path

from malwhunter.analyst.session import Analyst
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.recon import ast_js
from malwhunter.recon.catalog import (
    BULK_ENV_ENUMERATION,
    CI_ENVIRONMENT_CHECK,
    COMMAND_EXEC_CALL,
    EVAL_FAMILY_CALL,
    EXFIL_CHANNEL_PATTERN,
    NAMED_CREDENTIAL_ENV_READ,
    NETWORK_PRIMITIVE,
    NPM_SELF_PUBLISH_PATTERN,
    NPMRC_TOKEN_TAMPERING,
    PACKED_STRING_CANDIDATE,
    SENSITIVE_READ,
    SHELL_ABUSE_PATTERN,
    TYPOSQUAT_ESTABLISHED_DOWNLOADS,
    closest_typosquat_target,
    has_computed_arg,
    looks_like_alphabet,
    shannon_entropy,
)

_SKIP_DIRS = {"node_modules", ".git"}
_SOURCE_EXTENSIONS = {".js", ".cjs", ".mjs"}
_MAX_FILE_SIZE = 2_000_000
_ENTROPY_THRESHOLD = 4.6  # bits/char — clears typical base64/packed content, not prose or ordinary code


def _iter_source_files(package_dir: Path):
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        # relative parts: an absolute path can contain a skipped directory
        # name (a scratch dir under a "node_modules" checkout) that says
        # nothing about the package itself
        if any(part in _SKIP_DIRS for part in path.relative_to(package_dir).parts):
            continue
        if path.suffix not in _SOURCE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        yield path


def scan_lifecycle_scripts(package_name: str, scripts: dict[str, str]) -> list[Signal]:
    signals = []
    for script_name, command in scripts.items():
        if SHELL_ABUSE_PATTERN.search(command):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "lifecycle-script-abuse", f"{package_name}:{script_name}"),
                    source=SignalSource.RECON,
                    category="lifecycle-script-abuse",
                    severity=Severity.HIGH,
                    description=f"`{script_name}` script pipes a remote or decoded payload into a shell",
                    evidence=[Evidence(excerpt=command, file="package.json", detail=f"scripts.{script_name}")],
                )
            )
    return signals


def scan_typosquat(package_name: str, ecosystem: str = "npm") -> list[Signal]:
    if ecosystem == "pypi":
        from malwhunter.recon.catalog import KNOWN_LEGIT_NEAR_PYPI, POPULAR_PYPI_NAMES

        target = closest_typosquat_target(package_name, POPULAR_PYPI_NAMES, KNOWN_LEGIT_NEAR_PYPI)
    else:
        target = closest_typosquat_target(package_name)
    if target is None:
        return []
    return [
        Signal(
            id=signal_id(SignalSource.RECON, "typosquat-candidate", package_name),
            source=SignalSource.RECON,
            category="typosquat-candidate",
            severity=Severity.MEDIUM,
            description=f"package name is suspiciously close to popular package '{target}'",
            evidence=[Evidence(excerpt=package_name, detail=f"edit-distance to '{target}'")],
        )
    ]


def drop_established_typosquats(signals: list[Signal], downloads_last_month: int | None) -> list[Signal]:
    """Name distance alone can't tell a squat from a real package that just
    has a similar name — `preact` is one edit from `react`. A package that
    is itself heavily downloaded isn't living off mistyped installs, so its
    typosquat signal is dropped. Unknown downloads (lookup failed) keeps the
    signal: failing toward flagging, same as the detonation pre-filter."""
    if downloads_last_month is None or downloads_last_month < TYPOSQUAT_ESTABLISHED_DOWNLOADS:
        return signals
    return [s for s in signals if s.category != "typosquat-candidate"]


_CHILD_PROCESS_IMPORT = re.compile(
    r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|"""
    r"""from\s+['"](?:node:)?child_process['"]"""
)


def _is_regexp_exec_false_positive(line: str, exec_match, file_imports_child_process: bool) -> bool:
    """`someRegex.exec(str)` is one of the most common idioms in all of
    JavaScript — RegExp.prototype.exec — and it's indistinguishable from
    `someHandle.exec(cmd)` by name alone. Found by live-benchmarking the
    scanner against 20 real, well-known packages: ms, chalk, axios,
    semver, and others all legitimately call `.exec()` on a regex, and
    every one of them was flagged HIGH severity for it, escalating their
    verdict to `suspicious`. Only "exec" collides with a legitimate
    built-in this way — spawn/execFile/execSync/spawnSync have no such
    namesake, so those stay flagged regardless of how they're called.

    A bare (non-dotted) `exec(...)` — the common
    `const { exec } = require('child_process')` destructuring pattern —
    is unaffected by this check. A dotted call is only suppressed when
    the file never imports child_process *at all* — checking the file,
    not the literal variable name, so a real child_process user aliased
    to `cp`/`childProcess`/anything else still gets flagged; only a file
    with no child_process import anywhere can be the regex case.
    """
    if exec_match.group(1) != "exec":
        return False
    preceding = line[: exec_match.start(1)].rstrip()
    if not preceding.endswith("."):
        return False
    return not file_imports_child_process


def _signals_from_ast(findings: list[ast_js.AstFinding], rel_path: str, text: str) -> list[Signal]:
    source_lines = text.split("\n")
    signals: list[Signal] = []
    seen: set[tuple[str, int]] = set()
    for f in findings:
        excerpt = source_lines[f.line - 1].strip()[:300] if 0 < f.line <= len(source_lines) else f.name
        if f.kind == "command-exec":
            category, description = "command-exec-computed-arg", f"`{f.name}` called with a computed (non-literal) command"
        elif f.kind == "eval":
            category, description = "eval-computed-arg", f"`{f.name}` called with a computed (non-literal) argument"
        elif f.kind == "shell-pipe":
            category = "command-exec-shell-pipe"
            description = f"`{f.name}` runs a command that pipes a remote or decoded payload into a shell"
        else:  # obfuscated-module-load
            category = "obfuscated-module-load"
            description = (
                f"loads the built-in module '{f.name}' from a string assembled at runtime — "
                "a way to hide it from scanners that nothing legitimate needs"
            )
        if (category, f.line) in seen:
            continue
        seen.add((category, f.line))
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, category, f"{rel_path}:{f.line}"),
                source=SignalSource.RECON,
                category=category,
                severity=Severity.HIGH,
                description=description,
                evidence=[Evidence(excerpt=excerpt, file=rel_path, line=f.line, detail="syntax-tree match" if not f.detail else f.detail)],
            )
        )
    return signals


def _scan_source_file(package_dir: Path, path: Path, analyst: Analyst | None) -> list[Signal]:
    signals: list[Signal] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return signals

    rel_path = str(path.relative_to(package_dir))
    lines = text.splitlines()
    file_imports_child_process = bool(_CHILD_PROCESS_IMPORT.search(text))
    # When the file parses, the syntax tree decides eval/exec findings (it knows
    # what `exec` is bound to). When it doesn't, the regex rules below run as before.
    ast_findings = ast_js.analyze(text)

    sensitive_evidence: Evidence | None = None
    network_evidence: Evidence | None = None
    ci_check_evidence: Evidence | None = None

    for lineno, line in enumerate(lines, start=1):
        eval_match = EVAL_FAMILY_CALL.search(line)
        if ast_findings is None and eval_match and has_computed_arg(eval_match):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "eval-computed-arg", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="eval-computed-arg",
                    severity=Severity.HIGH,
                    description=f"`{eval_match.group(1)}` called with a computed (non-literal) argument",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        exec_match = COMMAND_EXEC_CALL.search(line)
        if (
            ast_findings is None
            and exec_match
            and has_computed_arg(exec_match)
            and not _is_regexp_exec_false_positive(line, exec_match, file_imports_child_process)
        ):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "command-exec-computed-arg", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="command-exec-computed-arg",
                    severity=Severity.HIGH,
                    description=f"`{exec_match.group(1)}` called with a computed (non-literal) command",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        if EXFIL_CHANNEL_PATTERN.search(line):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "known-exfil-channel", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="known-exfil-channel",
                    severity=Severity.HIGH,
                    description="references a known exfiltration/C2 channel (webhook, paste service, bare IP, or .onion address) — rarely legitimate in a dependency",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        if NPM_SELF_PUBLISH_PATTERN.search(line) or NPMRC_TOKEN_TAMPERING.search(line):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "npm-self-publish-behavior", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="npm-self-publish-behavior",
                    severity=Severity.HIGH,
                    description="invokes `npm publish`/`unpublish` or tampers with .npmrc auth tokens — the signature of self-replicating npm worm packages. Note: a handful of legitimate release-automation tools (semantic-release, np, lerna) do this by design — corroboration still required before treating as malicious",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        if NAMED_CREDENTIAL_ENV_READ.search(line):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "named-credential-env-read", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="named-credential-env-read",
                    severity=Severity.HIGH,
                    description="reads a specific, well-known secret-shaped environment variable by name",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        if ci_check_evidence is None and CI_ENVIRONMENT_CHECK.search(line):
            ci_check_evidence = Evidence(excerpt=line.strip(), file=rel_path, line=lineno)

        if BULK_ENV_ENUMERATION.search(line):
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "bulk-env-enumeration", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="bulk-env-enumeration",
                    severity=Severity.HIGH,
                    description="enumerates the entire environment rather than reading a specific named variable",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

        if sensitive_evidence is None and SENSITIVE_READ.search(line):
            sensitive_evidence = Evidence(excerpt=line.strip(), file=rel_path, line=lineno)

        if network_evidence is None and NETWORK_PRIMITIVE.search(line):
            network_evidence = Evidence(excerpt=line.strip(), file=rel_path, line=lineno)

        blob_match = PACKED_STRING_CANDIDATE.search(line)
        if (
            blob_match
            and shannon_entropy(blob_match.group(1)) >= _ENTROPY_THRESHOLD
            and not looks_like_alphabet(blob_match.group(1))
        ):
            excerpt = blob_match.group(1)[:80] + "..."
            signals.append(
                Signal(
                    id=signal_id(SignalSource.RECON, "packed-string-blob", f"{rel_path}:{lineno}"),
                    source=SignalSource.RECON,
                    category="packed-string-blob",
                    severity=Severity.MEDIUM,
                    description="high-entropy string literal — possible packed/obfuscated payload",
                    evidence=[Evidence(excerpt=excerpt, file=rel_path, line=lineno)],
                )
            )
            # The catalog matched nothing more specific — this is exactly
            # the genuinely ambiguous case the Analyst is reserved for.
            if analyst is not None:
                from malwhunter.analyst.judge import judge_packed_blob

                signals.extend(judge_packed_blob(analyst, file=rel_path, line=lineno, excerpt=excerpt))

    if ast_findings:
        signals.extend(_signals_from_ast(ast_findings, rel_path, text))

    if sensitive_evidence is not None and network_evidence is not None:
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "sensitive-data-network-cooccurrence", rel_path),
                source=SignalSource.RECON,
                category="sensitive-data-network-cooccurrence",
                severity=Severity.HIGH,
                description="reads sensitive data and has a network-capable call in the same file",
                evidence=[sensitive_evidence, network_evidence],
            )
        )

    if ci_check_evidence is not None and network_evidence is not None:
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "ci-sandbox-evasion", rel_path),
                source=SignalSource.RECON,
                category="ci-sandbox-evasion",
                severity=Severity.HIGH,
                description="checks for a CI/sandbox environment and also has a network-capable call in the same file — a bare CI check alone is common and benign, but paired with network activity it matches malware that behaves differently under automated scanning",
                evidence=[ci_check_evidence, network_evidence],
            )
        )

    return signals


# Every packed-looking string costs two `claude` calls. A minified bundle can
# hold hundreds, so one package gets a fixed budget instead of an open tab.
_ANALYST_CALL_BUDGET = 20


class _BudgetedAnalyst:
    """Wraps an Analyst so one package can't run up an unbounded number of
    calls (each is a network round-trip, and sends package code off-box).
    Once spent, further questions come back as 'no opinion', never as a
    verdict either way."""

    def __init__(self, analyst: Analyst, budget: int) -> None:
        self._analyst = analyst
        self._remaining = budget

    def ask(self, *, system: str, prompt: str):
        from malwhunter.analyst.session import Verdict

        if self._remaining <= 0:
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error="analyst budget exhausted")
        self._remaining -= 1
        return self._analyst.ask(system=system, prompt=prompt)


def _bin_files(package_dir: Path, package_json: dict) -> list[Path]:
    """Files named in package.json's `bin` run as commands but often have no
    .js extension, so the extension filter alone would never read them."""
    bin_field = package_json.get("bin") if isinstance(package_json, dict) else None
    entries = [bin_field] if isinstance(bin_field, str) else list(bin_field.values()) if isinstance(bin_field, dict) else []
    root = package_dir.resolve()
    found: list[Path] = []
    for entry in entries:
        if not isinstance(entry, str):
            continue
        candidate = (package_dir / entry).resolve()
        if candidate.is_file() and root in candidate.parents:
            found.append(package_dir / candidate.relative_to(root))
    return found


def _coverage_gaps(package_dir: Path, package_json: dict) -> list[Signal]:
    """LOW-severity notes on what Recon did NOT read, so the report never
    implies a package was fully covered when part of it was skipped. LOW
    signals don't change a verdict — they are context for a reader."""
    signals: list[Signal] = []
    skipped: list[str] = []
    for path in sorted(package_dir.rglob("*")):
        try:
            if (
                path.is_file()
                and path.suffix in _SOURCE_EXTENSIONS
                and path.stat().st_size > _MAX_FILE_SIZE
                and not any(part in _SKIP_DIRS for part in path.relative_to(package_dir).parts)
            ):
                skipped.append(str(path.relative_to(package_dir)))
        except OSError:
            continue
    if skipped:
        shown = ", ".join(skipped[:5]) + (f" (+{len(skipped) - 5} more)" if len(skipped) > 5 else "")
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "scan-coverage-gap", "oversized"),
                source=SignalSource.RECON,
                category="scan-coverage-gap",
                severity=Severity.LOW,
                description=f"{len(skipped)} source file(s) over {_MAX_FILE_SIZE // 1_000_000} MB were not scanned",
                evidence=[Evidence(excerpt=shown, detail="skipped: file too large for Recon")],
            )
        )

    bundled = package_json.get("bundledDependencies", package_json.get("bundleDependencies")) if isinstance(package_json, dict) else None
    nested = package_dir / "node_modules"
    if bundled or (nested.is_dir() and any(nested.rglob("*.js"))):
        signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "scan-coverage-gap", "bundled"),
                source=SignalSource.RECON,
                category="scan-coverage-gap",
                severity=Severity.LOW,
                description="this package ships bundled dependencies (node_modules) that were not scanned",
                evidence=[Evidence(excerpt=str(bundled) if bundled else "node_modules/", detail="skipped: bundled dependencies")],
            )
        )
    return signals


def run_recon(
    package_dir: Path, package_name: str, package_json: dict, *, analyst: Analyst | None = None
) -> list[Signal]:
    from malwhunter.intake.manifest import get_lifecycle_scripts

    if analyst is not None:
        analyst = _BudgetedAnalyst(analyst, _ANALYST_CALL_BUDGET)  # type: ignore[assignment]

    signals: list[Signal] = []
    signals.extend(scan_lifecycle_scripts(package_name, get_lifecycle_scripts(package_json)))
    signals.extend(scan_typosquat(package_name))
    paths = list(_iter_source_files(package_dir))
    seen = {p.resolve() for p in paths}
    paths.extend(p for p in _bin_files(package_dir, package_json) if p.resolve() not in seen)
    for path in paths:
        signals.extend(_scan_source_file(package_dir, path, analyst))
    signals.extend(_coverage_gaps(package_dir, package_json))
    return signals
