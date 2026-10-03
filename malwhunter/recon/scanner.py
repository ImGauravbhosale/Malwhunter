"""Walks an extracted package and package.json against the catalog,
producing Signals. Every Signal is source=RECON and carries real
evidence — a file, a line, an excerpt — never a bare verdict.
"""
from __future__ import annotations

import re
from pathlib import Path

from malwhunter.analyst.session import Analyst
from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id
from malwhunter.recon.catalog import (
    BULK_ENV_ENUMERATION,
    COMMAND_EXEC_CALL,
    EVAL_FAMILY_CALL,
    EXFIL_CHANNEL_PATTERN,
    NETWORK_PRIMITIVE,
    PACKED_STRING_CANDIDATE,
    SENSITIVE_READ,
    SHELL_ABUSE_PATTERN,
    closest_typosquat_target,
    has_computed_arg,
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
        if any(part in _SKIP_DIRS for part in path.parts):
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


def scan_typosquat(package_name: str) -> list[Signal]:
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


def _scan_source_file(package_dir: Path, path: Path, analyst: Analyst | None) -> list[Signal]:
    signals: list[Signal] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return signals

    rel_path = str(path.relative_to(package_dir))
    lines = text.splitlines()
    file_imports_child_process = bool(_CHILD_PROCESS_IMPORT.search(text))

    sensitive_evidence: Evidence | None = None
    network_evidence: Evidence | None = None

    for lineno, line in enumerate(lines, start=1):
        eval_match = EVAL_FAMILY_CALL.search(line)
        if eval_match and has_computed_arg(eval_match):
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
            exec_match
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
                    description="references a Discord webhook or Telegram bot API endpoint — a common exfiltration channel in npm supply-chain malware",
                    evidence=[Evidence(excerpt=line.strip(), file=rel_path, line=lineno)],
                )
            )

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
        if blob_match and shannon_entropy(blob_match.group(1)) >= _ENTROPY_THRESHOLD:
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

    return signals


def run_recon(
    package_dir: Path, package_name: str, package_json: dict, *, analyst: Analyst | None = None
) -> list[Signal]:
    from malwhunter.intake.manifest import get_lifecycle_scripts

    signals: list[Signal] = []
    signals.extend(scan_lifecycle_scripts(package_name, get_lifecycle_scripts(package_json)))
    signals.extend(scan_typosquat(package_name))
    for path in _iter_source_files(package_dir):
        signals.extend(_scan_source_file(package_dir, path, analyst))
    return signals
