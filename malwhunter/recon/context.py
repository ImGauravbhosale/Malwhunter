"""Captures the source lines around each piece of Recon evidence while the
unpacked package still exists on disk. The scan deletes its working
directory when it finishes, so anything a later reader (a human, or an AI
agent given the review prompt) needs to judge a finding in context has to
be taken now.
"""
from __future__ import annotations

from pathlib import Path

from malwhunter.dossier.model import Signal

_LINES_BEFORE = 6
_LINES_AFTER = 6
_MAX_LINE_CHARS = 400  # minified files have single lines of megabytes
_MAX_CONTEXTS_PER_PACKAGE = 40


def context_key(file: str, line: int) -> str:
    return f"{file}:{line}"


def collect_code_context(
    package_dir: Path, signals: list[Signal], *, labelled_roots: dict[str, Path] | None = None
) -> dict[str, str]:
    """Maps "file:line" to a numbered excerpt of the surrounding source, for
    every evidence item that points at a location in the package.
    `labelled_roots` is for releases unpacked into several trees (a PyPI
    sdist and wheel): evidence paths there look like "sdist:setup.py"."""
    root = package_dir.resolve()
    roots = {label: path.resolve() for label, path in (labelled_roots or {}).items()}
    contexts: dict[str, str] = {}
    cache: dict[str, list[str] | None] = {}

    for signal in signals:
        for evidence in signal.evidence:
            if not evidence.file or not evidence.line:
                continue
            key = context_key(evidence.file, evidence.line)
            if key in contexts:
                continue
            if len(contexts) >= _MAX_CONTEXTS_PER_PACKAGE:
                return contexts

            if evidence.file not in cache:
                label, _, rest = evidence.file.partition(":")
                cache[evidence.file] = (
                    _read_lines(roots[label], rest) if label in roots else _read_lines(root, evidence.file)
                )
            lines = cache[evidence.file]
            if lines is None:
                continue

            first = max(evidence.line - _LINES_BEFORE, 1)
            last = min(evidence.line + _LINES_AFTER, len(lines))
            contexts[key] = "\n".join(
                f"{n:>5}{'>' if n == evidence.line else ' '}| {lines[n - 1][:_MAX_LINE_CHARS]}"
                for n in range(first, last + 1)
            )
    return contexts


def _read_lines(root: Path, relative: str) -> list[str] | None:
    path = (root / relative).resolve()
    if root not in path.parents:  # evidence paths come from our own scan, but never trust a path blindly
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
