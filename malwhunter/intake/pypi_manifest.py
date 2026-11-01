"""Resolves a Python project's dependencies to exact `name==version` pairs.

Lockfiles are preferred because they pin what is actually installed:
`uv.lock`, then `poetry.lock`, then `Pipfile.lock`. Only when there is no
lockfile does it fall back to `requirements*.txt`, where anything that is
not an exact `==` pin is passed on with its raw specifier as the "version",
so the scan reports it as UNSCANNED (with the reason) instead of silently
skipping it or analyzing a different release than the one that gets installed.

Dependencies that do not come from the public index (git URLs, local paths,
editable installs, the project itself) are skipped: there is no registry
artifact to fetch for them.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from malwhunter.intake.manifest import DependencyRef

ECOSYSTEM = "pypi"
_MAX_REQUIREMENTS_DEPTH = 3
_MAX_FILE_BYTES = 5 * 1024 * 1024


def normalize_name(name: str) -> str:
    """PEP 503 normalization: case-insensitive, runs of - _ . are one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


def has_python_manifest(project_dir: Path) -> bool:
    names = ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt")
    return any((project_dir / n).exists() for n in names) or any(project_dir.glob("requirements*.txt"))


def _read(path: Path) -> str:
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"{path.name} is larger than {_MAX_FILE_BYTES // (1024 * 1024)} MB")
    return path.read_text(encoding="utf-8", errors="replace")


def _dedupe(refs: list[DependencyRef]) -> list[DependencyRef]:
    seen: dict[tuple[str, str], DependencyRef] = {}
    for ref in refs:
        seen[(ref.name, ref.version)] = ref
    return sorted(seen.values(), key=lambda r: (r.name, r.version))


def _from_toml_packages(text: str, *, registry_check) -> list[DependencyRef]:
    data = tomllib.loads(text)
    refs = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version or not registry_check(pkg.get("source")):
            continue
        refs.append(DependencyRef(name=normalize_name(name), version=str(version), ecosystem=ECOSYSTEM))
    return refs


def _uv_from_registry(source) -> bool:
    # uv: { registry = "https://pypi.org/simple" } — editable / virtual / git / path / url are not downloadable
    return isinstance(source, dict) and "registry" in source


def _poetry_from_registry(source) -> bool:
    # poetry: no `source` table means the default index; git / directory / file / url are not
    return source is None or (isinstance(source, dict) and source.get("type") in ("legacy", "pypi"))


def _from_pipfile_lock(text: str) -> list[DependencyRef]:
    data = json.loads(text)
    refs = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = (info or {}).get("version", "")
            if not isinstance(version, str) or not version.startswith("=="):
                continue  # git / editable / path entries carry no version
            refs.append(DependencyRef(name=normalize_name(name), version=version[2:], ecosystem=ECOSYSTEM))
    return refs


_REQ_LINE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>.*)$")


def _from_requirements(path: Path, depth: int = 0) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    # join backslash continuations (used for --hash lines) before reading line by line
    text = re.sub(r"\\\s*\n", " ", _read(path))
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-r=", "--requirement=")):
            target = re.split(r"[ =]", line, maxsplit=1)[1].strip()
            nested = (path.parent / target).resolve()
            if depth < _MAX_REQUIREMENTS_DEPTH and nested.is_file() and path.parent.resolve() in nested.parents:
                refs.extend(_from_requirements(nested, depth + 1))
            continue
        if line.startswith("-") or "://" in line or line.startswith((".", "/", "git+")):
            continue  # options, -e editable installs, URLs and local paths: no registry artifact
        line = line.split(";", 1)[0].strip()  # environment markers
        line = re.split(r"\s--hash", line, maxsplit=1)[0].strip()
        m = _REQ_LINE.match(line)
        if not m:
            continue
        spec = m.group("spec").replace(" ", "")
        exact = re.fullmatch(r"===?([A-Za-z0-9._+!-]+)", spec)
        refs.append(
            DependencyRef(
                name=normalize_name(m.group("name")),
                version=exact.group(1) if exact else (spec or "unpinned"),
                ecosystem=ECOSYSTEM,
            )
        )
    return refs


def resolve_python_dependencies(project_dir: Path) -> list[DependencyRef]:
    for filename, parse in (
        ("uv.lock", lambda t: _from_toml_packages(t, registry_check=_uv_from_registry)),
        ("poetry.lock", lambda t: _from_toml_packages(t, registry_check=_poetry_from_registry)),
        ("Pipfile.lock", _from_pipfile_lock),
    ):
        path = project_dir / filename
        if path.exists():
            return _dedupe(parse(_read(path)))

    refs: list[DependencyRef] = []
    candidates = [project_dir / "requirements.txt"] if (project_dir / "requirements.txt").exists() else []
    candidates += sorted(p for p in project_dir.glob("requirements*.txt") if p.name != "requirements.txt")
    for path in candidates:
        refs.extend(_from_requirements(path))
    return _dedupe(refs)
