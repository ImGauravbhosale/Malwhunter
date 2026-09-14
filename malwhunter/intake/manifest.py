"""Reads package.json and an npm lockfile to resolve the exact set of
package@version pairs a project depends on. Lockfile-driven (not
package.json's loose semver ranges) so every package analyzed is the
exact version that would actually be installed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

LIFECYCLE_SCRIPT_NAMES = ("preinstall", "install", "postinstall")


@dataclass(frozen=True)
class DependencyRef:
    name: str
    version: str


def read_package_json(project_dir: Path) -> dict:
    path = project_dir / "package.json"
    return json.loads(path.read_text(encoding="utf-8"))


def get_lifecycle_scripts(package_json: dict) -> dict[str, str]:
    scripts = package_json.get("scripts", {})
    return {name: scripts[name] for name in LIFECYCLE_SCRIPT_NAMES if name in scripts}


def _name_from_node_modules_path(path: str) -> str | None:
    # "node_modules/foo" -> "foo"; "node_modules/@scope/foo" -> "@scope/foo";
    # "node_modules/a/node_modules/b" (nested/deduped dep) -> "b"
    marker = "node_modules/"
    idx = path.rfind(marker)
    if idx == -1:
        return None
    tail = path[idx + len(marker):]
    return tail or None


def resolve_dependencies(project_dir: Path) -> list[DependencyRef]:
    """Reads package-lock.json (lockfileVersion 2 or 3's flat `packages`
    map) for the exact resolved version of every package in the tree.
    Falls back to package.json's declared ranges (loose — not exact
    resolutions) if no lockfile is present."""
    lock_path = project_dir / "package-lock.json"
    if lock_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        packages = lock.get("packages")
        if packages is not None:
            refs: list[DependencyRef] = []
            for path, info in packages.items():
                if path == "":
                    continue  # the root project itself
                name = info.get("name") or _name_from_node_modules_path(path)
                version = info.get("version")
                if name and version:
                    refs.append(DependencyRef(name=name, version=version))
            # de-dupe (a package can appear multiple times if nested at
            # different depths, usually pinned to the same version)
            seen: dict[tuple[str, str], DependencyRef] = {}
            for ref in refs:
                seen[(ref.name, ref.version)] = ref
            return sorted(seen.values(), key=lambda r: (r.name, r.version))

    package_json = read_package_json(project_dir)
    deps = {}
    deps.update(package_json.get("dependencies", {}))
    deps.update(package_json.get("devDependencies", {}))
    return sorted(
        (DependencyRef(name=name, version=version) for name, version in deps.items()),
        key=lambda r: (r.name, r.version),
    )
