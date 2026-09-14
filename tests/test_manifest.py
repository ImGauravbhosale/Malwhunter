import json
from pathlib import Path

from malwhunter.intake.manifest import (
    DependencyRef,
    get_lifecycle_scripts,
    read_package_json,
    resolve_dependencies,
)


def test_read_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0"}))
    data = read_package_json(tmp_path)
    assert data["name"] == "x"


def test_get_lifecycle_scripts_only_returns_known_names():
    pkg = {"scripts": {"postinstall": "node setup.js", "test": "jest", "preinstall": "echo hi"}}
    scripts = get_lifecycle_scripts(pkg)
    assert scripts == {"postinstall": "node setup.js", "preinstall": "echo hi"}


def test_get_lifecycle_scripts_empty_when_none_present():
    assert get_lifecycle_scripts({"scripts": {"test": "jest"}}) == {}
    assert get_lifecycle_scripts({}) == {}


def test_resolve_dependencies_from_lockfile_v3(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"left-pad": "^1.0.0"}}))
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
            "node_modules/@scope/util": {"version": "2.1.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    refs = resolve_dependencies(tmp_path)

    assert {(r.name, r.version) for r in refs} == {
        ("left-pad", "1.3.0"),
        ("@scope/util", "2.1.0"),
    }


def test_resolve_dependencies_falls_back_to_package_json_without_lockfile(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"left-pad": "1.3.0"}})
    )
    refs = resolve_dependencies(tmp_path)
    assert refs == [DependencyRef("left-pad", "1.3.0")]


def test_resolve_dependencies_dedupes_same_name_version(tmp_path: Path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/a/node_modules/left-pad": {"version": "1.3.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "package.json").write_text(json.dumps({"name": "app"}))

    refs = resolve_dependencies(tmp_path)
    assert len(refs) == 1
    assert (refs[0].name, refs[0].version) == ("left-pad", "1.3.0")
