"""Fetches a release's files from PyPI and unpacks them safely.

A release can ship an sdist (source: where `setup.py` and build hooks run at
install time) and wheels (prebuilt: no install-time code, but the files
themselves, `__init__.py` and `.pth` files run when Python starts or imports
the package). Attackers use both, and have shipped a wheel that differs from
its sdist, so both are fetched when they exist: the sdist, plus one wheel
(a pure-Python one if there is one).

As with npm, every artifact is checked against the SHA-256 digest PyPI
publishes, size-capped, and extracted with traversal protection: the point of
the tool is handling adversarial archives.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import httpx

from malwhunter.intake.pypi_manifest import normalize_name
from malwhunter.intake.registry import (
    MAX_EXTRACTED_BYTES,
    MAX_EXTRACTED_MEMBERS,
    MAX_TARBALL_BYTES,
    PackageFetchError,
    PackageReputation,
    RegistryPresence,
)

PYPI_API = os.environ.get("MALWHUNTER_PYPI_API", "https://pypi.org/pypi")
PYPISTATS_API = os.environ.get("MALWHUNTER_PYPISTATS_API", "https://pypistats.org/api/packages")


@dataclass
class PyPIPackage:
    root: Path  # directory holding the unpacked artifacts (sdist/ and wheel/)
    sdist_dir: Path | None  # unpacked source tree, where setup.py / pyproject.toml live
    wheel_dir: Path | None  # unpacked wheel contents
    wheel_file: Path | None  # the wheel as downloaded (what pip installs)
    yanked: bool = False


def _json_url(name: str, version: str | None = None) -> str:
    base = f"{PYPI_API}/{normalize_name(name)}"
    return f"{base}/{version}/json" if version else f"{base}/json"


def fetch_release_metadata(name: str, version: str, *, client: httpx.Client | None = None) -> dict:
    owns = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        resp = client.get(_json_url(name, version))
        if resp.status_code != 200:
            raise PackageFetchError(f"{name}=={version}: PyPI returned {resp.status_code}", status_code=resp.status_code)
        return resp.json()
    finally:
        if owns:
            client.close()


def _pick_artifacts(files: list[dict]) -> tuple[dict | None, dict | None]:
    sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    pure = next((w for w in wheels if str(w.get("filename", "")).endswith("-none-any.whl")), None)
    linux = next((w for w in wheels if "manylinux" in str(w.get("filename", "")) and "x86_64" in str(w.get("filename", ""))), None)
    return sdist, pure or linux or (wheels[0] if wheels else None)


def _download(client: httpx.Client, entry: dict, dest: Path, label: str) -> Path:
    url = entry.get("url")
    if not url:
        raise PackageFetchError(f"{label}: no download URL")
    expected = (entry.get("digests") or {}).get("sha256")
    digest = hashlib.sha256()
    size = 0
    with client.stream("GET", url) as resp:
        if resp.status_code != 200:
            raise PackageFetchError(f"{label}: download returned {resp.status_code}", status_code=resp.status_code)
        with dest.open("wb") as fh:
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > MAX_TARBALL_BYTES:
                    raise PackageFetchError(f"{label}: file is larger than {MAX_TARBALL_BYTES // (1024 * 1024)} MB — refusing to download")
                digest.update(chunk)
                fh.write(chunk)
    if expected and not hmac.compare_digest(digest.hexdigest(), expected.lower()):
        raise PackageFetchError(f"{label}: download does not match the SHA-256 digest PyPI published")
    return dest


def _extract_zip(path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_EXTRACTED_MEMBERS or sum(i.file_size for i in infos) > MAX_EXTRACTED_BYTES:
            raise PackageFetchError("archive expands past the safety limit — refusing to extract")
        for info in infos:
            parts = PurePosixPath(info.filename).parts
            if info.filename.startswith(("/", "\\")) or ".." in parts or (parts and ":" in parts[0]):
                raise PackageFetchError(f"archive member escapes the extraction directory: {info.filename!r}")
            target = (root / info.filename).resolve()
            if root != target and root not in target.parents:
                raise PackageFetchError(f"archive member escapes the extraction directory: {info.filename!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # a symlink entry: never recreated
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as out:
                    out.write(src.read())


def _extract_sdist(path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(path):
        _extract_zip(path, dest)
    else:
        with tarfile.open(path) as tf:
            members = tf.getmembers()
            if len(members) > MAX_EXTRACTED_MEMBERS or sum(m.size for m in members) > MAX_EXTRACTED_BYTES:
                raise PackageFetchError("archive expands past the safety limit — refusing to extract")
            tf.extractall(dest, members=members, filter="data")
    entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
    # an sdist has a single top-level `name-version/` directory
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else dest


def fetch_package(name: str, version: str, workdir: Path, *, client: httpx.Client | None = None) -> PyPIPackage:
    owns = client is None
    client = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        meta = fetch_release_metadata(name, version, client=client)
        files = meta.get("urls") or []
        sdist, wheel = _pick_artifacts(files)
        if sdist is None and wheel is None:
            raise PackageFetchError(f"{name}=={version}: the release has no downloadable files")

        root = workdir / f"pypi-{normalize_name(name)}-{version}"
        root.mkdir(parents=True, exist_ok=True)
        sdist_dir = wheel_dir = wheel_file = None
        if sdist is not None:
            archive = _download(client, sdist, root / ("sdist-" + Path(str(sdist.get("filename", "sdist"))).name), f"{name}=={version} sdist")
            sdist_dir = _extract_sdist(archive, root / "sdist")
        if wheel is not None:
            wheel_file = _download(client, wheel, root / Path(str(wheel.get("filename", "package.whl"))).name, f"{name}=={version} wheel")
            wheel_dir = root / "wheel"
            _extract_zip(wheel_file, wheel_dir)
        yanked = any(bool(f.get("yanked")) for f in files)
        return PyPIPackage(root=root, sdist_dir=sdist_dir, wheel_dir=wheel_dir, wheel_file=wheel_file, yanked=yanked)
    except (tarfile.TarError, zipfile.BadZipFile) as exc:
        raise PackageFetchError(f"{name}=={version}: could not unpack the release: {exc}") from exc
    finally:
        if owns:
            client.close()


def check_pypi_presence(name: str, version: str, *, client: httpx.Client | None = None) -> RegistryPresence | None:
    """None means PyPI couldn't be asked; callers treat that as "unknown", never "doesn't exist"."""
    owns = client is None
    client = client or httpx.Client(timeout=10.0)
    url = _json_url(name)
    try:
        resp = client.get(url)
        if resp.status_code == 404:
            return RegistryPresence(url=url, name_exists=False, version_exists=False, security_holding=False)
        if resp.status_code != 200:
            return None
        releases = resp.json().get("releases") or {}
        return RegistryPresence(url=url, name_exists=True, version_exists=version in releases, security_holding=False)
    except (httpx.HTTPError, ValueError, AttributeError):
        return None
    finally:
        if owns:
            client.close()


def fetch_pypi_reputation(name: str, version: str, *, client: httpx.Client | None = None) -> PackageReputation:
    """How established a release is. Fields are None on any failure, and
    unknown reputation deliberately fails toward detonating."""
    owns = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        age_days = downloads = None
        try:
            resp = client.get(_json_url(name, version))
            if resp.status_code == 200:
                uploaded = [f.get("upload_time_iso_8601") for f in resp.json().get("urls", []) if f.get("upload_time_iso_8601")]
                if uploaded:
                    published = datetime.fromisoformat(min(uploaded).replace("Z", "+00:00"))
                    age_days = (datetime.now(UTC) - published).days
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        try:
            resp = client.get(f"{PYPISTATS_API}/{normalize_name(name)}/recent")
            if resp.status_code == 200:
                downloads = resp.json().get("data", {}).get("last_month")
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return PackageReputation(age_days=age_days, downloads_last_month=downloads)
    finally:
        if owns:
            client.close()
