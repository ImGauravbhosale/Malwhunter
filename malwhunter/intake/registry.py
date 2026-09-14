"""Fetches package tarballs from the npm registry and extracts them
safely. Extraction safety is non-negotiable here specifically: the whole
point of this tool is handling adversarial tarballs, so a path-traversal
bug in extraction would be a real vulnerability, not just a bug.
"""
from __future__ import annotations

import tarfile
from pathlib import Path

import httpx

NPM_REGISTRY = "https://registry.npmjs.org"


class PackageFetchError(Exception):
    pass


def fetch_package_metadata(name: str, version: str, *, client: httpx.Client | None = None) -> dict:
    owns_client = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        resp = client.get(f"{NPM_REGISTRY}/{name}/{version}")
        if resp.status_code != 200:
            raise PackageFetchError(
                f"{name}@{version}: registry returned {resp.status_code}"
            )
        return resp.json()
    finally:
        if owns_client:
            client.close()


def fetch_tarball(
    name: str, version: str, dest_dir: Path, *, client: httpx.Client | None = None
) -> Path:
    metadata = fetch_package_metadata(name, version, client=client)
    tarball_url = metadata.get("dist", {}).get("tarball")
    if not tarball_url:
        raise PackageFetchError(f"{name}@{version}: no tarball URL in registry metadata")

    owns_client = client is None
    client = client or httpx.Client(timeout=30.0)
    try:
        resp = client.get(tarball_url)
        if resp.status_code != 200:
            raise PackageFetchError(f"{name}@{version}: tarball fetch returned {resp.status_code}")
        safe_name = name.replace("/", "__")
        tarball_path = dest_dir / f"{safe_name}-{version}.tgz"
        tarball_path.write_bytes(resp.content)
        return tarball_path
    finally:
        if owns_client:
            client.close()


def extract_tarball(tarball_path: Path, dest_dir: Path) -> Path:
    """Extracts an npm tarball (always has a single top-level `package/`
    directory) into dest_dir, refusing anything that would escape it —
    absolute paths, `..` traversal, symlinks pointing outside the
    extraction root. Uses tarfile's `data` filter (safe-by-default:
    strips dangerous metadata, refuses traversal) rather than trusting
    tarball content blindly."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path) as tf:
        tf.extractall(dest_dir, filter="data")
    extracted = dest_dir / "package"
    if not extracted.is_dir():
        raise PackageFetchError(f"unexpected tarball layout: no top-level package/ in {tarball_path}")
    return extracted
