"""Fetches package tarballs from the npm registry and extracts them
safely. Extraction safety is non-negotiable here specifically: the whole
point of this tool is handling adversarial tarballs, so a path-traversal
bug in extraction would be a real vulnerability, not just a bug.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

# Overridable so the tool can be pointed at a private mirror or the local test registry
# in the sample project; the defaults are the public npm services.
NPM_REGISTRY = os.environ.get("MALWHUNTER_NPM_REGISTRY", "https://registry.npmjs.org").rstrip("/")
NPM_DOWNLOADS_API = os.environ.get(
    "MALWHUNTER_NPM_DOWNLOADS_API", "https://api.npmjs.org/downloads/point/last-month"
).rstrip("/")


# A real npm package is almost never above a few MB. These caps exist so a
# hostile tarball (or a registry mirror gone wrong) can't exhaust memory or
# disk on the machine doing the scanning.
MAX_TARBALL_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_EXTRACTED_MEMBERS = 50_000


class PackageFetchError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        # The registry's HTTP status when that's what failed — lets callers
        # tell "this version doesn't exist" (404) apart from an outage.
        self.status_code = status_code


# npm's security team replaces a package it takes down for malware with a
# placeholder published as 0.0.1-security (0.0.2-security, ...), described
# as a "security holding package".
_SECURITY_HOLDING_VERSION = re.compile(r"^0\.0\.\d+-security$")


@dataclass(frozen=True)
class RegistryPresence:
    """What the registry says about a package name, independent of any
    one version. Only looked up after a version fails to download, to
    explain *why* — so the common path costs no extra request."""

    url: str
    name_exists: bool
    version_exists: bool
    security_holding: bool


def check_registry_presence(
    name: str, version: str, *, client: httpx.Client | None = None
) -> RegistryPresence | None:
    """None means the registry couldn't be asked (network error, 5xx,
    garbage response) — callers must treat that as "unknown", never as
    "doesn't exist"."""
    owns_client = client is None
    client = client or httpx.Client(timeout=10.0)
    # scoped names go to the registry as @scope%2fname
    url = f"{NPM_REGISTRY}/{name.replace('/', '%2f')}"
    try:
        # the abbreviated document: just versions and dist-tags, far smaller
        # than the full packument for packages with thousands of releases
        resp = client.get(url, headers={"Accept": "application/vnd.npm.install-v1+json"})
        if resp.status_code == 404:
            return RegistryPresence(url=url, name_exists=False, version_exists=False, security_holding=False)
        if resp.status_code != 200:
            return None
        doc = resp.json()
        latest = (doc.get("dist-tags") or {}).get("latest", "")
        return RegistryPresence(
            url=url,
            name_exists=True,
            version_exists=version in (doc.get("versions") or {}),
            security_holding=bool(_SECURITY_HOLDING_VERSION.match(latest)),
        )
    except (httpx.HTTPError, ValueError, AttributeError):
        return None
    finally:
        if owns_client:
            client.close()


@dataclass
class PackageReputation:
    """Cheap, registry-only signal about how established a package is —
    used to decide whether a package is worth the cost of a full
    Detonation pass. Fields are None on any lookup failure (network
    error, missing data) rather than raising: a flaky reputation lookup
    should never block a scan, and "unknown" reputation deliberately
    fails toward detonating, not skipping."""

    age_days: int | None
    downloads_last_month: int | None


def fetch_package_reputation(name: str, version: str, *, client: httpx.Client | None = None) -> PackageReputation:
    owns_client = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        age_days = _fetch_version_age_days(name, version, client)
        downloads = _fetch_downloads_last_month(name, client)
        return PackageReputation(age_days=age_days, downloads_last_month=downloads)
    finally:
        if owns_client:
            client.close()


def _fetch_version_age_days(name: str, version: str, client: httpx.Client) -> int | None:
    try:
        resp = client.get(f"{NPM_REGISTRY}/{name}")
        if resp.status_code != 200:
            return None
        published_at = resp.json().get("time", {}).get(version)
        if not published_at:
            return None
        published = _parse_iso8601(published_at)
        if published is None:
            return None
        return (datetime.now(UTC) - published).days
    except (httpx.HTTPError, ValueError, KeyError):
        return None


def _parse_iso8601(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _fetch_downloads_last_month(name: str, client: httpx.Client) -> int | None:
    try:
        resp = client.get(f"{NPM_DOWNLOADS_API}/{name}")
        if resp.status_code != 200:
            return None
        return resp.json().get("downloads")
    except (httpx.HTTPError, ValueError, KeyError):
        return None


def fetch_package_metadata(name: str, version: str, *, client: httpx.Client | None = None) -> dict:
    owns_client = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        resp = client.get(f"{NPM_REGISTRY}/{name}/{version}")
        if resp.status_code != 200:
            raise PackageFetchError(
                f"{name}@{version}: registry returned {resp.status_code}", status_code=resp.status_code
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
        with client.stream("GET", tarball_url) as resp:
            if resp.status_code != 200:
                raise PackageFetchError(f"{name}@{version}: tarball fetch returned {resp.status_code}")
            content = bytearray()
            for chunk in resp.iter_bytes():
                content.extend(chunk)
                if len(content) > MAX_TARBALL_BYTES:
                    raise PackageFetchError(
                        f"{name}@{version}: tarball is larger than {MAX_TARBALL_BYTES // (1024 * 1024)} MB — refusing to download"
                    )
        _verify_integrity(name, version, bytes(content), metadata.get("dist", {}))
        safe_name = name.replace("/", "__")
        tarball_path = dest_dir / f"{safe_name}-{version}.tgz"
        tarball_path.write_bytes(content)
        return tarball_path
    finally:
        if owns_client:
            client.close()


def _verify_integrity(name: str, version: str, content: bytes, dist: dict) -> None:
    """Checks the downloaded bytes against the digest the registry published
    for this exact version, so a tampered or substituted download (a bad
    mirror, a CDN hiccup, a MITM) is never analyzed as if it were the real
    package. Metadata with no digest at all is accepted — older packages."""
    integrity = dist.get("integrity")
    if isinstance(integrity, str) and integrity:
        for entry in integrity.split():
            algo, _, expected_b64 = entry.partition("-")
            if algo not in ("sha512", "sha384", "sha256"):
                continue
            actual = base64.b64encode(hashlib.new(algo, content).digest()).decode()
            if hmac.compare_digest(actual, expected_b64):
                return
            raise PackageFetchError(f"{name}@{version}: tarball does not match the registry's {algo} integrity digest")
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and shasum:
        if not hmac.compare_digest(hashlib.sha1(content, usedforsecurity=False).hexdigest(), shasum.lower()):
            raise PackageFetchError(f"{name}@{version}: tarball does not match the registry's sha1 shasum")


def extract_tarball(tarball_path: Path, dest_dir: Path) -> Path:
    """Extracts an npm tarball (always has a single top-level `package/`
    directory) into dest_dir, refusing anything that would escape it —
    absolute paths, `..` traversal, symlinks pointing outside the
    extraction root. Uses tarfile's `data` filter (safe-by-default:
    strips dangerous metadata, refuses traversal) rather than trusting
    tarball content blindly."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path) as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACTED_MEMBERS or sum(m.size for m in members) > MAX_EXTRACTED_BYTES:
            raise PackageFetchError(
                f"tarball expands past the safety limit ({MAX_EXTRACTED_MEMBERS} files / "
                f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB) — refusing to extract"
            )
        tf.extractall(dest_dir, members=members, filter="data")
    extracted = dest_dir / "package"
    if not extracted.is_dir():
        raise PackageFetchError(f"unexpected tarball layout: no top-level package/ in {tarball_path}")
    return extracted
