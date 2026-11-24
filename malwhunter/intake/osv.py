"""Known-malware lookup against the OSV database (osv.dev).

The OpenSSF malicious-packages project publishes every confirmed malicious
npm and PyPI release to OSV with an id that starts with `MAL-`. Checking that
list first is instant and has no false positives of our own: someone already
confirmed the package as malware. It never replaces our own analysis for
packages that are not listed; it only short-cuts the ones that are.

One batch request covers a whole lockfile. A failed lookup (offline, outage,
garbage answer) returns None, which callers treat as "unknown", never as
"not malicious".
"""
from __future__ import annotations

import os

import httpx

from malwhunter.dossier.model import Evidence, Severity, Signal, SignalSource, signal_id

# Overridable for a private mirror or tests; the default is the public OSV API.
OSV_API = os.environ.get("MALWHUNTER_OSV_API", "https://api.osv.dev").rstrip("/")
OSV_VULN_URL = "https://osv.dev/vulnerability/"

# OSV's querybatch accepts up to 1000 queries per request.
_BATCH_SIZE = 1000
_ECOSYSTEM_NAMES = {"npm": "npm", "pypi": "PyPI"}

PackageKey = tuple[str, str, str]  # (ecosystem, name, version), ecosystem as "npm" / "pypi"


def _key(ecosystem: str, name: str, version: str) -> PackageKey:
    # PyPI names are case- and separator-insensitive; npm names are already lower-case
    if ecosystem == "pypi":
        from malwhunter.intake.pypi_manifest import normalize_name

        name = normalize_name(name)
    return (ecosystem, name, version)


def lookup_known_malware(
    packages: list[PackageKey], *, client: httpx.Client | None = None, timeout: float = 20.0
) -> dict[PackageKey, list[str]] | None:
    """Returns {(ecosystem, name, version): [MAL-ids]} for every listed package
    that OSV reports as malicious. Packages with no MAL- entry are left out.
    Returns None when the lookup could not be completed."""
    keys = list(dict.fromkeys(_key(*p) for p in packages if p[0] in _ECOSYSTEM_NAMES))
    if not keys:
        return {}
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=False)
    hits: dict[PackageKey, list[str]] = {}
    try:
        for start in range(0, len(keys), _BATCH_SIZE):
            chunk = keys[start:start + _BATCH_SIZE]
            body = {
                "queries": [
                    {"package": {"name": name, "ecosystem": _ECOSYSTEM_NAMES[eco]}, "version": version}
                    for eco, name, version in chunk
                ]
            }
            resp = client.post(f"{OSV_API}/v1/querybatch", json=body)
            if resp.status_code != 200:
                return None
            results = resp.json().get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                return None
            for key, result in zip(chunk, results, strict=True):
                vulns = result.get("vulns") if isinstance(result, dict) else None
                ids = sorted(
                    v["id"] for v in (vulns or [])
                    if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"].startswith("MAL-")
                )
                if ids:
                    hits[key] = ids
    except (httpx.HTTPError, ValueError, AttributeError, TypeError):
        return None
    finally:
        if owns_client:
            client.close()
    return hits


def find_hit(hits: dict[PackageKey, list[str]] | None, ecosystem: str, name: str, version: str) -> list[str]:
    if not hits:
        return []
    return hits.get(_key(ecosystem, name, version), [])


def known_malware_signal(ecosystem: str, name: str, version: str, mal_ids: list[str]) -> Signal:
    spec = f"{name}=={version}" if ecosystem == "pypi" else f"{name}@{version}"
    return Signal(
        id=signal_id(SignalSource.RECON, "known-malware", f"{ecosystem}:{spec}"),
        source=SignalSource.RECON,
        category="known-malware",
        severity=Severity.CRITICAL,
        description=(
            f"{spec} is listed as malicious in the OSV database ({', '.join(mal_ids)}); "
            "it was not downloaded or run"
        ),
        evidence=[Evidence(excerpt=mal_id, detail=f"{OSV_VULN_URL}{mal_id}") for mal_id in mal_ids],
    )
