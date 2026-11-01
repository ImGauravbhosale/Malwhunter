"""Delta scanning: remember the result for each exact `package@version`.

An npm version is immutable once published, so analysing it again gives the
same answer as long as MalwHunter's own rules haven't changed. The cache
key therefore includes a fingerprint of the rule files and the scan mode,
and entries expire after a week; a rule change, a different mode, or time
passing all force a fresh look. Only packages that were actually analysed
are stored; an UNSCANNED package is never cached, so a transient outage
can't turn into a remembered pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from malwhunter.dossier.model import Dossier

CACHE_TTL_SECONDS = 7 * 24 * 3600
_RULE_FILES = ("recon/catalog.py", "recon/scanner.py", "recon/python_scanner.py", "recon/ast_js.py", "dossier/verdict.py", "chamber/runner.py", "chamber/trust.py")


def rules_fingerprint() -> str:
    base = Path(__file__).parent
    digest = hashlib.sha256()
    for name in _RULE_FILES:
        try:
            digest.update(name.encode() + b"\0" + (base / name).read_bytes())
        except OSError:
            digest.update(b"missing:" + name.encode())
    return digest.hexdigest()[:16]


class DossierCache:
    def __init__(self, directory: Path, *, mode: str, ai: bool, fingerprint: str | None = None) -> None:
        self.directory = directory
        self._scope = f"{fingerprint or rules_fingerprint()}|{mode}|ai={int(ai)}"

    def _path(self, name: str, version: str, ecosystem: str = "npm") -> Path:
        key = hashlib.sha256(f"{self._scope}|{ecosystem}:{name}@{version}".encode()).hexdigest()
        return self.directory / f"{key}.json"

    def get(self, name: str, version: str, ecosystem: str = "npm", *, now: float | None = None) -> Dossier | None:
        path = self._path(name, version, ecosystem)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            if (now if now is not None else time.time()) - entry["stored_at"] > CACHE_TTL_SECONDS:
                return None
            if entry["scope"] != self._scope:
                return None
            dossier = Dossier.from_dict(entry["dossier"])
        except (OSError, ValueError, KeyError, TypeError):
            return None  # missing, corrupt or from an older format: just analyse again
        if (dossier.package, dossier.version, dossier.ecosystem.value) != (name, version, ecosystem):
            return None
        dossier.from_cache = True
        return dossier

    def put(self, dossier: Dossier) -> None:
        if dossier.scan_error is not None:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            entry = {"stored_at": time.time(), "scope": self._scope, "dossier": dossier.to_dict()}
            # write-then-rename so a crash or a parallel scan never leaves a half-written entry
            fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(entry, fh)
            os.replace(tmp, self._path(dossier.package, dossier.version, dossier.ecosystem.value))
        except OSError:
            pass  # a cache that can't be written is just a cache miss next time
