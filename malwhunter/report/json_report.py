from __future__ import annotations

import json

from malwhunter.dossier.model import Dossier

SCHEMA_VERSION = 1


def dossiers_to_dict(dossiers: list[Dossier]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "package_count": len(dossiers),
        "dossiers": [d.to_dict() for d in dossiers],
    }


def dossiers_to_json_str(dossiers: list[Dossier]) -> str:
    return json.dumps(dossiers_to_dict(dossiers), indent=2)


def write_json_report(dossiers: list[Dossier], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(dossiers_to_dict(dossiers), fh, indent=2)
