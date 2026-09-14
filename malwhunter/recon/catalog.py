"""The static signal catalog — pattern definitions only, no scanning
logic here (see scanner.py). Kept separate so the catalog itself stays
easy to scan and extend without wading through file-walking code.
"""
from __future__ import annotations

import math
import re

SHELL_ABUSE_PATTERN = re.compile(
    r"(curl|wget)\s+\S+.*\|\s*(sh|bash)\b|"
    r"\bnode\s+-e\s|"
    r"base64\s+(-d|--decode).*\|\s*(sh|bash)\b",
    re.IGNORECASE,
)

EVAL_FAMILY_CALL = re.compile(r"\b(eval|Function|vm\.runInNewContext|vm\.runInContext)\s*\(\s*(.*)")
_LITERAL_ARG_START = re.compile(r"""^['"`]""")

SENSITIVE_READ = re.compile(
    r"process\.env(?!\s*\.\s*NODE_ENV\b)|"
    r"os\.homedir\(\)|"
    r"\.ssh[/\\]|\.npmrc\b|\.aws[/\\]credentials"
)

NETWORK_PRIMITIVE = re.compile(
    r"\bfetch\s*\(|\bhttps?\.request\s*\(|\bnet\.connect\s*\(|\bdns\.lookup\s*\(|"
    r"""require\(['"]https?['"]\)|require\(['"]node-fetch['"]\)"""
)

PACKED_STRING_CANDIDATE = re.compile(r"""['"`]([A-Za-z0-9+/=_\-]{60,})['"`]""")

# A small, deliberately short seed list of widely-used package names —
# good enough to catch obvious typosquats (extra/missing letter, swapped
# adjacent letters) without needing a live registry popularity feed for v1.
POPULAR_PACKAGE_NAMES = (
    "lodash", "react", "express", "axios", "chalk", "request", "commander",
    "async", "underscore", "moment", "debug", "colors", "left-pad",
    "webpack", "babel-core", "eslint", "jquery", "vue", "typescript",
)


def has_computed_arg(call_match: re.Match) -> bool:
    rest = call_match.group(2)
    return not bool(_LITERAL_ARG_START.match(rest))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def closest_typosquat_target(package_name: str, max_distance: int = 2) -> str | None:
    if package_name in POPULAR_PACKAGE_NAMES:
        return None
    for popular in POPULAR_PACKAGE_NAMES:
        if levenshtein(package_name, popular) <= max_distance:
            return popular
    return None
