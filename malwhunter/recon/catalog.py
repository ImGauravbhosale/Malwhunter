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

# child_process's exec family is the more common real-world RCE vector —
# eval/Function get the attention, but `exec(cmd)` with a computed `cmd`
# is the same "computed argument reaches an interpreter" shape.
COMMAND_EXEC_CALL = re.compile(
    r"\b(?:child_process\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(.*)"
)

SENSITIVE_READ = re.compile(
    r"process\.env(?!\s*\.\s*NODE_ENV\b)|"
    r"os\.homedir\(\)|"
    r"\.ssh[/\\]|\.npmrc\b|\.aws[/\\]credentials"
)

# Reading one named env var is normal. Enumerating *all* of them at once
# is what credential-harvesting code does — a distinct, stronger signal
# than SENSITIVE_READ alone (seen in real npm malware, e.g. MAL-2026-7003
# / searchresults@999.0.0, which dumped the full environment looking for
# AWS/GitHub/Docker credentials rather than reading anything by name).
BULK_ENV_ENUMERATION = re.compile(
    r"Object\.(keys|entries|values)\(\s*process\.env\s*\)|"
    r"JSON\.stringify\(\s*process\.env\s*\)|"
    r"for\s*\([^)]*\bin\b\s*process\.env\s*\)"
)

NETWORK_PRIMITIVE = re.compile(
    r"\bfetch\s*\(|\bhttps?\.request\s*\(|\bnet\.connect\s*\(|\bdns\.lookup\s*\(|"
    r"""require\(['"]https?['"]\)|require\(['"]node-fetch['"]\)"""
)

# Discord/Telegram/Slack webhooks, paste services, and generic "catch
# whatever gets sent here" endpoints (webhook.site, requestbin) are all
# legitimate for an actual bot/integration package, but are extremely
# well-documented exfiltration/C2 channels in npm supply-chain malware —
# posting stolen data to someone else's API needs no C2 infrastructure of
# the attacker's own. A bare IP-literal URL or a .onion address is a
# distinct, even stronger signal: real packages essentially never hardcode
# a raw IP or a Tor hidden service as an endpoint.
EXFIL_CHANNEL_PATTERN = re.compile(
    r"discord(?:app)?\.com/api/webhooks/|"
    r"api\.telegram\.org/bot|"
    r"hooks\.slack\.com/services/|"
    r"(?:pastebin\.com/raw/|hastebin\.com/raw/|paste\.ee/r/)|"
    r"(?:webhook\.site/|requestbin\.com/)|"
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/|"
    r"\.onion\b",
    re.IGNORECASE,
)

# No legitimate dependency needs to publish or unpublish *itself* — this is
# the signature of the self-replicating "worm" packages seen in real 2025
# npm incidents, which modify the victim's own .npmrc auth token and then
# run `npm publish` to spread to every package the victim maintains.
NPM_SELF_PUBLISH_PATTERN = re.compile(r"\bnpm\s+(?:publish|unpublish)\b", re.IGNORECASE)
NPMRC_TOKEN_TAMPERING = re.compile(
    r"\.npmrc[^\n]{0,80}(_authToken|authToken)|(_authToken|authToken)[^\n]{0,80}\.npmrc",
    re.IGNORECASE,
)

# Checking for a CI/sandbox environment is normal in plenty of legitimate
# CLIs (skip interactive prompts, disable telemetry) — a bare check alone
# would be noisy, the same mistake already found and fixed for exec(). Kept
# deliberately separate from NETWORK_PRIMITIVE/COMMAND_EXEC_CALL so the
# scanner can require both in the same file before treating it as evasion
# (a package fingerprinting "am I being scanned?" and also phoning home or
# shelling out is a much rarer, much stronger combination).
CI_ENVIRONMENT_CHECK = re.compile(
    r"process\.env\.(CI|GITHUB_ACTIONS|CONTINUOUS_INTEGRATION|TRAVIS|CIRCLECI|GITLAB_CI)\b"
)

# Reading one named env var is normal — SENSITIVE_READ's generic
# process.env match is deliberately broad and only dangerous when paired
# with network activity. This is the precise version: a small, well-known
# list of secret-shaped variable names that a package has essentially no
# legitimate reason to read by name.
NAMED_CREDENTIAL_ENV_READ = re.compile(
    r"process\.env\.(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|"
    r"GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NPM_AUTH_TOKEN|STRIPE_SECRET_KEY|"
    r"DATABASE_URL|PRIVATE_KEY|SSH_PRIVATE_KEY|SLACK_TOKEN|DOCKER_PASSWORD|"
    r"DOCKERHUB_TOKEN|NGROK_AUTHTOKEN)\b"
)

PACKED_STRING_CANDIDATE = re.compile(r"""['"`]([A-Za-z0-9+/=_\-]{60,})['"`]""")

# A small, deliberately short seed list of widely-used package names —
# good enough to catch obvious typosquats (extra/missing letter, swapped
# adjacent letters) without needing a live registry popularity feed for v1.
POPULAR_PACKAGE_NAMES = (
    "lodash", "react", "express", "axios", "chalk", "request", "commander",
    "async", "underscore", "moment", "debug", "colors", "left-pad",
    "webpack", "babel-core", "eslint", "jquery", "vue", "typescript",
    "cross-env", "babel-cli", "electron", "mongoose", "dotenv", "node-fetch",
)

# Real, widely-used packages that happen to sit one edit away from a name
# above. Edit distance alone can't tell `vuex` (Vue's official store)
# from a squat on `vue` — this is the offline fallback for that; online,
# the package's own download count settles it (see
# TYPOSQUAT_ESTABLISHED_DOWNLOADS). Found by benchmarking the check
# against ~170 popular real package names.
KNOWN_LEGIT_NEAR_NAMES = frozenset({"vuex", "preact", "color", "chai", "cors", "vite"})

# A package with this many monthly downloads is established in its own
# right — real typosquats live off mistyped installs and stay tiny.
TYPOSQUAT_ESTABLISHED_DOWNLOADS = 100_000

# "<popular>.js" / "<popular>-js" / "<popular>js" — dressing up a popular
# name with a JS-ish suffix is a squat technique edit distance misses once
# the suffix is long (`cross-env.js` is 3 edits from `cross-env`).
_JS_SUFFIX = re.compile(r"[.\-_]?js$")
_SEPARATORS = re.compile(r"[.\-_]")


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


def osa_distance(a: str, b: str) -> int:
    """Edit distance where swapping two adjacent characters costs 1, not 2
    (optimal string alignment) — `lodahs` is one slip of the fingers away
    from `lodash`, and should score like one."""
    if a == b:
        return 0
    rows = [list(range(len(b) + 1))]
    for i, ca in enumerate(a, start=1):
        row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def _max_typo_distance(popular: str) -> int:
    # Two edits on a short name reaches far too much of the namespace:
    # `pug`, `yup` and `vite` are all two edits from `vue`, `cypress` two
    # from `express`. One edit is a typo; two only for longer names.
    return 1 if len(popular) <= 8 else 2


def closest_typosquat_target(package_name: str) -> str | None:
    name = package_name.lower()
    if name in POPULAR_PACKAGE_NAMES or name in KNOWN_LEGIT_NEAR_NAMES:
        return None
    unsuffixed = _JS_SUFFIX.sub("", name)
    for popular in POPULAR_PACKAGE_NAMES:
        if osa_distance(name, popular) <= _max_typo_distance(popular):
            return popular
        if unsuffixed != name and unsuffixed == popular:
            return popular
        if _SEPARATORS.sub("", name) == _SEPARATORS.sub("", popular):
            return popular  # crossenv / cross_env vs cross-env
    return None
