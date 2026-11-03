"""Property-based (fuzz) tests: feed the parsers and report writers arbitrary
input and check they never crash or let attacker-controlled text through.
Package contents, lockfiles and ignore files all come from outside, so
these are the places where unexpected input must fail cleanly."""
from __future__ import annotations

import base64
import csv
import io
import json
import tempfile
from pathlib import Path
from urllib.parse import quote

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from malwhunter.dossier.model import Dossier, Evidence, Severity, Signal, SignalSource
from malwhunter.intake.ignore import IgnoreFileError, load_ignore_rules
from malwhunter.intake.manifest import resolve_dependencies
from malwhunter.report.csv_report import dossiers_to_csv_str
from malwhunter.report.sanitize import sanitize_text
from malwhunter.report.sarif import dossiers_to_sarif_str
from malwhunter.wiretap.canary import find_leaked_canaries

FUZZ = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
CANARY = "canary_0123456789abcdef0123456789abcdef"

# any JSON value, nested
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4),
    max_leaves=20,
)


@FUZZ
@given(st.text())
def test_sanitize_text_leaves_no_control_characters(text):
    cleaned = sanitize_text(text)
    assert "\x1b" not in cleaned
    assert not any(ord(c) < 32 and c not in "\t\n" for c in cleaned)


@FUZZ
@given(st.text(max_size=40), st.text(max_size=40))
def test_a_canary_is_found_however_it_is_wrapped_or_encoded(prefix, suffix):
    blob = (prefix + CANARY + suffix).encode()
    for haystack in (
        blob.decode(),
        base64.b64encode(blob).decode(),
        base64.urlsafe_b64encode(blob).decode(),
        blob.hex(),
        quote(blob.decode(), safe=""),
    ):
        assert find_leaked_canaries(haystack, {"X": CANARY}) == ["X"]


@FUZZ
@given(st.text())
def test_find_leaked_canaries_never_crashes(text):
    assert find_leaked_canaries(text, {"X": CANARY}) in ([], ["X"])


@FUZZ
@given(st.text())
def test_ignore_file_is_parsed_or_rejected_cleanly(content):
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / ".MHignore").write_text(content, encoding="utf-8")
        try:
            rules = load_ignore_rules(Path(tmp))
        except IgnoreFileError:
            return
        assert isinstance(rules, list)


@FUZZ
@given(json_values)
def test_ignore_file_with_any_json_is_parsed_or_rejected_cleanly(value):
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / ".MHignore").write_text(json.dumps(value), encoding="utf-8")
        try:
            load_ignore_rules(Path(tmp))
        except IgnoreFileError:
            pass


@FUZZ
@given(json_values)
def test_package_lock_with_any_json_is_read_or_rejected_cleanly(value):
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "package-lock.json").write_text(json.dumps(value), encoding="utf-8")
        (Path(tmp) / "package.json").write_text("{}", encoding="utf-8")
        try:
            refs = resolve_dependencies(Path(tmp))
        except ValueError:
            return  # a clear "this lockfile is malformed" error is fine; any other crash is not
        assert all(isinstance(r.name, str) and isinstance(r.version, str) for r in refs)


def _dossier(text: str) -> Dossier:
    return Dossier(
        package="p",
        version="1.0.0",
        signals=[
            Signal(
                id="s", source=SignalSource.RECON, category="c", severity=Severity.HIGH, description=text,
                evidence=[Evidence(excerpt=text, file="a.js", line=3, detail=text)],
            )
        ],
    )


@FUZZ
@given(st.text())
def test_sarif_is_valid_json_without_escape_characters(text):
    out = dossiers_to_sarif_str([_dossier(text)])
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "\x1b" not in out


@FUZZ
@given(st.text())
def test_csv_round_trips_and_never_starts_a_cell_with_a_formula_character(text):
    rows = list(csv.reader(io.StringIO(dossiers_to_csv_str([_dossier(text)]))))
    assert len(rows) >= 2 and all(len(r) == len(rows[0]) for r in rows)
    assert all(cell[:1] not in ("=", "+", "-", "@") for row in rows[1:] for cell in row)


def test_malformed_ignore_rules_give_a_clear_error():
    import pytest

    for content in ("[null]", '["x"]', '[{"package": 5, "reason": "r"}]', '[{"package": "a", "reason": "r", "expires": 20270101}]'):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".MHignore").write_text(content, encoding="utf-8")
            with pytest.raises(IgnoreFileError):
                load_ignore_rules(Path(tmp))


def test_malformed_package_lock_gives_a_clear_error():
    import pytest

    for content in ("null", "[]", '{"packages": []}'):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package-lock.json").write_text(content, encoding="utf-8")
            with pytest.raises(ValueError):
                resolve_dependencies(Path(tmp))
