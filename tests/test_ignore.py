from datetime import date
from pathlib import Path

import pytest

from malwhunter.dossier.model import Dossier
from malwhunter.intake.ignore import (
    IgnoreFileError,
    IgnoreRule,
    apply_ignore_rules,
    load_ignore_rules,
)


def test_load_ignore_rules_missing_file_returns_empty(tmp_path: Path):
    assert load_ignore_rules(tmp_path) == []


def test_load_ignore_rules_parses_valid_file(tmp_path: Path):
    (tmp_path / ".MHignore").write_text(
        '[{"package": "left-pad", "version": "1.3.0", "reason": "reviewed, benign", "expires": "2027-01-01"}]'
    )
    rules = load_ignore_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0] == IgnoreRule(
        package="left-pad", version="1.3.0", reason="reviewed, benign", expires=date(2027, 1, 1)
    )


def test_load_ignore_rules_rejects_missing_reason(tmp_path: Path):
    (tmp_path / ".MHignore").write_text('[{"package": "left-pad"}]')
    with pytest.raises(IgnoreFileError, match="reason"):
        load_ignore_rules(tmp_path)


def test_load_ignore_rules_rejects_bad_expiry_format(tmp_path: Path):
    (tmp_path / ".MHignore").write_text('[{"package": "left-pad", "reason": "ok", "expires": "not-a-date"}]')
    with pytest.raises(IgnoreFileError, match="expires"):
        load_ignore_rules(tmp_path)


def test_load_ignore_rules_rejects_malformed_json(tmp_path: Path):
    (tmp_path / ".MHignore").write_text("not json")
    with pytest.raises(IgnoreFileError, match="not valid JSON"):
        load_ignore_rules(tmp_path)


def test_load_ignore_rules_rejects_non_array(tmp_path: Path):
    (tmp_path / ".MHignore").write_text('{"package": "left-pad", "reason": "ok"}')
    with pytest.raises(IgnoreFileError, match="JSON array"):
        load_ignore_rules(tmp_path)


def test_rule_matches_exact_version():
    rule = IgnoreRule(package="left-pad", version="1.3.0", reason="ok")
    assert rule.matches("left-pad", "1.3.0")
    assert not rule.matches("left-pad", "1.3.1")
    assert not rule.matches("chalk", "1.3.0")


def test_rule_without_version_matches_any_version():
    rule = IgnoreRule(package="left-pad", reason="ok")
    assert rule.matches("left-pad", "1.3.0")
    assert rule.matches("left-pad", "9.9.9")


def test_apply_ignore_rules_marks_matches_and_flags_unused():
    matched_pkg = Dossier(package="left-pad", version="1.3.0")
    other_pkg = Dossier(package="chalk", version="5.3.0")
    stale_rule = IgnoreRule(package="not-in-tree", reason="stale")
    live_rule = IgnoreRule(package="left-pad", version="1.3.0", reason="reviewed, benign")

    outcome = apply_ignore_rules([matched_pkg, other_pkg], [live_rule, stale_rule])

    assert outcome.matched[matched_pkg.dossier_key] is live_rule
    assert other_pkg.dossier_key not in outcome.matched
    assert outcome.unused == [stale_rule]
    assert outcome.expired == []


def test_apply_ignore_rules_skips_expired_rules():
    pkg = Dossier(package="left-pad", version="1.3.0")
    expired_rule = IgnoreRule(package="left-pad", version="1.3.0", reason="ok", expires=date(2020, 1, 1))

    outcome = apply_ignore_rules([pkg], [expired_rule], today=date(2026, 1, 1))

    assert outcome.matched == {}
    assert outcome.expired == [expired_rule]
    assert outcome.unused == []
