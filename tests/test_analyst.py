import json
import subprocess

from malwhunter.analyst.judge import judge_packed_blob
from malwhunter.analyst.session import Analyst


def _fake_run(stdout: str, returncode: int = 0):
    def run_fn(args, input, capture_output, timeout, shell):
        assert shell is False
        assert isinstance(input, bytes)
        return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout.encode("utf-8"), stderr=b"")

    return run_fn


def test_ask_returns_structured_verdict():
    envelope = json.dumps({"is_error": False, "structured_output": {"malicious": True, "confidence": 0.8, "rationale": "looks like a reverse shell payload"}})
    analyst = Analyst(run_fn=_fake_run(envelope))
    verdict = analyst.ask(system="s", prompt="p")
    assert verdict.ok is True
    assert verdict.malicious is True
    assert verdict.confidence == 0.8


def test_ask_handles_missing_binary_gracefully():
    def run_fn(*a, **kw):
        raise FileNotFoundError("no claude binary")

    analyst = Analyst(run_fn=run_fn)
    verdict = analyst.ask(system="s", prompt="p")
    assert verdict.ok is False
    assert "FileNotFoundError" in verdict.error


class _QueueAnalyst(Analyst):
    """Test double returning a queued sequence of Verdicts regardless of
    prompt content, so judge_packed_blob's two-call flow is easy to drive."""

    def __init__(self, verdicts):
        self._queue = list(verdicts)

    def ask(self, *, system, prompt):
        return self._queue.pop(0)


def _verdict(malicious, confidence=0.8, rationale="r"):
    from malwhunter.analyst.session import Verdict

    return Verdict(ok=True, malicious=malicious, confidence=confidence, rationale=rationale)


def test_judge_packed_blob_both_personas_agree_malicious():
    analyst = _QueueAnalyst([_verdict(True), _verdict(True)])
    signals = judge_packed_blob(analyst, file="index.js", line=12, excerpt="aGVsbG8=")
    assert len(signals) == 2
    assert all(s.category == "obfuscated-intent" for s in signals)


def test_judge_packed_blob_skeptical_disagrees_yields_one_signal():
    analyst = _QueueAnalyst([_verdict(False), _verdict(True)])
    signals = judge_packed_blob(analyst, file="index.js", line=12, excerpt="aGVsbG8=")
    assert len(signals) == 1


def test_judge_packed_blob_both_say_benign_yields_no_signals():
    analyst = _QueueAnalyst([_verdict(False), _verdict(False)])
    signals = judge_packed_blob(analyst, file="index.js", line=12, excerpt="aGVsbG8=")
    assert signals == []
