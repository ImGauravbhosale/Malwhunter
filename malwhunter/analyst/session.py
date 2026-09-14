"""Shells out to your own `claude` CLI session for narrow judgment calls —
written fresh for MalwHunter: its own interface, its own prompts, no
shared code with any other tool. Only used for genuinely ambiguous
Recon findings (a packed blob that matches nothing in the catalog) and
for the second-opinion mechanic in verdict combination.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable

RunFn = Callable[..., subprocess.CompletedProcess]

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "malicious": {"type": "boolean"},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
    },
    "required": ["malicious", "confidence", "rationale"],
}


@dataclass
class Verdict:
    ok: bool
    malicious: bool
    confidence: float
    rationale: str
    error: str | None = None


class Analyst:
    def __init__(self, *, binary: str = "claude", run_fn: RunFn = subprocess.run, timeout_seconds: float = 60.0):
        self._binary = binary
        self._run_fn = run_fn
        self._timeout_seconds = timeout_seconds

    def ask(self, *, system: str, prompt: str) -> Verdict:
        args = [
            self._binary, "-p",
            "--output-format", "json",
            "--restricted",
            "--permission-mode", "dontAsk",
            "--json-schema", json.dumps(_RESPONSE_SCHEMA),
            "--system-prompt", system,
        ]

        try:
            completed = self._run_fn(
                args, input=prompt.encode("utf-8"), capture_output=True, timeout=self._timeout_seconds, shell=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error=f"{type(exc).__name__}: {exc}")

        stdout = completed.stdout
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")

        if completed.returncode != 0:
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error=f"exit {completed.returncode}")

        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error=f"malformed envelope: {exc}")

        if envelope.get("is_error"):
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error=str(envelope.get("result")))

        data = envelope.get("structured_output")
        if data is None:
            return Verdict(ok=False, malicious=False, confidence=0.0, rationale="", error="no structured_output in response")

        return Verdict(
            ok=True,
            malicious=bool(data.get("malicious")),
            confidence=float(data.get("confidence", 0.0)),
            rationale=data.get("rationale", ""),
        )
