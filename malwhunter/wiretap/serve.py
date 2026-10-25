"""Entry point for running the Wiretap proxy as its own container, next to
the sandbox rather than on the host (see chamber/runner.py).

Every captured event is appended to a JSON-lines file the moment it
happens, so a run that gets killed partway through still leaves behind
everything it captured. Runs with only the standard library: the image
copies just this file and proxy.py.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
from dataclasses import asdict
from pathlib import Path

from proxy import WiretapProxy  # flat layout inside the image


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True, help="directory for capture.jsonl and the ready marker")
    args = parser.parse_args()

    log = (args.out / "capture.jsonl").open("a", encoding="utf-8", buffering=1)  # line-buffered: flushed per event

    def on_event(kind: str, record: object) -> None:
        data = asdict(record)
        if isinstance(data.get("body"), bytes):
            data["body"] = base64.b64encode(data["body"]).decode()
        log.write(json.dumps({"kind": kind, **data}) + "\n")

    async def run() -> None:
        proxy = WiretapProxy(on_event=on_event)
        # 0.0.0.0 inside this container's own network namespace: the
        # sandbox's internal network and the egress network are its only
        # interfaces — this is not the host's 0.0.0.0.
        await proxy.start(host="0.0.0.0", port=args.port)  # nosec B104
        (args.out / "ready").write_text("ready", encoding="utf-8")
        await asyncio.Event().wait()

    asyncio.run(run())


if __name__ == "__main__":
    main()
