# The Detonation sandbox image. node:20-slim alone doesn't include curl or
# wget — found by actually running a real malicious postinstall fixture
# through Detonation and getting zero signals, because the install
# script's own `curl | sh` silently failed with "command not found"
# before it ever reached the network. A real attacker's dropper using
# curl or wget (among the most common real-world patterns) would get the
# same free pass from a plain node:20-slim container — this isn't a
# detection-logic gap, it's a sandbox-can't-reproduce-the-attack gap.
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl wget \
    && rm -rf /var/lib/apt/lists/*
