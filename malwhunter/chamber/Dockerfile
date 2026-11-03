# The Detonation sandbox image. node:20-slim alone doesn't include curl or
# wget — found by actually running a real malicious postinstall fixture
# through Detonation and getting zero signals, because the install
# script's own `curl | sh` silently failed with "command not found"
# before it ever reached the network. A real attacker's dropper using
# curl or wget (among the most common real-world patterns) would get the
# same free pass from a plain node:20-slim container — this isn't a
# detection-logic gap, it's a sandbox-can't-reproduce-the-attack gap.
#
# ca-certificates too: --no-install-recommends leaves it out, and without
# it every HTTPS download by curl/wget fails certificate verification —
# found by live-testing through the Wiretap proxy. A dropper fetching its
# payload over HTTPS would fail before running it, and we'd only ever see
# the connection, never what the payload does.
# pinned by digest so a moved tag cannot change the sandbox; refresh with:
#   docker buildx imagetools inspect node:22-slim --raw | sha256sum
FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wget strace \
    && rm -rf /var/lib/apt/lists/*
