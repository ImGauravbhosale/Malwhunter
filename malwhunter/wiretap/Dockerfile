# The Wiretap proxy's own image. The proxy runs in a container beside the
# sandbox instead of on the host: the sandbox's network is created in
# Docker's `isolated` gateway mode, which gives the host no address on it
# at all, so the proxy has to live somewhere the sandbox *can* reach —
# found by live-testing Detonation and reaching a host service on the
# sandbox network's gateway IP. The proxy itself is standard library only;
# `cryptography` is installed only for the optional HTTPS inspection
# (tls_intercept.py) — if it were missing, serve.py falls back to relaying HTTPS blind.
# pinned by digest (refresh: docker buildx imagetools inspect python:3.12-slim --raw | sha256sum);
# the install is hash-locked: edit requirements.in, then run
#   uv pip compile requirements.in --generate-hashes --universal --python-version 3.12 -o requirements.txt
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY proxy.py serve.py tls_intercept.py /app/
WORKDIR /app
ENTRYPOINT ["python", "-u", "/app/serve.py"]
