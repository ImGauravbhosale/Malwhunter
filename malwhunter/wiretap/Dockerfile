# The Wiretap proxy's own image. The proxy runs in a container beside the
# sandbox instead of on the host: the sandbox's network is created in
# Docker's `isolated` gateway mode, which gives the host no address on it
# at all, so the proxy has to live somewhere the sandbox *can* reach —
# found by live-testing Detonation and reaching a host service on the
# sandbox network's gateway IP. Standard library only, so nothing to install.
FROM python:3.12-slim
COPY proxy.py serve.py /app/
WORKDIR /app
ENTRYPOINT ["python", "-u", "/app/serve.py"]
