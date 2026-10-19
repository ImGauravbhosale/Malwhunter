# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.13.1 AS uv
FROM python:3.12-slim-bookworm

COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    HOME=/home/scanner
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY malwhunter ./malwhunter
RUN uv sync --frozen --no-dev --no-editable \
    && groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid 10001 --create-home scanner
COPY docker/interactive.py /app/docker/interactive.py
USER 10001:10001
WORKDIR /project
ENTRYPOINT ["python", "/app/docker/interactive.py"]
CMD []
