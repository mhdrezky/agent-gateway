FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies first, so code changes do not invalidate this layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev

RUN useradd --system --uid 10001 --home-dir /app agw \
    && mkdir -p /app/var /app/config \
    && chown agw /app/var

USER agw

ENV PATH=/app/.venv/bin:$PATH \
    AGW_CONFIG_FILE=/app/config/gateway.yaml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/v1/health', timeout=3)"]

CMD ["agw", "serve"]
