# Multi-stage production container for Cloud Run / ADK API Server
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY opsguardian ./opsguardian

RUN pip install --upgrade pip && \
    pip wheel --wheel-dir /wheels ".[gcp]"

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPSGUARDIAN_ENV=gcp \
    PORT=8080

RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --create-home appuser

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

COPY opsguardian ./opsguardian
COPY eval ./eval
COPY deployment ./deployment

RUN mkdir -p /app/data && chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/list-apps')" || exit 1

CMD ["sh", "-c", "adk api_server --host 0.0.0.0 --port ${PORT} --trace_to_cloud ."]
