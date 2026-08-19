# syntax=docker/dockerfile:1
#
# NOTE: this Dockerfile has not been build-tested in this project's dev
# environment (no Docker available, and registry domains aren't reachable
# from the sandbox this was built in). It follows standard multi-stage,
# non-root best practices, but "written correctly" and "verified to build"
# are different claims -- please build and test this locally before relying
# on it. If you hit an issue, it's a real gap to report, not a hidden one.

# ---- Builder: install dependencies into a user site-packages dir ----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- Runtime: minimal image, non-root user ----
FROM python:3.12-slim

RUN useradd --create-home --shell /bin/bash sentinelcore && \
    mkdir -p /data && \
    chown -R sentinelcore:sentinelcore /data

WORKDIR /app
COPY --from=builder /root/.local /home/sentinelcore/.local
COPY app/ ./app/
RUN chown -R sentinelcore:sentinelcore /app

USER sentinelcore
ENV PATH=/home/sentinelcore/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    SENTINELCORE_AUDIT_DB_PATH=/data/sentinelcore_audit.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
