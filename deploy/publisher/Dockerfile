# Cathedral SN39 origin publisher — slim runtime image.
#
# Ported verbatim from the hub's deploy/Dockerfile (cathedral repo) with two
# deliberate deltas for the consolidated validator:
#   1. base is python:3.12-slim (the validator .venv + the systemd units under
#      deploy/publisher/ and deploy/sn39/ all run 3.12); the pinned wheels in
#      requirements.txt (bittensor-wallet, psycopg2-binary, blake3, cryptography)
#      all ship manylinux cp312 wheels, so the slim/glibc base needs no rust or
#      libpq build toolchain.
#   2. COPY scaffold only — the validator has no game/ package, and the
#      publisher runtime imports only scaffold.* (scaffold.publisher.server:app,
#      mechanism_router, external_scores, weights).
#
# This image runs the same canonical origin app as
# cathedral-scorer-sn39.service: scaffold.publisher.server:app from
# validator-sourced code. It does not define an alternate publisher role.
FROM python:3.12-slim AS base

# Faster, quieter, no .pyc clutter; unbuffered logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first (layer cache: deps change rarely vs source).
COPY deploy/publisher/requirements.txt /app/deploy/publisher/requirements.txt
RUN pip install --no-cache-dir -r /app/deploy/publisher/requirements.txt

# Copy only what the publisher runtime needs (scaffold package). The validator
# has no game/ package, unlike the hub image.
COPY scaffold /app/scaffold

# Non-root runtime user. A mounted persistent volume arrives owned by root, so
# the entrypoint fixes only the active DB path before dropping to `cathedral`.
RUN useradd --create-home --uid 10001 cathedral && chown -R cathedral:cathedral /app

# DB lives on the persistent volume by default.
ENV CATHEDRAL_DB_PATH=/data/publisher.db
RUN mkdir -p /app/data /data && chown cathedral:cathedral /app/data /data

# Host provides $PORT; default 8000 for local runs.
ENV PORT=8000
EXPOSE 8000

# Healthcheck hits the same /health the platform healthcheck uses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f\"http://127.0.0.1:{os.environ.get('PORT','8000')}/health\"; \
sys.exit(0 if urllib.request.urlopen(url,timeout=4).status==200 else 1)"

# Entrypoint: fix volume ownership as root, then drop to the runtime user.
# setpriv (util-linux, in slim base) execs with clean uid/gid — no su/gosu dep.
COPY deploy/publisher/entrypoint.sh /app/deploy/publisher/entrypoint.sh
RUN chmod +x /app/deploy/publisher/entrypoint.sh
ENTRYPOINT ["/app/deploy/publisher/entrypoint.sh"]

# Run through sh so the runtime PORT expands after the entrypoint drops
# privileges; exec lets uvicorn receive SIGTERM directly.
CMD ["sh", "-c", "exec uvicorn scaffold.publisher.server:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --no-access-log"]
