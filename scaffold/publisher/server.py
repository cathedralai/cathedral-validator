"""ASGI entrypoint for the thin publisher (used by the deploy image).

`build_app()` reads CATHEDRAL_EVAL_SIGNING_KEY (production key) and the rest of
the config from the environment. Run with:

    uvicorn scaffold.publisher.server:app --host 0.0.0.0 --port $PORT

The DB path comes from CATHEDRAL_DB_PATH (default ./publisher.db). The refill
loop starts on app startup iff CATHEDRAL_REFILL_ENABLED is truthy (see refill.py).
"""
from __future__ import annotations

import os

from .app import build_app

app = build_app(database_path=os.environ.get("CATHEDRAL_DB_PATH", "publisher.db"))


def _serve_cli() -> None:
    """Console-script entrypoint for the self-composing publisher role.

    A thin convenience wrapper around ``uvicorn.run(app, ...)`` reading host,
    port, and worker count from the same environment the deploy image's raw
    ``uvicorn scaffold.publisher.server:app`` invocation uses. No serving logic
    lives here — it exists so the systemd units under deploy/publisher/ can call
    ``cathedral-publisher-serve`` instead of hard-coding a venv uvicorn path.
    """
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("CATHEDRAL_PUBLISHER_HOST", "0.0.0.0"),  # noqa: S104
        port=int(os.environ.get("PORT", "8000")),
        workers=int(os.environ.get("WEB_CONCURRENCY", "1")),
        access_log=False,
    )
