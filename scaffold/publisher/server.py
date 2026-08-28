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
    """Console-script entrypoint for the origin publisher service.

    A thin convenience wrapper around ``uvicorn.run(app, ...)`` reading host and
    port from the same environment as the deploy image. The worker count is
    fixed at one because SQLite does not provide a cross-process singleton lock
    for the in-memory signed-vector cache. No serving logic lives here.
    """
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("CATHEDRAL_PUBLISHER_HOST", "0.0.0.0"),  # noqa: S104
        port=int(os.environ.get("PORT", "8000")),
        workers=1,
        access_log=False,
    )
