"""A file-backed `ConsumptionLedger` for tests that do not need a fixed path.

`ConsumptionLedger(":memory:")` is refused by the shared contract: with per-call
connections an in-memory database is not shared between them, and a ledger that
forgets consumed tokens on restart fails OPEN, which is the opposite of what
replay protection is for. Tests that only need "some working ledger" therefore
need a real file, and tests that assert restart behaviour should keep using
`tmp_path` directly so the path is visible in the test.

Each call gets its own directory, so two ledgers in one test cannot collide
unless the test asks them to share a path.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

from cathedral_distill.consumption_ledger import ConsumptionLedger

_TMPDIRS: list[str] = []


def _cleanup() -> None:
    while _TMPDIRS:
        shutil.rmtree(_TMPDIRS.pop(), ignore_errors=True)


atexit.register(_cleanup)


def durable_ledger_path(name: str = "consumption.sqlite") -> str:
    """A path on a real filesystem, cleaned up when the test process exits."""
    tmp = tempfile.mkdtemp(prefix="cathedral-ledger-")
    _TMPDIRS.append(tmp)
    return os.path.join(tmp, name)


def durable_ledger(**kwargs) -> ConsumptionLedger:
    """A ledger backed by its own throwaway file."""
    return ConsumptionLedger(durable_ledger_path(), **kwargs)
