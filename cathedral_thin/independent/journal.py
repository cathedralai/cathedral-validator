"""The independent dry-run journal.

This lineage keeps its own file. It never reads or writes the thin validator's
durable journal: the two are separate reservation fences, and sharing a path
would let one lineage's rollback fence be satisfied by the other's writes. The
file name is checked on every write, so a mistyped operator path cannot land
this record on top of another runtime's state.

The record carries no signed extrinsic and no ``signed_vector`` field, because
this path has no chain writer. A journal that recorded a signed vector would be
claiming a reservation that nothing can redeem, and a later reader could not
tell it apart from a real one.

Writes are atomic: a temporary file in the same directory, fsync, then
``os.replace``. A half-written journal is indistinguishable from a corrupted
one, and this file is the only record of what an epoch composed.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .constants import INDEPENDENT_STATE_FILE, LINEAGE
from .errors import JournalError

# Fields a caller may never supply. This path signs nothing.
REFUSED_JOURNAL_KEYS = frozenset({"signed_vector", "signature", "extrinsic"})

REQUIRED_JOURNAL_KEYS = frozenset(
    {
        "lineage",
        "netuid",
        "epoch_open",
        "anchor_number",
        "anchor_hash",
        "bundle_digest",
        "commitment",
        "h_map",
        "hamilton",
        "status",
        "broadcast",
    }
)

# One epoch's record on a bounded set of destinations; far above any legal size.
MAX_JOURNAL_BYTES = 4 * 1024 * 1024


def _require_independent_path(path: Path) -> Path:
    resolved = Path(path)
    if resolved.name != INDEPENDENT_STATE_FILE.name:
        raise JournalError(
            f"the independent journal must be named "
            f"{INDEPENDENT_STATE_FILE.name!r}, got {resolved.name!r}"
        )
    return resolved


def validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the record to persist, or raise."""
    if not isinstance(record, Mapping):
        raise JournalError("the journal record must be a mapping")
    refused = sorted(REFUSED_JOURNAL_KEYS & set(record))
    if refused:
        raise JournalError(
            f"the independent journal never records {', '.join(refused)}; "
            "this lineage has no chain writer"
        )
    missing = sorted(REQUIRED_JOURNAL_KEYS - set(record))
    if missing:
        raise JournalError(f"the journal record is missing {', '.join(missing)}")
    if record["lineage"] != LINEAGE:
        raise JournalError(f"the journal record must carry lineage {LINEAGE!r}")
    if record["broadcast"] is not False:
        raise JournalError(
            "the journal record must state broadcast = false; this lineage "
            "does not broadcast"
        )
    return dict(record)


def write_journal(
    record: Mapping[str, Any], path: Path | str = INDEPENDENT_STATE_FILE
) -> Path:
    """Atomically persist one epoch's dry-run record."""
    target = _require_independent_path(Path(path))
    payload = validate_record(record)
    try:
        serialised = json.dumps(payload, sort_keys=True, allow_nan=False, indent=2)
    except (TypeError, ValueError) as exc:
        raise JournalError(f"the journal record is not serialisable: {exc}") from exc
    encoded = (serialised + "\n").encode("utf-8")
    if len(encoded) > MAX_JOURNAL_BYTES:
        raise JournalError(
            f"the journal record exceeds the {MAX_JOURNAL_BYTES} byte bound"
        )
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise JournalError(f"the journal directory is unusable: {exc}") from exc
    handle = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=str(parent), prefix=f".{target.name}.", suffix=".tmp"
        )
        handle = os.fdopen(descriptor, "wb")
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        temporary = None
    except OSError as exc:
        raise JournalError(f"the journal could not be written: {exc}") from exc
    finally:
        if handle is not None:
            handle.close()
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    return target


def load_journal(path: Path | str = INDEPENDENT_STATE_FILE) -> dict[str, Any]:
    """Read one journal record, refusing duplicate keys and oversize files."""
    target = _require_independent_path(Path(path))
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise JournalError(f"the journal could not be read: {exc}") from exc
    if len(raw) > MAX_JOURNAL_BYTES:
        raise JournalError(
            f"the journal is {len(raw)} bytes, over the {MAX_JOURNAL_BYTES} byte bound"
        )

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise JournalError(f"the journal has duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalError(f"the journal is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise JournalError("the journal is not a JSON object")
    refused = sorted(REFUSED_JOURNAL_KEYS & set(document))
    if refused:
        raise JournalError(
            f"the journal on disk carries {', '.join(refused)}; refusing to trust it"
        )
    return document


__all__ = [
    "MAX_JOURNAL_BYTES",
    "REFUSED_JOURNAL_KEYS",
    "REQUIRED_JOURNAL_KEYS",
    "load_journal",
    "validate_record",
    "write_journal",
]
