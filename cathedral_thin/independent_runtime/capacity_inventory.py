"""A validator's own inventory of capacity boxes, kept from cycle to cycle.

Each cycle's shadow capacity scoring (capacity_shadow.py) sees the boxes the
SN94 prober probed that round. This module folds those observations into one
local JSON file, so an operator (or a public status page) can read which boxes
this validator currently sees as healthy, which failed, and which have gone
quiet, without trusting the control plane's own view:

* ``healthy``: its receipt this cycle verified and was accepted;
* ``unhealthy``: its receipt verified but was refused (a duplicate, hardware
  claimed under two hotkeys, a failed recheck, a box too small to use, a
  hotkey that is not a serving miner, a bare-metal box while the policy
  admits only TEE boxes, or a measurement an enforced allowlist does not
  list), with the reason;
* ``missing``: seen before, but no receipt this cycle. After MISSING_CYCLES
  quiet cycles the box is dropped.

Each box keeps the TEE evidence of its latest receipt (receipt v2: the quote
or report digest, launch measurement, verifier digest and attested TLS key
hash; None for bare metal), so an operator can audit which image a box ran
when it was last seen.

A receipt that does not verify names no box anyone can trust, so it never
enters the inventory. Which sandboxes are *assigned* to a box is known only to
the control plane that routes customer sandboxes; validators never see it, so
the inventory has no such field.

The file lives in the validator's state directory and is written atomically.
A file that cannot be read, or that belongs to another netuid, starts a new
inventory rather than failing the cycle.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cathedral_capacity_inventory_v1"
HEALTHY = "healthy"
UNHEALTHY = "unhealthy"
MISSING = "missing"
MISSING_CYCLES = 24
# The reasons capacity_shadow gives a verified receipt whose box is not
# admitted: bare metal while the policy leaves admit_bare_metal off, and a TEE
# measurement an enforced allowlist does not list. Such a receipt takes no part
# in dedup (a box that is not admitted cannot knock out an admitted one sharing
# its box id or hardware), and the inventory ranks its row below any other row
# for the same box id. Defined here so both modules share them.
BARE_METAL_REFUSED = "bare-metal boxes are not admitted (admit_bare_metal is off)"
MEASUREMENT_REFUSED = (
    "the TEE evidence measurement is not on the enforced measurement allowlist"
)
NOT_ADMITTED = frozenset({BARE_METAL_REFUSED, MEASUREMENT_REFUSED})
MAX_BOXES = 4096
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
_BOX_FIELDS = (
    "miner_hotkey",
    "uid",
    "kind",
    "tee_kind",
    "hardware_id_kind",
    "hardware_id",
    "vcpus",
    "memory_gib",
    "value",
    # the TEE evidence of the box's latest receipt (None for bare metal), and
    # whether its measurement is on the measurement allowlist (None: no policy)
    "evidence",
    "measurement_allowed",
)


class CapacityInventoryError(Exception):
    """The inventory file cannot be read or written."""


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_rank(row: Mapping[str, Any]) -> int:
    """Which of two rows for one box id the inventory keeps (higher wins)."""

    if row.get("verdict") == "ACCEPTED":
        return 2
    if row.get("reason") in NOT_ADMITTED:
        return 0
    return 1


def update_inventory(
    previous: Mapping[str, Any] | None,
    rows: Iterable[Mapping[str, Any]],
    *,
    netuid: int,
    round_: int,
    now: datetime,
) -> dict[str, Any]:
    """Fold one cycle's scored receipt rows into the inventory."""

    old_boxes: Mapping[str, Any] = {}
    if (
        isinstance(previous, Mapping)
        and previous.get("schema") == SCHEMA
        and previous.get("netuid") == netuid
        and isinstance(previous.get("boxes"), Mapping)
    ):
        old_boxes = previous["boxes"]
    stamp = _iso(now)
    boxes: dict[str, dict[str, Any]] = {}
    ranks: dict[str, int] = {}
    for row in rows:
        box_id = row.get("box_id")
        if not isinstance(box_id, str):
            continue  # an unverified receipt names no trustworthy box
        rank = _row_rank(row)
        if box_id in boxes and rank <= ranks[box_id]:
            # A box the feed carried twice keeps its first row, unless a later
            # row ranks higher: an accepted row above any refused one, and any
            # refused row above a not-admitted one (a not-admitted receipt
            # reusing a box's id must not hide that box, nor its own refusal
            # reason).
            continue
        ranks[box_id] = rank
        old = old_boxes.get(box_id)
        old = old if isinstance(old, Mapping) else {}
        healthy = row.get("verdict") == "ACCEPTED"
        box = {field: row.get(field) for field in _BOX_FIELDS}
        streak = old.get("streak") if isinstance(old.get("streak"), int) else 0
        was_healthy = old.get("status") == HEALTHY
        box.update(
            status=HEALTHY if healthy else UNHEALTHY,
            reason=None if healthy else row.get("reason"),
            recheck=row.get("recheck"),
            streak=streak + 1 if healthy and was_healthy else (1 if healthy else 0),
            first_seen=old.get("first_seen") or stamp,
            last_seen=stamp,
            last_round=round_,
            missed_cycles=0,
        )
        boxes[box_id] = box
    for box_id, old in old_boxes.items():
        if box_id in boxes or not isinstance(old, Mapping):
            continue
        missed = (
            old.get("missed_cycles") if isinstance(old.get("missed_cycles"), int) else 0
        )
        if missed + 1 >= MISSING_CYCLES:
            continue
        boxes[box_id] = {
            **old,
            "status": MISSING,
            "streak": 0,
            "missed_cycles": missed + 1,
        }
    if len(boxes) > MAX_BOXES:
        # Keep this cycle's boxes first, then the most recently seen.
        ranked = sorted(
            boxes.items(),
            key=lambda item: (
                item[1]["status"] == MISSING,
                item[1].get("missed_cycles", 0),
            ),
        )
        boxes = dict(ranked[:MAX_BOXES])
    return {
        "schema": SCHEMA,
        "netuid": netuid,
        "updated_at": stamp,
        "round": round_,
        "boxes": dict(sorted(boxes.items())),
        "aggregate": aggregate(boxes.values()),
    }


def aggregate(boxes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts by status, and the healthy capacity and value by box kind. It
    names no box, hotkey or hardware, so it can be published as it is."""

    counts = {HEALTHY: 0, UNHEALTHY: 0, MISSING: 0}
    healthy: dict[str, dict[str, int]] = {}
    for box in boxes:
        status = box.get("status")
        if status not in counts:
            continue
        counts[status] += 1
        if status != HEALTHY:
            continue
        kind = healthy.setdefault(
            str(box.get("kind")), {"boxes": 0, "vcpus": 0, "memory_gib": 0, "value": 0}
        )
        kind["boxes"] += 1
        for field in ("vcpus", "memory_gib", "value"):
            value = box.get(field)
            kind[field] += (
                value if isinstance(value, int) and not isinstance(value, bool) else 0
            )
    return {"boxes": counts, "healthy_by_kind": dict(sorted(healthy.items()))}


def load_inventory(path: Path) -> dict[str, Any] | None:
    """The previous inventory, or None when there is none or it is unreadable."""

    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CapacityInventoryError(
            f"inventory is unreadable: {type(exc).__name__}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INVENTORY_BYTES:
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_INVENTORY_BYTES + 1)
    finally:
        os.close(fd)
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def write_inventory(path: Path, document: Mapping[str, Any]) -> None:
    """Replace the inventory atomically: a reader sees the old file or the new."""

    data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_INVENTORY_BYTES:
        raise CapacityInventoryError("inventory is too large to write")
    # A random name, so a temp file left by a crash never blocks a later write.
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(
        tmp,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def record_cycle(
    path: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    netuid: int,
    round_: int,
    now: datetime,
) -> dict[str, Any]:
    """Update the file with one cycle and return the public aggregate."""

    try:
        previous = load_inventory(path)
    except CapacityInventoryError:
        previous = None
    document = update_inventory(previous, rows, netuid=netuid, round_=round_, now=now)
    write_inventory(path, document)
    return document["aggregate"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cathedral_thin.independent_runtime.capacity_inventory",
        description="Print a validator's capacity inventory, or only its public aggregate.",
    )
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--aggregate", action="store_true", help="print only the aggregate"
    )
    options = parser.parse_args(argv)
    try:
        document = load_inventory(options.path)
    except CapacityInventoryError as exc:
        print(f"capacity inventory: {exc}", file=sys.stderr)
        return 2
    if document is None or document.get("schema") != SCHEMA:
        print("capacity inventory: no inventory at that path", file=sys.stderr)
        return 2
    if options.aggregate:
        document = {
            key: document.get(key)
            for key in ("schema", "netuid", "updated_at", "round", "aggregate")
        }
    print(json.dumps(document, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
