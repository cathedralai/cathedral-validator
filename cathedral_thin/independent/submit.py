"""The submission shape, built and journalled -- never sent.

This module exists so the exact extrinsic arguments an independent composer
would submit can be reviewed, diffed against the thin path's live vector, and
journalled, before anything is capable of sending them. It builds the keyword
arguments for ``SubtensorModule.set_mechanism_weights`` and stops there.

There is no client here and no code path that acquires one. ``broadcast=True``
raises: the writer does not exist, and a stub that "works" behind the flag is
how a dry-run path becomes a live one without anybody deciding to make it live.

A composition that was blocked never becomes a submission, even a journalled
one. The interesting failure mode is a future runtime that reads a journalled
submission and sends it, so a blocked epoch must not leave one behind.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .compose import STATUS_BROADCAST_BLOCKED, ComposeResult
from .constants import INDEPENDENT_STATE_FILE, MAX_DESTS, MECID, NETUID, VERSION_KEY, W
from .errors import BroadcastBlocked, BroadcastDisabled, HamiltonError
from .journal import write_journal

MECHANISM_WEIGHTS_CALL = "SubtensorModule.set_mechanism_weights"


def _validate_vector(dests: Sequence[int], weights: Sequence[int]) -> None:
    """Re-check the wire shape independently of whatever produced it."""
    if len(dests) != len(weights):
        raise HamiltonError("dests and weights differ in length")
    if not dests:
        raise HamiltonError("the vector is empty")
    if len(dests) > MAX_DESTS:
        raise HamiltonError(f"{len(dests)} destinations exceeds the {MAX_DESTS} cap")
    for uid in dests:
        if isinstance(uid, bool) or not isinstance(uid, int) or not (0 <= uid <= W):
            raise HamiltonError(f"destination {uid!r} is not a u16 uid")
    for weight in weights:
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise HamiltonError(f"weight {weight!r} is not an integer")
        if not (0 < weight <= W):
            raise HamiltonError(f"weight {weight} is outside (0, {W}]")
    if any(dests[index] >= dests[index + 1] for index in range(len(dests) - 1)):
        raise HamiltonError("destinations are not strictly increasing")
    if sum(weights) != W:
        raise HamiltonError(f"weights sum to {sum(weights)}, not {W}")


def build_mechanism_weights_kwargs(
    *,
    dests: Sequence[int],
    weights: Sequence[int],
    netuid: int = NETUID,
    mecid: int = MECID,
    version_key: int = VERSION_KEY,
) -> dict[str, Any]:
    """The keyword arguments for one ``set_mechanism_weights`` call."""
    _validate_vector(dests, weights)
    if netuid != NETUID:
        raise BroadcastDisabled(f"this lineage composes for netuid {NETUID} only")
    if mecid != MECID:
        raise BroadcastDisabled(f"this lineage composes for mecid {MECID} only")
    if version_key != VERSION_KEY:
        raise BroadcastDisabled(f"this lineage pins version_key {VERSION_KEY}")
    return {
        "netuid": netuid,
        "mecid": mecid,
        "dests": list(dests),
        "weights": list(weights),
        "version_key": version_key,
    }


def prepare_mechanism_weights(
    *,
    result: ComposeResult,
    journal_path: Path | str | None = INDEPENDENT_STATE_FILE,
    broadcast: bool = False,
) -> Mapping[str, Any]:
    """Build and journal the submission for a composed vector. Sends nothing."""
    if broadcast is not False:
        raise BroadcastDisabled(
            "this lineage ships no chain writer; the submission is built and "
            "journalled, never sent"
        )
    if result.status == STATUS_BROADCAST_BLOCKED:
        raise BroadcastBlocked(
            f"the composition is blocked ({result.reason}); a blocked epoch "
            "leaves no journalled submission behind"
        )
    kwargs = build_mechanism_weights_kwargs(
        dests=result.dests,
        weights=result.weights,
        netuid=int(result.record["netuid"]),
    )
    if journal_path is not None:
        record = dict(result.record)
        record["submission"] = {
            "call": MECHANISM_WEIGHTS_CALL,
            "kwargs": kwargs,
            "broadcast": False,
        }
        write_journal(record, journal_path)
    return kwargs


__all__ = [
    "MECHANISM_WEIGHTS_CALL",
    "build_mechanism_weights_kwargs",
    "prepare_mechanism_weights",
]
