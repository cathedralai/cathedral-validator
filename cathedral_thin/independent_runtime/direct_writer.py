"""Durable direct SN94 weight writer with hash-only restart recovery.

The signed extrinsic hash, nonce, era, exact call, and evidence identity reach
disk before broadcast.  A restart with a pending intent only searches finalized
blocks for that hash.  Recovery never signs and never resubmits.  A signature
too close to the end of its mortal era is dropped before it reaches disk.

A write that is included in a finalized block and fails its dispatch stops the
validator. Only ``record_finalized_failure`` clears it, after proving that
failure from finalized chain state; it also never signs or resubmits.

On a subnet with commit-reveal enabled the writer refuses, exactly as before,
unless the operator opted in to timelocked commits (``commit_reveal.py``).
Then the same journaled, era-pinned, hash-recovered extrinsic carries the
vector encrypted to a drand round instead of in plain text. Its stored commit
is proven at inclusion and the attempt is recorded ``COMMITTED``; later cycles
prove from finalized state that the chain's own automatic reveal applied the
exact vector, or record that it did not and stop. That ``REVEAL_NOT_APPLIED``
stop stays in the journal: every later recovery and submit refuses on it until
``record_finalized_failure`` records it as reviewed. No reveal extrinsic exists.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import math
import os
import stat
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from functools import partial
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from bittensor.core.extrinsics.pallets import SubtensorModule
from bittensor.utils import get_mechid_storage_index, ss58_address_to_bytes

from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    MECID,
    MORTAL_PERIOD_BLOCKS,
    NETUID,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.submit import build_mechanism_weights_kwargs

from .axon import finalized_head, observed_genesis_hash
from .commit_reveal import (
    BLOCK_TIME_SECONDS,
    COMMIT_REVEAL_CALL,
    COMMIT_REVEAL_CALL_FUNCTION,
    COMMIT_REVEAL_OPT_IN_ENV,
    COMMIT_REVEAL_VERSION,
    DRAND_ROUND_TOLERANCE,
    MAX_COMMIT_BYTES,
    MAX_REVEAL_PERIOD_EPOCHS,
    CommitRevealOptIn,
    EpochSchedule,
    canonical_bytes_hex,
    chain_expected_reveal_round,
    decoded_commit_rows,
    default_commit_encryptor,
    drand_round_at,
    next_epoch_fire_block,
    predict_first_reveal_block,
)
from .direct_contract import (
    DIRECT_PLAN_SCHEMA,
    DirectSubmissionReceipt,
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
    require_netuid,
    zero_burn_vector,
)
from .preview_io import canonical_document_bytes
from .qvl import DIRECT_VALIDATOR_QVL_DIGEST

STATE_SCHEMA = "cathedral_direct_validator_state_v1"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_RECOVERED = "RECOVERED_CONFIRMED"
STATUS_EXPIRED = "EXPIRED_WITHOUT_INCLUSION"
# Terminal status of an intent whose exact call is proven included in a
# finalized block of its era with a failed dispatch. Only the operator's
# record command writes it, never the validator.
STATUS_FINALIZED_FAILED = "FINALIZED_FAILED"
# Pending phase the writer journals when its exact call finalized with failure.
PHASE_FINALIZED_FAILED = "finalized_failed"
# Timelocked commit-reveal, operator opt-in only. COMMITTED is the terminal
# status of the commit extrinsic itself: included, successful, and its stored
# commit proven. The attempt then moves to REVEALED_CONFIRMED once finalized
# state proves the chain's automatic reveal applied the exact vector, or to
# REVEAL_NOT_APPLIED once it proves the commit was consumed without it.
# COMMITTED_AWAITING_REVEAL is only ever a receipt, never a journal status.
STATUS_COMMITTED = "COMMITTED"
STATUS_AWAITING_REVEAL = "COMMITTED_AWAITING_REVEAL"
STATUS_REVEALED = "REVEALED_CONFIRMED"
STATUS_REVEAL_NOT_APPLIED = "REVEAL_NOT_APPLIED"
# Terminal status of a REVEAL_NOT_APPLIED stop once the operator's record
# command has recorded it as reviewed. Only that command writes it, never the
# validator. Until then REVEAL_NOT_APPLIED keeps every recovery, submit and
# update refused, as a finalized_failed pending intent does.
STATUS_REVEAL_NOT_APPLIED_RECORDED = "REVEAL_NOT_APPLIED_RECORDED"
# The commit is gone from finalized state but the blocks that prove what its
# reveal did are older than the node still serves. Nothing more can be proven
# on that node, so the attempt closes unproven and the writer continues.
STATUS_REVEAL_UNPROVEN = "REVEAL_UNPROVEN"
# How far behind the finalized head the last block that still held the commit
# may be before unreadable history closes the attempt as unproven rather than
# waiting for the next cycle. A pruning node keeps 256 blocks of state.
REVEAL_HISTORY_LIMIT_BLOCKS = 200
MAX_STATE_BYTES = 1_048_576
DIRECT_STATE_ROOT = Path.home() / ".local/state/cathedral-validator/direct-writer"
CONFIRMATION_WAIT_SECONDS = 60.0
CONFIRMATION_POLL_SECONDS = 2.0
# Bound for re-reading finalized history after the node reported the
# extrinsic finalized. Readers of chain_getFinalizedHead can trail that
# report by a block or two, so one immediate lookup misses the inclusion
# block and the write would otherwise sit in the journal until the next
# cycle. Together with CONFIRMATION_WAIT_SECONDS this stays far below the
# cycle interval. Nothing is resubmitted while waiting.
FINALIZED_HISTORY_WAIT_SECONDS = 90.0
# Blocks of the mortal era a signed write must still have when it leaves this
# process. The node checks a transaction as if it were in the block after its
# best head and accepts it only while that block is inside the era, so a
# write checked at best head B can land in at most era_end - 1 - B blocks.
# The margin is deliberately small. A refused write and a write that expires
# unincluded cost the same single interval: nothing is pending after a
# refusal, and an expired intent is resolved by the next cycle's recovery,
# which then writes fresh weights in that same cycle. So refusing is worth it
# only where inclusion is unlikely. With one block left, the write has one
# author slot and must be sent and gossiped before that block is built. With
# two or more it usually lands in the next block. The era is anchored on the
# finalized head, so the best head already runs the finality lag plus a block
# or two ahead of it: a wider margin would refuse every write under a steady
# lag of ten or so blocks while most of those writes would have landed.
BROADCAST_ERA_MARGIN_BLOCKS = 2
# Per-message wait and send count for every chain RPC the direct validator
# makes. The pinned async-substrate-interface defaults are 60 s and 5 sends,
# and each silent wait reconnects and re-sends, so one hung call could hold a
# cycle for about five minutes: longer than the whole mortal era, and after
# the last cooperative pre-sign deadline check. Two sends of 20 s plus one
# reconnect cap a single call below a minute (about four blocks). Every other
# call here is a read whose answer is one message; even the heaviest, the
# metagraph runtime call, normally arrives within a second or so.
DIRECT_RPC_RETRY_TIMEOUT_SECONDS = 20.0
DIRECT_RPC_MAX_RETRIES = 2
# The broadcast watch is the one call that is not a single-response read.
# After inBlock the node stays silent until that block is finalized, which is
# chain finality rather than RPC latency and often exceeds 20 s, and a
# silent watch is re-sent as a new submission of the same bytes that the node
# refuses as already known or outdated. A short wait there would turn ordinary
# writes into ambiguities, so the watch alone keeps the library's own
# defaults, exactly as before the bound above. A long watch delays only this
# cycle's receipt; it cannot change whether or when the bytes are included.
BROADCAST_WATCH_RETRY_TIMEOUT_SECONDS = 60.0
BROADCAST_WATCH_MAX_RETRIES = 5
_RPC_WAIT_FIELDS = ("retry_timeout", "max_retries")
_CHAIN_HASH_HEX = frozenset("0123456789abcdef")
_LOG = logging.getLogger(__name__)
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}
_STATUS_EXTRINSIC_FINALIZED = "EXTRINSIC_FINALIZED"
_I32F32_ONE = 1 << 32
_I32F32_HALF = 1 << 31
_I32F32_UPSCALE_THRESHOLD = 32_768


class DirectSubmissionAmbiguous(DirectValidatorError):
    """One exact signed hash is fenced and must be recovered, never retried."""


class DirectSubmissionContradiction(DirectSubmissionAmbiguous):
    """Finalized history or durable state contradicts the signed intent."""


class DirectSubmissionFinalizedFailure(DirectSubmissionContradiction):
    """The exact signed call is in a finalized block and its dispatch failed.

    It stays a contradiction for every existing handler. The validator stops
    on it with its own exit code, and only ``record_finalized_failure`` clears
    the pending intent.
    """


class DirectCommitNotRevealed(DirectSubmissionContradiction):
    """A proven timelocked commit was consumed without applying its vector.

    Nothing was written, and the journal already records the
    ``REVEAL_NOT_APPLIED`` proof. It is a contradiction so the validator stops
    with the exit code its unit never restarts: the chain refused a vector
    every pre-sign check accepted, which needs an operator before another
    commit. The journal keeps the stop, so every later recovery and submit
    raises it again until ``record_finalized_failure`` records it as reviewed.
    """


class FailedWriteRecordRefused(DirectValidatorError):
    """The failed-write record was refused and the journal is unchanged."""


class FailedWriteHistoryUnreadable(DirectValidatorError):
    """The node could not serve the history the proof needs; nothing changed.

    This is not a refusal. A node that prunes state, or an RPC that fails,
    proves nothing either way, so the same command may be retried, for
    example against an archive node.
    """


class _Undecodable(ValueError):
    """A dispatch error that cannot be named; it is then recorded raw."""


# Bound on a raw dispatch error kept in the journal when it cannot be named.
MAX_RAW_DISPATCH_ERROR_CHARS = 1024


def _presign_deadline(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise DirectValidatorError(
            "pre-sign deadline must be a finite monotonic timestamp"
        )
    return float(value)


def _require_presign_time(deadline: float, *, stage: str) -> None:
    if time.monotonic() >= deadline:
        raise DirectValidatorError(f"pre-sign deadline expired during {stage}")


def bound_rpc_waits(subtensor: Any) -> None:
    """Cap every later RPC on this chain client well inside one mortal era.

    The pinned client reads ``retry_timeout`` and ``max_retries`` as plain
    attributes on every request. A client without them is refused: assigning
    them anyway would add attributes nothing reads and silently leave every
    call unbounded.
    """

    substrate = getattr(subtensor, "substrate", None)
    for name in _RPC_WAIT_FIELDS:
        value = getattr(substrate, name, None)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DirectValidatorError(f"chain client has no {name} to bound")
    substrate.retry_timeout = DIRECT_RPC_RETRY_TIMEOUT_SECONDS
    substrate.max_retries = DIRECT_RPC_MAX_RETRIES


def _uncached_block_hash(substrate: Any, block_number: int) -> object:
    """Ask the node for the canonical hash at one height, bypassing caches.

    The pinned client remembers every number-to-hash lookup for the life of
    the process, and signing makes it remember an unfinalized one:
    ``create_signed_extrinsic`` initializes its runtime at the best head by
    number. If that block is later reorged out, a cached lookup keeps naming
    the orphan. A scan of the era would then miss a write that landed in the
    canonical block at that height, and could record it as expired or leave
    it unresolved, and a confirmation would see a false contradiction. Every
    height of finalized history the writer proves anything from is therefore
    read straight from the node, and a read that can only name a height is
    preceded by ``_correct_cached_block_hash``.
    """

    response = substrate.rpc_request("chain_getBlockHash", [block_number])
    return response.get("result") if isinstance(response, Mapping) else None


def _cached_block_hash(subtensor: Any, block_number: int) -> str | None:
    """Return the hash a read that names only a block number would use."""

    try:
        return _canonical_hash(
            subtensor.get_block_hash(block_number), label="cached block"
        )
    except DirectSubmissionAmbiguous:
        return None


def _correct_cached_block_hash(
    subtensor: Any, block_number: int, canonical: str
) -> None:
    """Make reads that name only a block number resolve to the canonical block.

    The metagraph takes a block number, not a hash. bittensor resolves it
    through its own memo of lookups, then the client's number-to-hash map,
    which has a memo of node answers behind it, and all three last for the
    process. If the block signing cached at this height was reorged out, the
    metagraph reads the orphan. Once the height is finalized a pruning node
    has discarded the orphan's state, so that read fails on every later
    recovery of the same pending write, until the process restarts.

    A differing entry is therefore overwritten with the canonical hash and
    both memos are cleared, so the next lookup reads the corrected map or
    asks the node again. The lookup is then read back. Only a client that
    still names another block leaves the confirmation ambiguous, and every
    later recovery makes the same correction again.
    """

    if _cached_block_hash(subtensor, block_number) == canonical:
        return
    substrate = subtensor.substrate
    runtime_cache = getattr(substrate, "runtime_cache", None)
    add_item = getattr(runtime_cache, "add_item", None)
    if callable(add_item):
        add_item(block=block_number, block_hash=canonical)
    for client in (substrate, subtensor):
        memo = getattr(client, "_get_block_hash", None)
        clear = getattr(memo, "cache_clear", None)
        if callable(clear):
            clear()
    if _cached_block_hash(subtensor, block_number) != canonical:
        raise DirectSubmissionAmbiguous(
            f"client cache for finalized block {block_number} still names "
            "a block that is not canonical"
        )


@contextmanager
def _broadcast_watch_waits(substrate: Any) -> Iterator[None]:
    """Give only the finalization watch the library's waits, then restore."""

    previous = tuple(getattr(substrate, name, None) for name in _RPC_WAIT_FIELDS)
    if None in previous:
        # A client without these knobs never had a bound to widen.
        yield
        return
    substrate.retry_timeout = BROADCAST_WATCH_RETRY_TIMEOUT_SECONDS
    substrate.max_retries = BROADCAST_WATCH_MAX_RETRIES
    try:
        yield
    finally:
        substrate.retry_timeout, substrate.max_retries = previous


def _canonical_hash(value: object, *, label: str) -> str:
    try:
        if isinstance(value, str):
            text = value
        elif hasattr(value, "hex"):
            text = str(value.hex())
        else:
            text = bytes(value).hex()
    except (AttributeError, TypeError, ValueError) as exc:
        raise DirectSubmissionAmbiguous(f"{label} is not a usable hash") from exc
    text = text.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    body = text[2:]
    if len(body) != 64 or any(character not in _CHAIN_HASH_HEX for character in body):
        raise DirectSubmissionAmbiguous(f"{label} is not a canonical chain hash")
    return text


def _strict_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DirectSubmissionContradiction(f"direct state repeats key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DirectSubmissionContradiction("direct state is not strict JSON") from exc
    if not isinstance(document, dict):
        raise DirectSubmissionContradiction("direct state is not an object")
    return document


def _initial_state() -> dict[str, object]:
    return {"schema": STATE_SCHEMA, "pending": None, "last_attempt": None}


def _attempt_id(identity: Mapping[str, Any], intent: Mapping[str, Any]) -> str:
    exact = {"identity": identity, "intent": intent}
    return "sha256:" + hashlib.sha256(canonical_document_bytes(exact)).hexdigest()


def _local_lock(path: Path) -> threading.Lock:
    key = str(path.absolute())
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


def _chain_call_arg(call: Mapping[str, Any], name: str) -> Any:
    for item in call.get("call_args") or ():
        if isinstance(item, Mapping) and item.get("name") == name:
            return item.get("value")
    return None


def _raw_value(value: Any) -> Any:
    value = getattr(value, "value", value)
    if hasattr(value, "tolist"):
        value = value.tolist()
    if hasattr(value, "item"):
        value = value.item()
    return value


def _nonnegative_int(value: Any, *, label: str) -> int:
    value = _raw_value(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DirectValidatorError(f"{label} is not a non-negative integer")
    return value


def _balance_rao(value: Any, *, label: str) -> int:
    return _nonnegative_int(getattr(value, "rao", value), label=label)


def _strict_bool(value: Any, *, label: str) -> bool:
    value = _raw_value(value)
    item = getattr(value, "item", None)
    if callable(item):
        value = item()
    if type(value) is not bool:
        raise DirectValidatorError(f"{label} is not an explicit boolean")
    return value


def _stored_weight_rows(value: Any) -> tuple[tuple[int, int], ...]:
    raw = _raw_value(value)
    if not isinstance(raw, (list, tuple)):
        raise DirectSubmissionAmbiguous("stored mechanism weights are unavailable")
    result: list[tuple[int, int]] = []
    for row in raw:
        row = _raw_value(row)
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise DirectSubmissionAmbiguous("stored mechanism weight row is malformed")
        uid = _raw_value(row[0])
        weight = _raw_value(row[1])
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or not 0 <= uid <= W
            or isinstance(weight, bool)
            or not isinstance(weight, int)
            or not 0 < weight <= W
        ):
            raise DirectSubmissionAmbiguous("stored mechanism weight value is invalid")
        result.append((uid, weight))
    return tuple(result)


def _subtensor_max_upscale_to_u16(weights: tuple[int, ...]) -> tuple[int, ...]:
    """Reproduce the pallet's Q32 max-upscale before comparing storage.

    ``pallets/subtensor/src/subnets/weights.rs::internal_set_weights`` stores
    ``vec_u16_max_upscale_to_u16(values)``, not the submitted values. The math
    lives in ``pallets/subtensor/src/epoch/math.rs`` and uses I32F32 division,
    a separate overflow-avoiding branch above 32768, and round-half-away from
    zero. All inputs here are non-negative u16 values, so the exact operation
    is integer Q32 arithmetic.
    """

    if any(
        isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= W
        for weight in weights
    ):
        raise DirectSubmissionContradiction(
            "confirmation weight vector is not a u16 vector"
        )
    if not weights:
        return ()
    maximum = max(weights)
    if maximum == 0:
        return tuple(0 for _weight in weights)

    if maximum > _I32F32_UPSCALE_THRESHOLD:
        # Mirrors e.saturating_mul(u16_max.safe_div(maximum)).round().
        multiplier_q32 = (W * _I32F32_ONE) // maximum
        return tuple(
            (weight * multiplier_q32 + _I32F32_HALF) // _I32F32_ONE
            for weight in weights
        )

    # Mirrors e.saturating_mul(u16_max).safe_div(maximum).round().
    return tuple(
        (((weight * W * _I32F32_ONE) // maximum) + _I32F32_HALF) // _I32F32_ONE
        for weight in weights
    )


_COMMIT_REVEAL_FIELDS = frozenset(
    {
        "call",
        "commit",
        "reveal_round",
        "commit_reveal_version",
        "reveal_period_epochs",
        "block_time_seconds",
        "hotkey_public_key",
        "schedule",
        "drand_last_stored_round",
        "next_epoch_block",
        "first_reveal_block",
        "expected_reveal_round",
        "local_drand_round",
    }
)
_SCHEDULE_FIELDS = frozenset(
    {
        "block",
        "tempo",
        "last_epoch_block",
        "pending_epoch_at",
        "subnet_epoch_index",
        "blocks_since_last_step",
    }
)
_REVEAL_FIELDS = frozenset({"commit_epoch", "present_through_block", "outcome"})
_COMMITTED_ATTEMPT_FIELDS = frozenset(
    {"attempt_id", "status", "identity", "intent", "receipt", "reveal"}
)


def _plain_nonnegative(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


_REVEAL_NOT_APPLIED_ACTION = (
    "The journal keeps the validator stopped on it. Find the cause, then clear "
    "it with `cathedral-validator record-failed-write` while the service is "
    'stopped; see docs/AUTO_UPDATE.md "Commit-reveal subnets"'
)


def _reveal_not_applied_stop(
    state: Mapping[str, Any],
) -> DirectCommitNotRevealed | None:
    """Return the stop a ``REVEAL_NOT_APPLIED`` last attempt holds, or ``None``.

    The status alone is the stop. A malformed record still stops: only the
    record command, which validates it in full, may move it on.
    """

    last = state.get("last_attempt")
    if not isinstance(last, Mapping) or last.get("status") != STATUS_REVEAL_NOT_APPLIED:
        return None
    receipt = last.get("receipt")
    reveal = last.get("reveal")
    outcome = reveal.get("outcome") if isinstance(reveal, Mapping) else None
    extrinsic_hash = (
        receipt.get("extrinsic_hash") if isinstance(receipt, Mapping) else None
    )
    consumed = outcome.get("consumed_block") if isinstance(outcome, Mapping) else None
    return DirectCommitNotRevealed(
        f"timelocked commit {extrinsic_hash} was consumed at block {consumed} "
        "without applying its weights (REVEAL_NOT_APPLIED). "
        f"{_REVEAL_NOT_APPLIED_ACTION}"
    )


def _commit_reveal_document(intent: object) -> dict[str, Any] | None:
    """Return a journaled intent's timelocked-commit record, or ``None``.

    A plain intent has no ``commit_reveal`` key and stays byte-identical to
    earlier releases. A present record must be exactly the shape the writer
    journals; anything else is a contradiction, never a guess.
    """

    if not isinstance(intent, Mapping) or "commit_reveal" not in intent:
        return None
    document = intent["commit_reveal"]
    schedule = document.get("schedule") if isinstance(document, Mapping) else None
    commit = document.get("commit") if isinstance(document, Mapping) else None
    public_key = (
        document.get("hotkey_public_key") if isinstance(document, Mapping) else None
    )
    if (
        not isinstance(document, dict)
        or set(document) != _COMMIT_REVEAL_FIELDS
        or document["call"] != COMMIT_REVEAL_CALL
        or not isinstance(commit, str)
        or canonical_bytes_hex(commit) != commit
        or not 0 < (len(commit) - 2) // 2 <= MAX_COMMIT_BYTES
        or not isinstance(public_key, str)
        or canonical_bytes_hex(public_key) != public_key
        or len(public_key) != 66
        or document["commit_reveal_version"] != COMMIT_REVEAL_VERSION
        or document["block_time_seconds"] != BLOCK_TIME_SECONDS
        or not isinstance(schedule, dict)
        or set(schedule) != _SCHEDULE_FIELDS
        or not all(_plain_nonnegative(value) for value in schedule.values())
        or not all(
            _plain_nonnegative(document[name])
            for name in (
                "reveal_round",
                "reveal_period_epochs",
                "drand_last_stored_round",
                "next_epoch_block",
                "first_reveal_block",
                "expected_reveal_round",
                "local_drand_round",
            )
        )
    ):
        raise DirectSubmissionContradiction("journaled timelocked commit is malformed")
    return document


def _plain_detail(value: object) -> object:
    """Copy one decoded dispatch-error detail as JSON data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain_detail(item) for item in value]
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {key: _plain_detail(item) for key, item in value.items()}
    raise _Undecodable("dispatch error detail is not plain data")


def _module_error_index(value: object) -> int:
    """Return a pallet error index, including the four-byte encoding.

    Newer runtimes encode ``ModuleError.error`` as ``[u8; 4]``, whose first
    byte is the index; the pinned client reads it the same way
    (``async_substrate_interface/utils/receipt.py:99-101``). The metadata
    indexes errors like a list, so a bool or negative index would name the
    wrong error; any other unusable index fails the lookup and stays raw.
    """

    if isinstance(value, str):
        text = value.lower()
        if (
            len(text) != 10
            or not text.startswith("0x")
            or any(character not in _CHAIN_HASH_HEX for character in text[2:])
        ):
            raise _Undecodable("dispatch module error bytes are invalid")
        return int(text[2:4], 16)
    if isinstance(value, (list, tuple)) and len(value) == 4:
        value = value[0]
    if isinstance(value, bool) or value < 0:
        raise _Undecodable("dispatch module error index is invalid")
    return value


def _decoded_dispatch_error(attributes: object, metadata: Any) -> dict[str, Any]:
    """Name one proven ``ExtrinsicFailed`` dispatch error, or keep it raw.

    The failure itself is already proven by the event, so an error that
    cannot be named is recorded as it came from the node, never refused.
    """

    error = (
        attributes.get("dispatch_error") if isinstance(attributes, Mapping) else None
    )
    try:
        return _named_dispatch_error(error, metadata)
    except Exception:
        try:
            raw = _plain_detail(error)
        except _Undecodable:
            raw = repr(error)[:MAX_RAW_DISPATCH_ERROR_CHARS]
        return {"type": "Undecoded", "raw": raw}


def _named_dispatch_error(error: object, metadata: Any) -> dict[str, Any]:
    """Name a dispatch error, or raise.

    A module error is named from the runtime metadata of its own block, as
    the pinned client names it (``sync_substrate.py:282-292``). Any other
    ``DispatchError`` variant keeps its variant name and plain detail.
    """

    if isinstance(error, Mapping) and set(error) == {"Module"}:
        body = error["Module"]
        if isinstance(body, (list, tuple)):
            pallet_index, raw_error = body
        elif isinstance(body, Mapping) and "index" in body and "error" in body:
            pallet_index, raw_error = body["index"], body["error"]
        else:
            raise _Undecodable("dispatch module error is malformed")
        # The metadata matches a pallet by equality, so True or 7.0 would
        # name another pallet's error or this one's under a wrong index.
        if isinstance(pallet_index, bool) or not isinstance(pallet_index, int):
            raise _Undecodable("dispatch module index is invalid")
        error_index = _module_error_index(raw_error)
        named = metadata.get_module_error(
            module_index=pallet_index, error_index=error_index
        )
        name = getattr(named, "name", None)
        docs = getattr(named, "docs", None)
        if not isinstance(name, str) or not name:
            raise _Undecodable("dispatch module error is not named by its runtime")
        return {
            "type": "Module",
            "pallet_index": pallet_index,
            "error_index": error_index,
            "name": name,
            "docs": [str(line) for line in docs]
            if isinstance(docs, (list, tuple))
            else [],
        }
    if isinstance(error, str) and error:
        return {"type": "System", "name": error, "detail": None}
    if isinstance(error, Mapping):
        # Exactly one variant; anything else fails to unpack and stays raw.
        ((name, detail),) = error.items()
        if isinstance(name, str) and name:
            return {"type": "System", "name": name, "detail": _plain_detail(detail)}
    raise _Undecodable("dispatch error is not decodable")


def _read_fresh_snapshot(
    subtensor: Any, keypair: Any, *, netuid: int
) -> FinalizedMetagraphSnapshot:
    # Keep the writer's contract module independent of the collection runtime.
    from .direct_validator import finalized_serving_miners_snapshot

    return finalized_serving_miners_snapshot(subtensor, keypair, netuid)


def _hotkey_public_key(keypair: Any) -> bytes:
    """Return the signer's 32-byte public key, bound to its SS58 address.

    The chain applies a revealed payload only when the ``hotkey`` inside it
    decodes to the committing account (``reveal_commits.rs:142-150``), so the
    key is derived from the address that signs and cross-checked against the
    key the keypair reports.
    """

    address = str(getattr(keypair, "ss58_address", ""))
    try:
        derived = bytes(ss58_address_to_bytes(address))
    except Exception as exc:
        raise DirectValidatorError(
            "validator hotkey address does not decode to a public key"
        ) from exc
    declared = getattr(keypair, "public_key", None)
    if len(derived) != 32 or (declared is not None and bytes(declared) != derived):
        raise DirectValidatorError(
            "validator hotkey public key does not match its address"
        )
    return derived


def direct_state_scope(netuid: int) -> str:
    """Return the journal directory that scopes one subnet's mechanism writes.

    For the compiled netuid this is byte-identical to the scope every earlier
    release wrote, which is where existing hosts keep their journal and where
    the updater and status tool, which still spell it out, look for it.
    """

    return f"finney-sn{require_netuid(netuid)}-mechanism-{MECID}"


def canonical_state_path(keypair: Any, *, netuid: int = NETUID) -> Path:
    """Return the one operational journal path for this Finney signer and netuid.

    The default is the compiled netuid for callers that predate the setting;
    the validator's entry point always passes the value it resolved.
    """

    hotkey = str(getattr(keypair, "ss58_address", ""))
    if not hotkey or not hotkey.isascii() or not hotkey.isalnum() or len(hotkey) > 64:
        raise DirectValidatorError("direct writer hotkey is not path-safe")
    return DIRECT_STATE_ROOT / direct_state_scope(netuid) / hotkey / "state.json"


def cycle_lock_path_for_state(state_path: Path) -> Path:
    """Return the lock shared by one signer cycle and the local updater.

    The path is derived from the journal rather than configuration so a root
    updater cannot accidentally lock a different signer from the validator it
    restarts.
    """

    if not state_path.is_absolute() or state_path.name != "state.json":
        raise DirectValidatorError("direct state path is not canonical")
    return state_path.with_name("cycle.lock")


class DirectWeightWriter:
    """One in-process writer. The journal is its sole retry authority.

    ``netuid`` is the one subnet this writer signs for. It scopes the journal,
    every pre-sign chain read, and the exact call, and a plan read on any other
    subnet is refused. The default is the compiled netuid for callers that
    predate the setting; the validator's entry point always passes it.
    """

    def __init__(
        self,
        *,
        subtensor: Any,
        keypair: Any,
        snapshot_reader: Callable[[Any, Any], FinalizedMetagraphSnapshot] | None = None,
        call_builder: Callable[[Mapping[str, Any]], Any] | None = None,
        netuid: int = NETUID,
        commit_reveal: CommitRevealOptIn | None = None,
        commit_encryptor: Callable[..., tuple[bytes, int]] | None = None,
        commit_call_builder: Callable[[Mapping[str, Any]], Any] | None = None,
        hotkey_public_key: Callable[[Any], bytes] | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.subtensor = subtensor
        self.keypair = keypair
        self.netuid = require_netuid(netuid)
        self.state_path = canonical_state_path(keypair, netuid=self.netuid)
        self.snapshot_reader = snapshot_reader or partial(
            _read_fresh_snapshot, netuid=self.netuid
        )
        self.call_builder = call_builder or self._build_call
        # Timelocked commit-reveal is off unless the operator opted in. With it
        # absent every path below is the one earlier releases ran. Recovery of
        # a journaled commit never depends on it: a commit signed under the
        # opt-in is still recovered and proven after the opt-in is removed.
        if commit_reveal is not None and not isinstance(
            commit_reveal, CommitRevealOptIn
        ):
            raise DirectValidatorError("commit-reveal opt-in is invalid")
        self.commit_reveal = commit_reveal
        self.commit_encryptor = commit_encryptor
        self.commit_call_builder = commit_call_builder or self._build_commit_call
        self.hotkey_public_key = hotkey_public_key or _hotkey_public_key
        self.wall_clock = wall_clock

    def _prepare_parent(self) -> None:
        parent = self.state_path.parent
        if parent.is_symlink():
            raise DirectValidatorError("direct state parent is a symlink")
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise DirectValidatorError("direct state parent is unusable") from exc
        metadata = parent.stat()
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise DirectValidatorError("direct state parent is not owner-controlled")

    @contextmanager
    def _exclusive_runtime_lock(
        self, path: Path, *, label: str, wait: bool
    ) -> Iterator[None]:
        """Hold one owner-only process lock, optionally waiting for handoff.

        Cycle locking is intentionally outside the narrower journal lock.  It
        covers recovery, evidence collection, signing, submission, and final
        confirmation as one indivisible updater boundary.
        """

        self._prepare_parent()
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise DirectSubmissionAmbiguous(f"{label} lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise DirectSubmissionAmbiguous(f"{label} lock is not owner-only")
            if wait:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            else:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise DirectSubmissionAmbiguous(
                        f"another process holds the direct {label} lock"
                    ) from exc
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @contextmanager
    def cycle_locked(self) -> Iterator[None]:
        """Exclude a local update for this signer's complete direct cycle."""

        with self._exclusive_runtime_lock(
            cycle_lock_path_for_state(self.state_path), label="cycle", wait=True
        ):
            yield

    @contextmanager
    def process_locked(self) -> Iterator[None]:
        """Ensure one recurring direct-validator process per signer."""

        with self._exclusive_runtime_lock(
            self.state_path.with_name("process.lock"), label="process", wait=False
        ):
            yield

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._prepare_parent()
        local = _local_lock(self.state_path)
        if not local.acquire(blocking=False):
            raise DirectSubmissionAmbiguous("another direct writer holds this state")
        descriptor: int | None = None
        try:
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.state_path.with_suffix(".lock"), flags, 0o600)
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DirectSubmissionAmbiguous(
                    "another process holds the direct writer lock"
                ) from exc
            yield
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
            local.release()

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return _initial_state()
        if self.state_path.is_symlink():
            raise DirectSubmissionContradiction("direct state is a symlink")
        metadata = self.state_path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_STATE_BYTES
        ):
            raise DirectSubmissionContradiction("direct state file is not owner-only")
        try:
            raw = self.state_path.read_bytes()
        except OSError as exc:
            raise DirectSubmissionAmbiguous("direct state could not be read") from exc
        document = _strict_json(raw)
        if (
            set(document) != {"schema", "pending", "last_attempt"}
            or document.get("schema") != STATE_SCHEMA
        ):
            raise DirectSubmissionContradiction("direct state schema is invalid")
        if document["pending"] is not None and not isinstance(
            document["pending"], dict
        ):
            raise DirectSubmissionContradiction("direct pending state is invalid")
        if document["last_attempt"] is not None and not isinstance(
            document["last_attempt"], dict
        ):
            raise DirectSubmissionContradiction("direct last attempt is invalid")
        return document

    def _write_state(self, document: Mapping[str, Any]) -> None:
        if set(document) != {"schema", "pending", "last_attempt"}:
            raise DirectSubmissionContradiction("direct state fields are invalid")
        body = canonical_document_bytes(document)
        if len(body) > MAX_STATE_BYTES:
            raise DirectSubmissionContradiction("direct state exceeds 1 MiB")
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=self.state_path.parent,
                prefix=f".{self.state_path.name}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.state_path)
            temporary = None
            directory = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise DirectSubmissionAmbiguous(
                "direct state could not be persisted"
            ) from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _build_call(self, kwargs: Mapping[str, Any]) -> Any:
        return SubtensorModule(self.subtensor).set_mechanism_weights(
            netuid=int(kwargs["netuid"]),
            mecid=int(kwargs["mecid"]),
            dests=list(kwargs["dests"]),
            weights=list(kwargs["weights"]),
            version_key=int(kwargs["version_key"]),
        )

    def _build_commit_call(self, document: Mapping[str, Any]) -> Any:
        # The same composer the pinned SDK uses for this call (bittensor 10.5.0
        # core/extrinsics/weights.py:103-109).
        return SubtensorModule(self.subtensor).commit_timelocked_mechanism_weights(
            netuid=int(document["netuid"]),
            mecid=int(document["mecid"]),
            commit=bytes.fromhex(str(document["commit"])[2:]),
            reveal_round=int(document["reveal_round"]),
            commit_reveal_version=int(document["commit_reveal_version"]),
        )

    def _validate_plan(self, plan: DirectWeightPlan) -> dict[str, Any]:
        if not isinstance(plan, DirectWeightPlan):
            raise DirectValidatorError("direct writer requires a DirectWeightPlan")
        if (
            isinstance(plan.netuid, bool)
            or not isinstance(plan.netuid, int)
            or plan.netuid != self.netuid
        ):
            raise DirectValidatorError(
                "direct plan was read on another netuid than this writer signs for"
            )
        kwargs = plan.kwargs()
        # The submit layer repeats the comparison: the plan's netuid is the
        # call's, and this writer's is the only one it may sign for.
        expected = build_mechanism_weights_kwargs(
            dests=list(plan.wire_uids),
            weights=list(plan.wire_weights),
            netuid=plan.netuid,
            expected_netuid=self.netuid,
        )
        if kwargs != expected or kwargs != {
            "netuid": self.netuid,
            "mecid": MECID,
            "dests": list(plan.wire_uids),
            "weights": list(plan.wire_weights),
            "version_key": VERSION_KEY,
        }:
            raise DirectValidatorError("direct plan is not an exact zero-burn vector")
        uid_hotkeys = dict(plan.uid_hotkeys)
        raw_scores = dict(plan.raw_scores)
        machine_ids = dict(plan.machine_ids_by_uid)
        snapshot_hotkeys = {miner.uid: miner.hotkey for miner in plan.snapshot.miners}
        expected_uids, expected_weights = zero_burn_vector(plan.raw_scores, uid_hotkeys)
        if (
            len(uid_hotkeys) != len(plan.uid_hotkeys)
            or len(raw_scores) != len(plan.raw_scores)
            or len(machine_ids) != len(plan.machine_ids_by_uid)
            or uid_hotkeys != snapshot_hotkeys
            or set(raw_scores) != set(uid_hotkeys)
            or set(machine_ids) != set(uid_hotkeys)
            or any(
                not isinstance(ids, tuple)
                or len(ids) != raw_scores[uid]
                or len(ids) != len(set(ids))
                or any(not isinstance(value, str) or not value for value in ids)
                for uid, ids in machine_ids.items()
            )
            or len({value for ids in machine_ids.values() for value in ids})
            != sum(len(ids) for ids in machine_ids.values())
            or plan.wire_uids != expected_uids
            or plan.wire_weights != expected_weights
            or set(plan.wire_uids)
            != {uid for uid, score in raw_scores.items() if score > 0}
            or any(uid not in uid_hotkeys for uid in plan.wire_uids)
            or plan.snapshot.validator_uid in plan.wire_uids
            or sum(plan.wire_weights) != 0xFFFF
            or plan.qvl_digest != DIRECT_VALIDATOR_QVL_DIGEST
            or not isinstance(plan.evidence_digest, str)
            or not plan.evidence_digest.startswith("sha256:")
            or len(plan.evidence_digest) != 71
            or any(
                character not in _CHAIN_HASH_HEX
                for character in plan.evidence_digest[7:]
            )
        ):
            raise DirectValidatorError("direct plan UID identities are inconsistent")
        if str(getattr(self.keypair, "ss58_address", "")) != (
            plan.snapshot.validator_hotkey
        ) or not callable(getattr(self.keypair, "sign", None)):
            raise DirectValidatorError("direct writer key does not match the plan")
        return kwargs

    def _require_fresh_snapshot(
        self,
        plan: DirectWeightPlan,
        fresh: FinalizedMetagraphSnapshot,
        *,
        presign_deadline: float,
    ) -> None:
        _require_presign_time(presign_deadline, stage="freshness preflight")
        anchor = plan.snapshot
        if fresh.netuid != anchor.netuid:
            raise DirectValidatorError(
                "fresh snapshot was read on another netuid than the plan"
            )
        anchor_miners = anchor.miner_by_uid()
        fresh_miners = fresh.miner_by_uid()
        if (
            fresh.block_number < anchor.block_number
            or fresh.block_number - anchor.block_number >= MORTAL_PERIOD_BLOCKS
            or fresh.validator_uid != anchor.validator_uid
            or fresh.validator_hotkey != anchor.validator_hotkey
            or fresh.miners != anchor.miners
            or fresh_miners != anchor_miners
        ):
            raise DirectValidatorError(
                "validator or serving miner set changed before direct signing"
            )
        try:
            canonical = _canonical_hash(
                self.subtensor.substrate.get_block_hash(anchor.block_number),
                label="evidence anchor",
            )
        except DirectSubmissionAmbiguous as exc:
            raise DirectValidatorError("evidence anchor cannot be rechecked") from exc
        _require_presign_time(presign_deadline, stage="anchor freshness RPC")
        if canonical != anchor.block_hash:
            raise DirectValidatorError("evidence anchor is no longer canonical")

    def _require_finalized_eligibility(
        self,
        plan: DirectWeightPlan,
        fresh: FinalizedMetagraphSnapshot,
        *,
        presign_deadline: float,
    ) -> dict[str, object]:
        """Refuse every deterministic chain-policy failure before signing."""

        block = fresh.block_number
        try:
            _require_presign_time(presign_deadline, stage="eligibility preflight")
            rate_limit = _nonnegative_int(
                self.subtensor.weights_rate_limit(self.netuid, block=block),
                label="SN94 weight cooldown",
            )
            _require_presign_time(presign_deadline, stage="weight cooldown RPC")
            blocks_since = _nonnegative_int(
                self.subtensor.blocks_since_last_update(
                    self.netuid, fresh.validator_uid, block=block
                ),
                label="validator blocks since last update",
            )
            _require_presign_time(presign_deadline, stage="last-update RPC")
            min_allowed = _nonnegative_int(
                self.subtensor.min_allowed_weights(netuid=self.netuid, block=block),
                label="SN94 minimum allowed weights",
            )
            _require_presign_time(presign_deadline, stage="minimum-weights RPC")
            commit_reveal = _strict_bool(
                self.subtensor.commit_reveal_enabled(netuid=self.netuid, block=block),
                label="SN94 commit-reveal state",
            )
            _require_presign_time(presign_deadline, stage="commit-reveal RPC")
            mechanism_count = _nonnegative_int(
                self.subtensor.get_mechanism_count(self.netuid, block=block),
                label="SN94 mechanism count",
            )
            _require_presign_time(presign_deadline, stage="mechanism-count RPC")
            metagraph = self.subtensor.metagraph(self.netuid, block=block)
            _require_presign_time(presign_deadline, stage="eligibility metagraph RPC")
            if (
                _nonnegative_int(
                    int(getattr(metagraph, "block", -1)),
                    label="eligibility metagraph block",
                )
                != block
            ):
                raise DirectValidatorError(
                    "eligibility metagraph is not at the finalized sign head"
                )
            uids = [int(value) for value in list(metagraph.uids)]
            hotkeys = [str(value) for value in list(metagraph.hotkeys)]
            permits = list(metagraph.validator_permit)
            last_updates = [
                _nonnegative_int(int(value), label="validator last update")
                for value in list(metagraph.last_update)
            ]
            info = self.subtensor.get_metagraph_info(self.netuid, MECID, block=block)
            _require_presign_time(presign_deadline, stage="metagraph-info RPC")
            if info is None or int(getattr(info, "block", -1)) != block:
                raise DirectValidatorError(
                    "SN94 metagraph info is not at the finalized sign head"
                )
            info_hotkeys = [str(value) for value in list(info.hotkeys)]
            info_permits = tuple(
                _strict_bool(value, label="finalized metagraph-info permit")
                for value in list(info.validator_permit)
            )
            info_stakes = list(info.total_stake)
            # SubnetworkN at the sign head, taken from the answer just read
            # rather than from another RPC: the chain's metagraph runtime API
            # reports it as `num_uids` and builds `hotkeys` over exactly
            # `0..num_uids`, so the two are cross-checked below.
            subnet_n = _nonnegative_int(
                getattr(info, "num_uids", None),
                label="subnet registered UID count",
            )
            stake_threshold = _nonnegative_int(
                self.subtensor.substrate.query(
                    module="SubtensorModule",
                    storage_function="StakeThreshold",
                    params=[],
                    block_hash=fresh.block_hash,
                ),
                label="weight stake threshold",
            )
            _require_presign_time(presign_deadline, stage="stake-threshold RPC")
            version_key = _nonnegative_int(
                self.subtensor.substrate.query(
                    module="SubtensorModule",
                    storage_function="WeightsVersionKey",
                    params=[self.netuid],
                    block_hash=fresh.block_hash,
                ),
                label="SN94 weight version",
            )
            _require_presign_time(presign_deadline, stage="weight-version RPC")
        except DirectValidatorError:
            raise
        except Exception as exc:
            raise DirectValidatorError(
                "finalized direct-write eligibility is unavailable"
            ) from exc

        strict_permits = tuple(
            _strict_bool(value, label="finalized validator permit") for value in permits
        )
        if (
            not (len(uids) == len(hotkeys) == len(permits) == len(last_updates))
            or len(set(uids)) != len(uids)
            or len(set(hotkeys)) != len(hotkeys)
        ):
            raise DirectValidatorError("finalized eligibility rows are inconsistent")
        matches = [
            index
            for index, value in enumerate(hotkeys)
            if value == fresh.validator_hotkey
        ]
        if (
            len(matches) != 1
            or uids[matches[0]] != fresh.validator_uid
            or strict_permits[matches[0]] is not True
        ):
            raise DirectValidatorError("validator is not eligible at the sign head")
        if not (
            len(info_hotkeys) == len(info_permits) == len(info_stakes) == subnet_n
            and 0 <= fresh.validator_uid < len(info_hotkeys)
            and info_hotkeys[fresh.validator_uid] == fresh.validator_hotkey
            and info_permits[fresh.validator_uid] is True
        ):
            raise DirectValidatorError(
                "validator metagraph-info eligibility is inconsistent"
            )
        validator_stake = _balance_rao(
            info_stakes[fresh.validator_uid], label="validator effective stake"
        )
        if validator_stake < stake_threshold:
            raise DirectValidatorError(
                "validator is below the finalized weight stake threshold"
            )
        last_update = last_updates[matches[0]]
        if block - last_update != blocks_since:
            raise DirectValidatorError(
                "validator last update and cooldown distance disagree"
            )
        if rate_limit < MORTAL_PERIOD_BLOCKS:
            raise DirectValidatorError("SN94 cooldown is shorter than the mortal era")
        if blocks_since < rate_limit:
            raise DirectValidatorError(
                "validator is inside the finalized weight cooldown"
            )
        # Mirror the chain's `check_length` (pallets/subtensor/src/subnets/
        # weights.rs): at least min(SubnetworkN, MinAllowedWeights) weights, or
        # a lone self-weight, which this plan never is (`_validate_plan`
        # excludes the validator's own UID). A shorter vector passes the pool
        # and fails at dispatch, which halts the writer, so it is refused here;
        # a vector that meets the rule is signed whatever MinAllowedWeights is.
        # The plan names only registered UIDs other than the validator's own,
        # so it is always shorter than SubnetworkN and the cap never changes
        # the decision, only the requirement the refusal reports: with
        # MinAllowedWeights above SubnetworkN the chain demands every
        # registered UID, which a writer that excludes itself cannot meet.
        required_weights = min(subnet_n, min_allowed)
        if len(plan.wire_uids) < required_weights:
            raise DirectValidatorError(
                f"direct vector has {len(plan.wire_uids)} weights but the chain "
                f"requires at least {required_weights} "
                f"(MinAllowedWeights {min_allowed}, SubnetworkN {subnet_n})"
            )
        # No maximum-weight check: the chain compares against a constant
        # u16::MAX (`get_max_weight_limit`, pallets/subtensor/src/utils/misc.rs)
        # and never reads the `MaxWeightsLimit` storage behind the SDK's
        # `max_weight_limit()`, so a legacy stored value must not refuse a
        # write the chain accepts. It is not read.
        if self.commit_reveal is None:
            if commit_reveal is not COMMIT_REVEAL_ENABLED:
                # The chain refuses a plain weight call while commit-reveal is
                # on. The refusal names both ways out: the subnet owner's
                # command, and this host's opt-in. bittensor-cli 9.23.2
                # `sudo set` takes the hyperparameter as `--param` (or
                # `--parameter`); `--name` is its alias for `--wallet-name`.
                raise DirectValidatorError(
                    f"subnet {self.netuid} has commit_reveal_weights_enabled "
                    "set, and this validator is not opted in to timelocked "
                    "commits, so nothing was signed. The subnet owner turns it "
                    f"off with `btcli sudo set --netuid {self.netuid} "
                    "--param commit_reveal_weights_enabled --value false`, and "
                    "the validator writes on its next cycle after that. "
                    f"Otherwise the operator opts in with {COMMIT_REVEAL_OPT_IN_ENV} "
                    '(docs/AUTO_UPDATE.md "Commit-reveal subnets")'
                )
        elif commit_reveal is not True:
            # The opt-in names the chain policy the operator expects. A chain
            # that turned commit-reveal off is not silently written in plain
            # text by a process configured for commits.
            raise DirectValidatorError(
                "chain commit-reveal is disabled but the operator opted in to "
                f"timelocked commits; remove {COMMIT_REVEAL_OPT_IN_ENV} to write "
                "plain weights"
            )
        if mechanism_count <= MECID:
            raise DirectValidatorError("SN94 mechanism 0 is unavailable")
        if version_key != 0 and VERSION_KEY < version_key:
            raise DirectValidatorError(
                "direct weight version is below the chain minimum"
            )
        return {
            "block_number": block,
            "block_hash": fresh.block_hash,
            "validator_last_update": last_update,
            "blocks_since_last_update": blocks_since,
            "weights_rate_limit": rate_limit,
            "min_allowed_weights": min_allowed,
            "subnetwork_n": subnet_n,
            "commit_reveal_enabled": commit_reveal,
            "mechanism_count": mechanism_count,
            "weights_version_key": version_key,
            "validator_stake_rao": validator_stake,
            "stake_threshold_rao": stake_threshold,
        }

    def _raw_storage(
        self, module: str, function: str, params: list[Any], block_hash: str
    ) -> Any:
        """Read one storage value at one block, telling absence from failure.

        The pinned client's ``query`` answers a node error, such as state the
        node already discarded, with the storage default
        (``async_substrate_interface/sync_substrate.py:1771-1779``). That
        reads exactly like a real empty value; on Finney a block about 400
        deep reads ``SubnetEpochIndex`` as 0 that way. Every read that
        concludes anything from absence goes through ``state_getStorage``
        instead: a node that cannot serve the block raises, and ``None``
        means the key is really unset at that block.
        """

        substrate = self.subtensor.substrate
        try:
            key = substrate.create_storage_key(
                module, function, params, block_hash=block_hash
            )
            response = substrate.rpc_request(
                "state_getStorage", [key.to_hex(), block_hash]
            )
            if (
                not isinstance(response, Mapping)
                or "error" in response
                or "result" not in response
            ):
                raise ValueError("storage response has no result")
            result = response["result"]
            if result is None:
                return None
            if not isinstance(result, str) or not result.startswith("0x"):
                raise ValueError("storage response is not hex")
            decoded = substrate.decode_scale(
                key.value_scale_type, bytes.fromhex(result[2:])
            )
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                f"{module}.{function} at {block_hash} is unreadable"
            ) from exc
        return getattr(decoded, "value", decoded)

    def _require_commit_reveal_context(
        self,
        fresh: FinalizedMetagraphSnapshot,
        *,
        presign_deadline: float,
    ) -> dict[str, Any]:
        """Refuse a timelocked commit unless the chain matches the opt-in.

        Everything is read at the finalized sign head: the reveal period and
        payload version the opt-in names, the epoch schedule bittensor-drand
        predicts the reveal from, the chain's own drand head, and every commit
        of this hotkey the chain still holds. A defaulted read is refused, a
        commit that could land in the next epoch is refused, and a local clock
        that disagrees with the chain's drand head is refused.
        """

        opt_in = self.commit_reveal
        if opt_in is None:
            raise DirectValidatorError("commit-reveal context without an opt-in")
        substrate = self.subtensor.substrate
        block_hash = fresh.block_hash
        index = int(get_mechid_storage_index(self.netuid, MECID))

        def read(module: str, function: str, params: list[Any]) -> int:
            value = _nonnegative_int(
                substrate.query(
                    module=module,
                    storage_function=function,
                    params=params,
                    block_hash=block_hash,
                ),
                label=f"{module}.{function}",
            )
            _require_presign_time(presign_deadline, stage=f"{function} RPC")
            return value

        try:
            _require_presign_time(presign_deadline, stage="commit-reveal preflight")
            public_key = self.hotkey_public_key(self.keypair)
            reveal_period = read("SubtensorModule", "RevealPeriodEpochs", [self.netuid])
            version = read("SubtensorModule", "CommitRevealWeightsVersion", [])
            schedule = EpochSchedule(
                last_epoch_block=read(
                    "SubtensorModule", "LastEpochBlock", [self.netuid]
                ),
                pending_epoch_at=read(
                    "SubtensorModule", "PendingEpochAt", [self.netuid]
                ),
                subnet_epoch_index=read(
                    "SubtensorModule", "SubnetEpochIndex", [self.netuid]
                ),
                tempo=read("SubtensorModule", "Tempo", [self.netuid]),
                blocks_since_last_step=read(
                    "SubtensorModule", "BlocksSinceLastStep", [self.netuid]
                ),
                current_block=fresh.block_number,
            )
            drand_head = read("Drand", "LastStoredRound", [])
            outstanding = 0
            # Commits are keyed by the epoch they landed in and removed once
            # their reveal epoch passes, so these keys hold every live one.
            for epoch in range(
                max(0, schedule.subnet_epoch_index - reveal_period),
                schedule.subnet_epoch_index + 2,
            ):
                stored = self._raw_storage(
                    "SubtensorModule",
                    "TimelockedWeightCommits",
                    [index, epoch],
                    block_hash,
                )
                _require_presign_time(presign_deadline, stage="stored commits RPC")
                rows = decoded_commit_rows([] if stored is None else stored)
                if rows is None:
                    raise DirectValidatorError(
                        "stored timelocked commits are malformed"
                    )
                outstanding += sum(row[0] == fresh.validator_hotkey for row in rows)
        except DirectSubmissionAmbiguous as exc:
            raise DirectValidatorError(
                "finalized commit-reveal state is unreadable"
            ) from exc
        except DirectValidatorError:
            raise
        except Exception as exc:
            raise DirectValidatorError(
                "finalized commit-reveal state is unavailable"
            ) from exc
        if reveal_period != opt_in.reveal_period_epochs:
            raise DirectValidatorError(
                f"chain reveal period is {reveal_period} epochs but the opt-in "
                f"expects {opt_in.reveal_period_epochs}"
            )
        if version != COMMIT_REVEAL_VERSION:
            raise DirectValidatorError(
                f"chain commit-reveal version is {version}, not the pinned "
                f"{COMMIT_REVEAL_VERSION}"
            )
        if (
            schedule.tempo == 0
            or schedule.subnet_epoch_index == 0
            or schedule.last_epoch_block == 0
            or drand_head == 0
        ):
            raise DirectValidatorError(
                "finalized commit-reveal state reads as storage defaults"
            )
        if outstanding:
            raise DirectValidatorError(
                "this hotkey already has an unrevealed timelocked commit on chain"
            )
        next_epoch = next_epoch_fire_block(schedule)
        if next_epoch <= fresh.block_number + MORTAL_PERIOD_BLOCKS:
            # The chain keys a commit by the epoch of its inclusion block. One
            # that lands in the next epoch reveals an epoch after the round it
            # was encrypted to, so anyone could read it an epoch early.
            raise DirectValidatorError(
                f"the next epoch starts at block {next_epoch}, inside the "
                f"signing era of block {fresh.block_number}"
            )
        first_reveal = predict_first_reveal_block(schedule, reveal_period)
        expected_round = chain_expected_reveal_round(
            drand_last_stored_round=drand_head,
            sign_block=fresh.block_number,
            first_reveal_block=first_reveal,
        )
        local_round = drand_round_at(float(self.wall_clock()))
        if abs(local_round - drand_head) > DRAND_ROUND_TOLERANCE:
            raise DirectValidatorError(
                f"local clock is at drand round {local_round} but the chain's "
                f"drand head at the sign block is {drand_head}"
            )
        _require_presign_time(presign_deadline, stage="commit-reveal preflight")
        return {
            "reveal_period_epochs": reveal_period,
            "commit_reveal_version": version,
            "hotkey_public_key": "0x" + public_key.hex(),
            "schedule": schedule,
            "drand_last_stored_round": drand_head,
            "next_epoch_block": next_epoch,
            "first_reveal_block": first_reveal,
            "expected_reveal_round": expected_round,
            "local_drand_round": local_round,
        }

    def _timelocked_commit(
        self,
        kwargs: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        presign_deadline: float,
    ) -> dict[str, Any]:
        """Encrypt the exact plan vector and check the round it was locked to.

        The ciphertext comes from the pinned library call the SDK itself makes
        (bittensor-drand 2.0.0 ``get_encrypted_commit_v2``), over the same
        dests, weights and version key the plain call would carry. Its reveal
        round depends on the local clock, so it must agree with the round the
        chain's own drand head predicts before anything is signed.
        """

        schedule = context["schedule"]
        encryptor = self.commit_encryptor or default_commit_encryptor()
        try:
            commit, reveal_round = encryptor(
                uids=list(kwargs["dests"]),
                weights=list(kwargs["weights"]),
                version_key=int(kwargs["version_key"]),
                last_epoch_block=schedule.last_epoch_block,
                pending_epoch_at=schedule.pending_epoch_at,
                subnet_epoch_index=schedule.subnet_epoch_index,
                tempo=schedule.tempo,
                blocks_since_last_step=schedule.blocks_since_last_step,
                current_block=schedule.current_block,
                subnet_reveal_period_epochs=context["reveal_period_epochs"],
                block_time=float(BLOCK_TIME_SECONDS),
                hotkey=bytes.fromhex(context["hotkey_public_key"][2:]),
            )
        except Exception as exc:
            raise DirectValidatorError(
                "timelocked commit could not be encrypted"
            ) from exc
        _require_presign_time(presign_deadline, stage="commit encryption")
        if (
            not isinstance(commit, (bytes, bytearray))
            or not 0 < len(commit) <= MAX_COMMIT_BYTES
        ):
            raise DirectValidatorError("timelocked commit is not a bounded byte string")
        if not _plain_nonnegative(reveal_round):
            raise DirectValidatorError("timelocked commit reveal round is invalid")
        if reveal_round <= context["drand_last_stored_round"]:
            raise DirectValidatorError(
                f"reveal round {reveal_round} is already on chain"
            )
        if abs(reveal_round - context["expected_reveal_round"]) > DRAND_ROUND_TOLERANCE:
            raise DirectValidatorError(
                f"reveal round {reveal_round} disagrees with the chain-derived "
                f"round {context['expected_reveal_round']}"
            )
        return {
            "call": COMMIT_REVEAL_CALL,
            "commit": "0x" + bytes(commit).hex(),
            "reveal_round": reveal_round,
            "commit_reveal_version": context["commit_reveal_version"],
            "reveal_period_epochs": context["reveal_period_epochs"],
            "block_time_seconds": BLOCK_TIME_SECONDS,
            "hotkey_public_key": context["hotkey_public_key"],
            "schedule": schedule.document(),
            "drand_last_stored_round": context["drand_last_stored_round"],
            "next_epoch_block": context["next_epoch_block"],
            "first_reveal_block": context["first_reveal_block"],
            "expected_reveal_round": context["expected_reveal_round"],
            "local_drand_round": context["local_drand_round"],
        }

    def _require_broadcast_window(
        self,
        substrate: Any,
        *,
        era_reference: int,
        presign_deadline: float,
    ) -> None:
        """Refuse to journal or broadcast a signature that can no longer land.

        The era is anchored on the finalized sign head, and signing itself
        makes chain calls (runtime, genesis and birth-block lookups) after the
        last cooperative deadline check. So the deadline is checked again and
        the best head the node validates against is read. A refusal here comes
        before the intent is journaled: the signature is dropped from memory,
        no node has seen it, and the next cycle signs a fresh plan.
        """

        _require_presign_time(presign_deadline, stage="signing")
        try:
            best = _nonnegative_int(substrate.get_block_number(None), label="best head")
        except DirectValidatorError:
            raise
        except Exception as exc:
            raise DirectValidatorError(
                "best head is unavailable before broadcast"
            ) from exc
        _require_presign_time(presign_deadline, stage="best-head RPC")
        if best < era_reference:
            # A node behind the sign head recomputes an older birth block, so
            # it would reject the signature outright.
            raise DirectValidatorError(
                f"best head {best} is behind the signed era anchor {era_reference}"
            )
        if best >= era_reference + MORTAL_PERIOD_BLOCKS - BROADCAST_ERA_MARGIN_BLOCKS:
            raise DirectValidatorError(
                f"best head {best} leaves fewer than {BROADCAST_ERA_MARGIN_BLOCKS} "
                f"blocks of the era signed at {era_reference}"
            )

    def _last_anchor(self, state: Mapping[str, Any]) -> int | None:
        last = state.get("last_attempt")
        if last is None:
            return None
        try:
            value = last["identity"]["anchor"]["block_number"]
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "last direct attempt lost its anchor"
            ) from exc
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DirectSubmissionContradiction("last direct anchor is invalid")
        return value

    def _pending(self, state: Mapping[str, Any]) -> dict[str, Any] | None:
        pending = state.get("pending")
        if pending is None:
            return None
        required = {"attempt_id", "phase", "identity", "intent", "receipt", "error"}
        if not isinstance(pending, dict) or set(pending) != required:
            raise DirectSubmissionContradiction("pending direct intent is malformed")
        attempt_id = pending.get("attempt_id")
        if (
            not isinstance(attempt_id, str)
            or not attempt_id.startswith("sha256:")
            or len(attempt_id) != 71
            or not isinstance(pending.get("identity"), dict)
            or not isinstance(pending.get("intent"), dict)
        ):
            raise DirectSubmissionContradiction("pending direct identity is malformed")
        digest = _attempt_id(pending["identity"], pending["intent"])
        if digest != attempt_id:
            raise DirectSubmissionContradiction("pending direct attempt id is wrong")
        return pending

    def _exact_call(
        self, observed: Mapping[str, Any], intent: Mapping[str, Any]
    ) -> bool:
        call = observed.get("call")
        kwargs = intent.get("kwargs")
        if not isinstance(call, Mapping) or not isinstance(kwargs, Mapping):
            return False
        commit = _commit_reveal_document(intent)
        if commit is not None:
            # The pinned client decodes the ciphertext argument as 0x hex
            # (observed on Finney SN94 commits).
            return (
                str(observed.get("address")) == str(intent.get("validator_hotkey"))
                and call.get("call_module") == "SubtensorModule"
                and call.get("call_function") == COMMIT_REVEAL_CALL_FUNCTION
                and _chain_call_arg(call, "netuid") == kwargs.get("netuid")
                and _chain_call_arg(call, "mecid") == kwargs.get("mecid")
                and canonical_bytes_hex(_chain_call_arg(call, "commit"))
                == commit["commit"]
                and _chain_call_arg(call, "reveal_round") == commit["reveal_round"]
                and _chain_call_arg(call, "commit_reveal_version")
                == commit["commit_reveal_version"]
            )
        return (
            str(observed.get("address")) == str(intent.get("validator_hotkey"))
            and call.get("call_module") == "SubtensorModule"
            and call.get("call_function") == "set_mechanism_weights"
            and _chain_call_arg(call, "netuid") == kwargs.get("netuid")
            and _chain_call_arg(call, "mecid") == kwargs.get("mecid")
            and _chain_call_arg(call, "version_key") == kwargs.get("version_key")
            and _chain_call_arg(call, "dests") == kwargs.get("dests")
            and _chain_call_arg(call, "weights") == kwargs.get("weights")
        )

    def _confirmation_contract(
        self, pending: Mapping[str, Any]
    ) -> tuple[int, str, dict[int, str], tuple[int, ...], tuple[int, ...]]:
        identity = pending.get("identity")
        intent = pending.get("intent")
        if not isinstance(identity, Mapping) or not isinstance(intent, Mapping):
            raise DirectSubmissionContradiction("confirmation identity is unavailable")
        anchor = identity.get("anchor")
        validator = anchor.get("validator") if isinstance(anchor, Mapping) else None
        miners = anchor.get("miners") if isinstance(anchor, Mapping) else None
        uid_rows = identity.get("uid_hotkeys")
        kwargs = intent.get("kwargs")
        if (
            identity.get("schema") != DIRECT_PLAN_SCHEMA
            or identity.get("qvl_digest") != DIRECT_VALIDATOR_QVL_DIGEST
            or identity.get("burn_uid") is not None
            or identity.get("burn_weight") != 0
            or identity.get("kwargs") != kwargs
            or not isinstance(validator, Mapping)
            or not isinstance(miners, list)
            or not isinstance(uid_rows, list)
            or not isinstance(kwargs, Mapping)
        ):
            raise DirectSubmissionContradiction("confirmation identity is malformed")
        validator_uid = validator.get("uid")
        validator_hotkey = validator.get("hotkey")
        if (
            isinstance(validator_uid, bool)
            or not isinstance(validator_uid, int)
            or not isinstance(validator_hotkey, str)
            or not validator_hotkey
            or intent.get("validator_hotkey") != validator_hotkey
        ):
            raise DirectSubmissionContradiction(
                "confirmation signer identity is malformed"
            )
        uid_hotkeys: dict[int, str] = {}
        for row in uid_rows:
            if (
                not isinstance(row, list)
                or len(row) != 2
                or isinstance(row[0], bool)
                or not isinstance(row[0], int)
                or not isinstance(row[1], str)
                or not row[1]
                or row[0] in uid_hotkeys
            ):
                raise DirectSubmissionContradiction(
                    "confirmation miner identity is malformed"
                )
            uid_hotkeys[row[0]] = row[1]
        anchor_hotkeys: dict[int, str] = {}
        for row in miners:
            if not isinstance(row, Mapping):
                raise DirectSubmissionContradiction(
                    "confirmation anchor miner is malformed"
                )
            uid = row.get("uid")
            hotkey = row.get("hotkey")
            if (
                isinstance(uid, bool)
                or not isinstance(uid, int)
                or not isinstance(hotkey, str)
                or not hotkey
                or uid in anchor_hotkeys
            ):
                raise DirectSubmissionContradiction(
                    "confirmation anchor miner identity is malformed"
                )
            anchor_hotkeys[uid] = hotkey
        try:
            dests = tuple(kwargs["dests"])
            weights = tuple(kwargs["weights"])
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "confirmation weight vector is malformed"
            ) from exc
        if (
            uid_hotkeys != anchor_hotkeys
            or not dests
            or len(dests) != len(weights)
            or set(dests) - set(uid_hotkeys)
            or validator_uid in dests
        ):
            raise DirectSubmissionContradiction(
                "confirmation weight identities disagree"
            )
        try:
            expected_kwargs = build_mechanism_weights_kwargs(
                dests=dests,
                weights=weights,
                netuid=self.netuid,
                expected_netuid=self.netuid,
            )
        except Exception as exc:
            raise DirectSubmissionContradiction(
                "confirmation weight vector is invalid"
            ) from exc
        if expected_kwargs != dict(kwargs):
            raise DirectSubmissionContradiction(
                "confirmation weight identities disagree"
            )
        return validator_uid, validator_hotkey, uid_hotkeys, dests, weights

    def _prove_stored_state(
        self,
        *,
        block_number: int,
        block_hash: str,
        validator_uid: int,
        validator_hotkey: str,
        uid_hotkeys: Mapping[int, str],
        dests: tuple[int, ...],
        weights: tuple[int, ...],
        require_dest_mapping: bool,
    ) -> None:
        try:
            canonical = _canonical_hash(
                _uncached_block_hash(self.subtensor.substrate, block_number),
                label="confirmation block",
            )
            # The metagraph names its block by number only, so the client's
            # cached lookup of this height must name the canonical block too.
            _correct_cached_block_hash(self.subtensor, block_number, canonical)
            metagraph = self.subtensor.metagraph(self.netuid, block=block_number)
            metagraph_block = int(getattr(metagraph, "block", -1))
            uids = [int(value) for value in list(metagraph.uids)]
            hotkeys = [str(value) for value in list(metagraph.hotkeys)]
            permits = tuple(
                _strict_bool(value, label="confirmation validator permit")
                for value in list(metagraph.validator_permit)
            )
            stored = self.subtensor.substrate.query(
                module="SubtensorModule",
                storage_function="Weights",
                params=[get_mechid_storage_index(self.netuid, MECID), validator_uid],
                block_hash=block_hash,
            )
            stored_rows = _stored_weight_rows(stored)
        except DirectSubmissionContradiction:
            raise
        except DirectSubmissionAmbiguous:
            raise
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                f"finalized confirmation block {block_number} is unavailable"
            ) from exc
        if canonical != block_hash or metagraph_block != block_number:
            raise DirectSubmissionAmbiguous(
                f"finalized confirmation block {block_number} is not canonical"
            )
        if (
            not (len(uids) == len(hotkeys) == len(permits))
            or len(set(uids)) != len(uids)
            or len(set(hotkeys)) != len(hotkeys)
        ):
            raise DirectSubmissionAmbiguous(
                f"finalized metagraph at {block_number} is inconsistent"
            )
        uid_to_index = {uid: index for index, uid in enumerate(uids)}
        validator_index = uid_to_index.get(validator_uid)
        if (
            validator_index is None
            or hotkeys[validator_index] != validator_hotkey
            or permits[validator_index] is not True
        ):
            raise DirectSubmissionContradiction(
                f"validator mapping changed at finalized block {block_number}"
            )
        if require_dest_mapping:
            for uid in dests:
                index = uid_to_index.get(uid)
                if index is None or hotkeys[index] != uid_hotkeys[uid]:
                    raise DirectSubmissionContradiction(
                        "weighted miner mapping changed at finalized block "
                        f"{block_number}"
                    )
        expected_stored_rows = tuple(zip(dests, _subtensor_max_upscale_to_u16(weights)))
        if stored_rows != expected_stored_rows:
            raise DirectSubmissionContradiction(
                f"stored mechanism row differs at finalized block {block_number}"
            )

    def _confirm_finalized_effect(
        self,
        pending: Mapping[str, Any],
        located: DirectSubmissionReceipt,
        *,
        recovered: bool,
    ) -> DirectSubmissionReceipt:
        if located.block_number is None or located.block_hash is None:
            raise DirectSubmissionContradiction(
                "finalized extrinsic has no inclusion block"
            )
        deadline = time.monotonic() + CONFIRMATION_WAIT_SECONDS
        while True:
            try:
                finalized_number, _finalized_hash = finalized_head(self.subtensor)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "later finalized heads are unavailable"
                ) from exc
            if finalized_number >= located.block_number + 2:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectSubmissionAmbiguous(
                    "two later finalized heads are not available yet"
                )
            time.sleep(min(CONFIRMATION_POLL_SECONDS, remaining))
        contract = self._confirmation_contract(pending)
        block_numbers = (
            located.block_number,
            located.block_number + 1,
            located.block_number + 2,
        )
        proven: list[tuple[int, str]] = []
        for block_number in block_numbers:
            try:
                raw_block_hash = _uncached_block_hash(
                    self.subtensor.substrate, block_number
                )
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    f"confirmation block {block_number} hash is unavailable"
                ) from exc
            try:
                block_hash = _canonical_hash(raw_block_hash, label="confirmation block")
            except DirectSubmissionAmbiguous as exc:
                raise DirectSubmissionAmbiguous(
                    f"confirmation block {block_number} hash is invalid"
                ) from exc
            if (
                block_number == located.block_number
                and block_hash != located.block_hash
            ):
                raise DirectSubmissionContradiction(
                    "finalized inclusion hash is no longer canonical"
                )
            self._prove_stored_state(
                block_number=block_number,
                block_hash=block_hash,
                validator_uid=contract[0],
                validator_hotkey=contract[1],
                uid_hotkeys=contract[2],
                dests=contract[3],
                weights=contract[4],
                require_dest_mapping=block_number == located.block_number,
            )
            proven.append((block_number, block_hash))
        return DirectSubmissionReceipt(
            status=STATUS_RECOVERED if recovered else STATUS_CONFIRMED,
            attempt_id=located.attempt_id,
            extrinsic_hash=located.extrinsic_hash,
            block_hash=located.block_hash,
            block_number=located.block_number,
            recovered=recovered,
            confirmation_heads=tuple(proven),
        )

    def _confirm_effect(
        self,
        pending: Mapping[str, Any],
        located: DirectSubmissionReceipt,
        *,
        recovered: bool,
    ) -> tuple[DirectSubmissionReceipt, dict[str, Any] | None]:
        """Prove what a finalized successful write changed, by write kind.

        A plain write is proven exactly as before. A timelocked commit changes
        no weights until the chain reveals it, so its effect is the stored
        commit, and the returned record lets later cycles prove the reveal.
        """

        if _commit_reveal_document(pending.get("intent")) is None:
            return (
                self._confirm_finalized_effect(pending, located, recovered=recovered),
                None,
            )
        return self._confirm_commit_stored(pending, located, recovered=recovered)

    def _canonical_height(self, block_number: int, *, label: str) -> str:
        try:
            return _canonical_hash(
                _uncached_block_hash(self.subtensor.substrate, block_number),
                label=label,
            )
        except DirectSubmissionAmbiguous:
            raise
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                f"{label} {block_number} hash is unavailable"
            ) from exc

    def _confirm_commit_stored(
        self,
        pending: Mapping[str, Any],
        located: DirectSubmissionReceipt,
        *,
        recovered: bool,
    ) -> tuple[DirectSubmissionReceipt, dict[str, Any]]:
        """Prove the exact commit is stored where the chain will reveal it.

        At the finalized inclusion block, under the epoch key the chain gave
        it (``weights.rs:365-401``), the hotkey holds exactly one entry and it
        is ``(hotkey, inclusion block, ciphertext, reveal round)``; the commit
        also moved this UID's ``LastUpdate`` to that block. Two later heads
        must be finalized, as for a plain write.
        """

        if located.block_number is None or located.block_hash is None:
            raise DirectSubmissionContradiction(
                "finalized extrinsic has no inclusion block"
            )
        deadline = time.monotonic() + CONFIRMATION_WAIT_SECONDS
        while True:
            try:
                finalized_number, _finalized_hash = finalized_head(self.subtensor)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "later finalized heads are unavailable"
                ) from exc
            if finalized_number >= located.block_number + 2:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectSubmissionAmbiguous(
                    "two later finalized heads are not available yet"
                )
            time.sleep(min(CONFIRMATION_POLL_SECONDS, remaining))
        validator_uid, validator_hotkey, _uids, _dests, _weights = (
            self._confirmation_contract(pending)
        )
        commit = _commit_reveal_document(pending["intent"])
        heads: list[tuple[int, str]] = []
        for block_number in range(located.block_number, located.block_number + 3):
            block_hash = self._canonical_height(
                block_number, label="confirmation block"
            )
            if (
                block_number == located.block_number
                and block_hash != located.block_hash
            ):
                raise DirectSubmissionContradiction(
                    "finalized inclusion hash is no longer canonical"
                )
            heads.append((block_number, block_hash))
        index = int(get_mechid_storage_index(self.netuid, MECID))
        inclusion = located.block_hash
        epoch = self._raw_storage(
            "SubtensorModule", "SubnetEpochIndex", [self.netuid], inclusion
        )
        if not _plain_nonnegative(epoch) or epoch == 0:
            raise DirectSubmissionAmbiguous(
                f"epoch index at commit block {located.block_number} is unreadable"
            )
        signed_row = (
            validator_hotkey,
            located.block_number,
            commit["commit"],
            commit["reveal_round"],
        )
        keys: list[int] = []
        # The commit belongs to the look-ahead epoch of its block: the stored
        # counter, or one more when that block's epoch was deferred.
        for key in (epoch, epoch + 1):
            stored = self._raw_storage(
                "SubtensorModule", "TimelockedWeightCommits", [index, key], inclusion
            )
            rows = decoded_commit_rows([] if stored is None else stored)
            if rows is None:
                raise DirectSubmissionAmbiguous(
                    f"stored commits at block {located.block_number} are unreadable"
                )
            mine = [row for row in rows if row[0] == validator_hotkey]
            if signed_row in mine:
                if len(mine) != 1:
                    raise DirectSubmissionContradiction(
                        "another timelocked commit of this hotkey is stored beside "
                        "the signed one"
                    )
                keys.append(key)
            elif mine:
                raise DirectSubmissionContradiction(
                    "another timelocked commit of this hotkey is stored"
                )
        if len(keys) != 1:
            raise DirectSubmissionContradiction(
                "the signed timelocked commit is not stored at its inclusion block"
            )
        last_update = self._raw_storage(
            "SubtensorModule", "LastUpdate", [index], inclusion
        )
        owner = self._raw_storage(
            "SubtensorModule", "Keys", [self.netuid, validator_uid], inclusion
        )
        if (
            not isinstance(last_update, (list, tuple))
            or validator_uid >= len(last_update)
            or last_update[validator_uid] != located.block_number
        ):
            raise DirectSubmissionContradiction(
                "the commit did not set this validator's last update"
            )
        if owner != validator_hotkey:
            raise DirectSubmissionContradiction(
                f"validator mapping changed at finalized block {located.block_number}"
            )
        receipt = DirectSubmissionReceipt(
            status=STATUS_COMMITTED,
            attempt_id=located.attempt_id,
            extrinsic_hash=located.extrinsic_hash,
            block_hash=located.block_hash,
            block_number=located.block_number,
            recovered=recovered,
            confirmation_heads=tuple(heads),
        )
        reveal = {
            "commit_epoch": keys[0],
            "present_through_block": located.block_number,
            "outcome": None,
        }
        return receipt, reveal

    def _commit_presence(
        self, block_number: int, *, index: int, key: int, row: tuple[Any, ...]
    ) -> tuple[bool, int]:
        """Whether the exact stored commit is still held at one finalized block.

        Presence is positive evidence. Absence is concluded only from a
        storage read the node answered, at a block whose epoch index it also
        answered as a real value.
        """

        block_hash = self._canonical_height(block_number, label="reveal search block")
        stored = self._raw_storage(
            "SubtensorModule", "TimelockedWeightCommits", [index, key], block_hash
        )
        rows = decoded_commit_rows([] if stored is None else stored)
        if rows is None:
            raise DirectSubmissionAmbiguous(
                f"stored commits at block {block_number} are unreadable"
            )
        matches = sum(candidate == row for candidate in rows)
        if matches > 1:
            raise DirectSubmissionContradiction(
                "the signed timelocked commit is stored more than once"
            )
        epoch = self._raw_storage(
            "SubtensorModule", "SubnetEpochIndex", [self.netuid], block_hash
        )
        if not _plain_nonnegative(epoch) or epoch == 0 or epoch + 1 < key:
            raise DirectSubmissionAmbiguous(
                f"epoch index at block {block_number} is unreadable"
            )
        return matches == 1, epoch

    def _block_events(self, block_hash: str, block_number: int) -> list[Mapping]:
        """Events of one block, refusing the empty list a failed read becomes."""

        try:
            events = self.subtensor.substrate.get_events(block_hash=block_hash)
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                f"events of block {block_number} are unavailable"
            ) from exc
        if not isinstance(events, (list, tuple)) or not all(
            isinstance(record, Mapping) and isinstance(record.get("event"), Mapping)
            for record in events
        ):
            raise DirectSubmissionAmbiguous(
                f"events of block {block_number} are unreadable"
            )
        # Every block applies its timestamp inherent, so a real event list is
        # never without an extrinsic outcome.
        if not any(
            (record["event"].get("module_id"), record["event"].get("event_id"))
            in {("System", "ExtrinsicSuccess"), ("System", "ExtrinsicFailed")}
            for record in events
        ):
            raise DirectSubmissionAmbiguous(
                f"events of block {block_number} hold no extrinsic outcome"
            )
        return list(events)

    def _reveal_count(
        self, events: list[Mapping], *, index: int, hotkey: str, block_number: int
    ) -> int:
        count = 0
        for record in events:
            event = record["event"]
            if (event.get("module_id"), event.get("event_id")) != (
                "SubtensorModule",
                "TimelockedWeightsRevealed",
            ):
                continue
            attributes = event.get("attributes")
            # TimelockedWeightsRevealed(NetUidStorageIndex, AccountId)
            # (macros/events.rs:428), decoded as [index, "ss58"].
            if (
                not isinstance(attributes, (list, tuple))
                or len(attributes) != 2
                or not _plain_nonnegative(attributes[0])
                or not isinstance(attributes[1], str)
            ):
                raise DirectSubmissionAmbiguous(
                    f"a reveal event of block {block_number} is unreadable"
                )
            if attributes[0] == index and attributes[1] == hotkey:
                count += 1
        return count

    def _prove_revealed_rows(
        self,
        consumed: int,
        contract: tuple[int, str, dict[int, str], tuple[int, ...], tuple[int, ...]],
        *,
        index: int,
    ) -> tuple[tuple[tuple[int, str], ...], list[list[Any]]]:
        """Prove the stored row the reveal wrote, and name any remapped UID.

        The chain stores the max-upscaled vector (``weights.rs:835-851``),
        read here at the reveal block and two later finalized blocks. The
        commit was signed about an epoch earlier, so a weighted UID may have
        been re-registered to another hotkey by the reveal block; that is the
        chain's fact to report, not a contradiction to stop on.
        """

        validator_uid, validator_hotkey, uid_hotkeys, dests, weights = contract
        expected = tuple(zip(dests, _subtensor_max_upscale_to_u16(weights)))
        heads: list[tuple[int, str]] = []
        for block_number in range(consumed, consumed + 3):
            block_hash = self._canonical_height(
                block_number, label="reveal confirmation block"
            )
            stored = self._raw_storage(
                "SubtensorModule", "Weights", [index, validator_uid], block_hash
            )
            owner = self._raw_storage(
                "SubtensorModule", "Keys", [self.netuid, validator_uid], block_hash
            )
            if stored is None or _stored_weight_rows(stored) != expected:
                raise DirectSubmissionContradiction(
                    f"stored mechanism row differs at finalized block {block_number}"
                )
            if owner != validator_hotkey:
                raise DirectSubmissionContradiction(
                    f"validator mapping changed at finalized block {block_number}"
                )
            heads.append((block_number, block_hash))
        remapped: list[list[Any]] = []
        for uid in dests:
            owner = self._raw_storage(
                "SubtensorModule", "Keys", [self.netuid, uid], heads[0][1]
            )
            if owner != uid_hotkeys[uid]:
                remapped.append(
                    [uid, uid_hotkeys[uid], owner if isinstance(owner, str) else None]
                )
        return tuple(heads), remapped

    def _record_reveal_unproven(
        self,
        state: dict[str, Any],
        last: dict[str, Any],
        receipt: Mapping[str, Any],
        *,
        head_number: int,
        error: Exception,
    ) -> DirectSubmissionReceipt:
        """Close a commit that is gone but whose reveal can no longer be read.

        The finalized head no longer holds the commit, read from state the
        node served, so the chain will never reveal it again. The blocks that
        would say whether it applied are older than a pruning node keeps, so
        waiting cannot prove anything more on this node. The attempt is
        recorded as unproven, not applied or failed, and the writer goes on:
        the next commit's own pre-sign check still refuses while any commit of
        this hotkey is stored.
        """

        head_hash = self._canonical_height(head_number, label="finalized head")
        reveal = dict(last["reveal"])
        reveal["outcome"] = {
            "applied": None,
            "absent_at_block": head_number,
            "absent_at_block_hash": head_hash,
            "unreadable": f"{type(error).__name__}: {error}"[:256],
        }
        last["status"] = STATUS_REVEAL_UNPROVEN
        last["reveal"] = reveal
        self._write_state(state)
        _LOG.warning(
            "timelocked commit %s is no longer stored at finalized block %d, and "
            "the history that proves its reveal is unreadable here: %s",
            receipt["extrinsic_hash"],
            head_number,
            error,
        )
        return DirectSubmissionReceipt(
            status=STATUS_REVEAL_UNPROVEN,
            attempt_id=str(last["attempt_id"]),
            extrinsic_hash=str(receipt["extrinsic_hash"]),
            block_hash=head_hash,
            block_number=head_number,
            recovered=True,
        )

    def _resolve_reveal(self, state: dict[str, Any]) -> DirectSubmissionReceipt | None:
        """Prove what the chain's automatic reveal did with the last commit.

        Nothing is signed or sent. While the exact stored commit is still
        held, the reveal is awaited. Once finalized state no longer holds it,
        the block that consumed it is found and its events read: the chain's
        ``TimelockedWeightsRevealed`` for this hotkey plus the exact stored row
        prove the vector applied; its absence proves the commit was dropped
        without writing anything (``reveal_commits.rs:73-200``).
        """

        last = state.get("last_attempt")
        if not isinstance(last, dict) or last.get("status") != STATUS_COMMITTED:
            return None
        identity = last.get("identity")
        intent = last.get("intent")
        receipt = last.get("receipt")
        reveal = last.get("reveal")
        if (
            set(last) != _COMMITTED_ATTEMPT_FIELDS
            or not isinstance(identity, dict)
            or not isinstance(intent, dict)
            or _attempt_id(identity, intent) != last.get("attempt_id")
            or not isinstance(receipt, dict)
            or receipt.get("status") != STATUS_COMMITTED
            or receipt.get("attempt_id") != last.get("attempt_id")
            or receipt.get("extrinsic_hash") != intent.get("extrinsic_hash")
            or not _plain_nonnegative(receipt.get("block_number"))
            or not isinstance(reveal, dict)
            or set(reveal) != _REVEAL_FIELDS
            or reveal["outcome"] is not None
            or not _plain_nonnegative(reveal["commit_epoch"])
            or not _plain_nonnegative(reveal["present_through_block"])
            or reveal["present_through_block"] < receipt["block_number"]
        ):
            raise DirectSubmissionContradiction(
                "committed timelocked attempt is malformed"
            )
        commit = _commit_reveal_document(intent)
        if commit is None:
            raise DirectSubmissionContradiction(
                "committed attempt carries no timelocked commit"
            )
        contract = self._confirmation_contract(last)
        validator_hotkey = contract[1]
        index = int(get_mechid_storage_index(self.netuid, MECID))
        commit_block = receipt["block_number"]
        row = (validator_hotkey, commit_block, commit["commit"], commit["reveal_round"])
        key = reveal["commit_epoch"]
        awaiting = DirectSubmissionReceipt(
            status=STATUS_AWAITING_REVEAL,
            attempt_id=str(last["attempt_id"]),
            extrinsic_hash=str(receipt["extrinsic_hash"]),
            block_hash=receipt.get("block_hash"),
            block_number=commit_block,
            recovered=True,
        )
        try:
            head_number, _head_hash = finalized_head(self.subtensor)
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                "finalized head is unavailable during reveal recovery"
            ) from exc
        low = reveal["present_through_block"]
        if head_number <= low:
            return awaiting
        present, head_epoch = self._commit_presence(
            head_number, index=index, key=key, row=row
        )
        if present:
            # Commits whose reveal epoch passed are removed, so one held for
            # longer than any reveal period can be is not a waiting commit.
            if head_epoch > key + MAX_REVEAL_PERIOD_EPOCHS + 1:
                raise DirectSubmissionContradiction(
                    "the timelocked commit outlived every possible reveal epoch"
                )
            reveal["present_through_block"] = head_number
            self._write_state(state)
            return awaiting
        try:
            low_present, _low_epoch = self._commit_presence(
                low, index=index, key=key, row=row
            )
            if not low_present:
                raise DirectSubmissionContradiction(
                    f"the stored commit proven at block {low} is no longer read there"
                )
            high = head_number
            while high - low > 1:
                middle = (low + high) // 2
                middle_present, _epoch = self._commit_presence(
                    middle, index=index, key=key, row=row
                )
                if middle_present:
                    low = middle
                else:
                    high = middle
            consumed = high
            if head_number < consumed + 2:
                reveal["present_through_block"] = low
                self._write_state(state)
                return awaiting
            consumed_hash = self._canonical_height(consumed, label="reveal block")
            events = self._block_events(consumed_hash, consumed)
            revealed = self._reveal_count(
                events, index=index, hotkey=validator_hotkey, block_number=consumed
            )
            proof = (
                self._prove_revealed_rows(consumed, contract, index=index)
                if revealed == 1
                else None
            )
        except DirectSubmissionContradiction:
            raise
        except DirectSubmissionAmbiguous as exc:
            if head_number - reveal["present_through_block"] <= (
                REVEAL_HISTORY_LIMIT_BLOCKS
            ):
                raise
            return self._record_reveal_unproven(
                state, last, receipt, head_number=head_number, error=exc
            )
        if revealed > 1:
            raise DirectSubmissionContradiction(
                f"block {consumed} revealed this hotkey's commit more than once"
            )
        if revealed == 0:
            last["status"] = STATUS_REVEAL_NOT_APPLIED
            last["reveal"] = {
                "commit_epoch": key,
                "present_through_block": low,
                "outcome": {
                    "applied": False,
                    "consumed_block": consumed,
                    "consumed_block_hash": consumed_hash,
                },
            }
            self._write_state(state)
            raise DirectCommitNotRevealed(
                f"timelocked commit {receipt['extrinsic_hash']} was consumed at "
                f"block {consumed} without applying its weights; nothing was "
                "written. The chain refused the revealed vector (stake, permit, "
                "version key or payload) or its drand pulse never arrived. "
                f"{_REVEAL_NOT_APPLIED_ACTION}"
            )
        heads, remapped = proof
        last["status"] = STATUS_REVEALED
        last["reveal"] = {
            "commit_epoch": key,
            "present_through_block": low,
            "outcome": {
                "applied": True,
                "consumed_block": consumed,
                "consumed_block_hash": consumed_hash,
                "confirmation_heads": [list(head) for head in heads],
                "remapped_dests": remapped,
            },
        }
        self._write_state(state)
        if remapped:
            _LOG.warning(
                "revealed weights landed on %d UID(s) re-registered since the "
                "commit: %s",
                len(remapped),
                remapped,
            )
        return DirectSubmissionReceipt(
            status=STATUS_REVEALED,
            attempt_id=str(last["attempt_id"]),
            extrinsic_hash=str(receipt["extrinsic_hash"]),
            block_hash=consumed_hash,
            block_number=consumed,
            recovered=True,
            confirmation_heads=heads,
        )

    def _await_finalized_history(
        self, pending: Mapping[str, Any]
    ) -> tuple[str, DirectSubmissionReceipt | None]:
        """Re-read finalized history until it settles or the bound is reached.

        Only the finalized head is polled between lookups; the era is re-read
        once per new finalized head, never on a timer, and never resubmitted.
        """

        deadline = time.monotonic() + FINALIZED_HISTORY_WAIT_SECONDS
        scanned_head: int | None = None
        while True:
            try:
                head_number, _head_hash = finalized_head(self.subtensor)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "finalized head is unavailable after submission"
                ) from exc
            if scanned_head is None or head_number > scanned_head:
                status, located = self._locate(pending, finalized_number=head_number)
                scanned_head = head_number
                if status != "pending":
                    return status, located
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "pending", None
            time.sleep(min(CONFIRMATION_POLL_SECONDS, remaining))

    def _signed_intent(self, pending: Mapping[str, Any]) -> tuple[str, int, int]:
        """Return the journaled hash, era anchor and period, or refuse."""

        intent = pending["intent"]
        try:
            extrinsic_hash = _canonical_hash(
                intent["extrinsic_hash"], label="signed extrinsic"
            )
            era_reference = intent["era_reference_block"]
            period = intent["mortal_period_blocks"]
            kwargs = intent["kwargs"]
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "pending signed intent is incomplete"
            ) from exc
        if not isinstance(kwargs, Mapping):
            raise DirectSubmissionContradiction("pending signed kwargs are invalid")
        try:
            # Rebuilt for this writer's netuid, so an intent signed for any
            # other subnet is a contradiction here, never a call to look for.
            expected_kwargs = build_mechanism_weights_kwargs(
                dests=list(kwargs.get("dests", ())),
                weights=list(kwargs.get("weights", ())),
                netuid=self.netuid,
                expected_netuid=self.netuid,
            )
        except Exception as exc:
            raise DirectSubmissionContradiction(
                "pending signed weight vector is invalid"
            ) from exc
        if (
            isinstance(era_reference, bool)
            or not isinstance(era_reference, int)
            or era_reference <= 0
            or period != MORTAL_PERIOD_BLOCKS
            or kwargs != expected_kwargs
        ):
            raise DirectSubmissionContradiction("pending signed intent is invalid")
        # A journaled timelocked commit must still be the exact record signed.
        _commit_reveal_document(intent)
        return extrinsic_hash, era_reference, period

    def _locate(
        self,
        pending: Mapping[str, Any],
        *,
        finalized_number: int | None = None,
    ) -> tuple[str, DirectSubmissionReceipt | None]:
        intent = pending["intent"]
        extrinsic_hash, era_reference, period = self._signed_intent(pending)

        if finalized_number is None:
            try:
                finalized_number, _finalized_hash = finalized_head(self.subtensor)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "finalized head is unavailable during recovery"
                ) from exc
        substrate = self.subtensor.substrate
        matches: list[DirectSubmissionReceipt] = []
        for block_number in range(era_reference, era_reference + period):
            if block_number > finalized_number:
                continue
            try:
                block_hash = _canonical_hash(
                    _uncached_block_hash(substrate, block_number),
                    label="recovery block",
                )
                block = substrate.get_block(block_hash=block_hash)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "authorized mortal era is not fully readable"
                ) from exc
            extrinsics = block.get("extrinsics") if isinstance(block, Mapping) else None
            if not isinstance(extrinsics, (list, tuple)):
                raise DirectSubmissionAmbiguous("recovery block has no extrinsics")
            for item in extrinsics:
                observed = getattr(item, "value", item)
                if not isinstance(observed, Mapping):
                    continue
                raw_hash = getattr(item, "extrinsic_hash", None)
                if raw_hash is None:
                    raw_hash = observed.get("extrinsic_hash")
                if raw_hash is None:
                    raise DirectSubmissionAmbiguous("recovery extrinsic has no hash")
                try:
                    observed_hash = _canonical_hash(
                        raw_hash, label="recovery extrinsic"
                    )
                except DirectSubmissionAmbiguous as exc:
                    raise DirectSubmissionAmbiguous(
                        "recovery extrinsic has an invalid hash"
                    ) from exc
                if observed_hash != extrinsic_hash:
                    continue
                if not self._exact_call(observed, intent):
                    raise DirectSubmissionContradiction(
                        "signed hash resolved to a different chain call"
                    )
                try:
                    receipt = substrate.retrieve_extrinsic_by_hash(
                        block_hash, extrinsic_hash
                    )
                    success = getattr(receipt, "is_success", None)
                    error = getattr(receipt, "error_message", None)
                except Exception as exc:
                    raise DirectSubmissionAmbiguous(
                        "exact chain call has no execution receipt"
                    ) from exc
                if success is not True or error is not None:
                    return "failed", None
                matches.append(
                    DirectSubmissionReceipt(
                        status=_STATUS_EXTRINSIC_FINALIZED,
                        attempt_id=str(pending["attempt_id"]),
                        extrinsic_hash=extrinsic_hash,
                        block_hash=block_hash,
                        block_number=block_number,
                        recovered=True,
                    )
                )
        if len(matches) > 1:
            raise DirectSubmissionContradiction(
                "signed hash appeared more than once in finalized history"
            )
        if matches:
            return "finalized", matches[0]
        if finalized_number >= era_reference + period - 1:
            return "expired", DirectSubmissionReceipt(
                status=STATUS_EXPIRED,
                attempt_id=str(pending["attempt_id"]),
                extrinsic_hash=extrinsic_hash,
                block_hash=None,
                block_number=None,
                recovered=True,
            )
        return "pending", None

    def _finish(
        self,
        state: dict[str, Any],
        pending: Mapping[str, Any],
        receipt: DirectSubmissionReceipt,
        *,
        reveal: dict[str, Any] | None = None,
    ) -> DirectSubmissionReceipt:
        state["last_attempt"] = {
            "attempt_id": pending["attempt_id"],
            "status": receipt.status,
            "identity": pending["identity"],
            "intent": pending["intent"],
            "receipt": receipt.as_document(),
        }
        if reveal is not None:
            # Only a proven timelocked commit carries this; later cycles
            # prove its reveal from it.
            state["last_attempt"]["reveal"] = reveal
        state["pending"] = None
        self._write_state(state)
        return receipt

    def recover(self) -> DirectSubmissionReceipt | None:
        """Confirm one signed hash and stored row without signing or resubmitting."""

        with self._locked():
            state = self._read_state()
            pending = self._pending(state)
            if pending is None:
                # A REVEAL_NOT_APPLIED stop persists across restarts: it is
                # raised again on every start until the record command moves
                # it on, as a finalized_failed pending intent is.
                stop = _reveal_not_applied_stop(state)
                if stop is not None:
                    raise stop
                # Only a proven timelocked commit has anything left to prove;
                # for every other journal this returns None exactly as before.
                return self._resolve_reveal(state)
            status, receipt = self._locate(pending)
            if status == "finalized" and receipt is not None:
                try:
                    confirmed, reveal = self._confirm_effect(
                        pending, receipt, recovered=True
                    )
                except DirectSubmissionContradiction as exc:
                    pending["phase"] = "confirmation_contradiction"
                    pending["receipt"] = receipt.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                except DirectSubmissionAmbiguous as exc:
                    pending["phase"] = "included_awaiting_confirmation"
                    pending["receipt"] = receipt.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                return self._finish(state, pending, confirmed, reveal=reveal)
            if status == "expired" and receipt is not None:
                return self._finish(state, pending, receipt)
            if status == "failed":
                pending["phase"] = PHASE_FINALIZED_FAILED
                state["pending"] = pending
                self._write_state(state)
                raise DirectSubmissionFinalizedFailure(
                    "signed direct extrinsic finalized with failure"
                )
            raise DirectSubmissionAmbiguous(
                "signed direct extrinsic is unresolved; recovery will not retry it"
            )

    @contextmanager
    def _record_locks(self) -> Iterator[None]:
        """Hold every lock of this signer without waiting, or refuse.

        The process lock proves no validator process runs, the cycle lock is
        the one the validator's cycles and the updater share, and the journal
        lock serializes every journal write. A busy lock is a refusal, never a
        wait, so the record cannot interleave with a validator or an update.
        """

        with ExitStack() as stack:
            try:
                stack.enter_context(self.process_locked())
                stack.enter_context(
                    self._exclusive_runtime_lock(
                        cycle_lock_path_for_state(self.state_path),
                        label="cycle",
                        wait=False,
                    )
                )
                stack.enter_context(self._locked())
            except (DirectValidatorError, OSError) as exc:
                # A busy lock, or a lock or directory this user cannot open.
                raise FailedWriteRecordRefused(f"{type(exc).__name__}: {exc}") from exc
            yield

    def record_finalized_failure(self) -> dict[str, Any]:
        """Prove that the pending write failed on chain, then record it terminal.

        This is the only way to clear an intent the validator stopped on with
        ``finalized_failed``. It never signs or broadcasts and needs no key.
        It refuses unless every lock of this signer is free and the journal
        holds exactly that stop. It then proves from finalized chain state
        that the journaled hash is in exactly one block of its fully finalized
        era, as the exact journaled call, and that the block's events hold one
        ``System.ExtrinsicFailed`` and no success for that extrinsic index.
        Only then does the intent move to ``last_attempt`` as
        ``FINALIZED_FAILED``: its identity and intent unchanged, the pending
        record's own phase, receipt and error kept beside the proof. Its
        anchor keeps fencing reuse, and the next write reads a fresh nonce
        from the chain. Every refusal leaves the journal unchanged.

        A node that cannot serve that history raises
        ``FailedWriteHistoryUnreadable`` instead of a refusal, also with the
        journal unchanged.

        The same command clears the other stop the validator never clears by
        itself: a ``REVEAL_NOT_APPLIED`` last attempt, which
        ``_reveal_not_applied_record`` records as reviewed.
        """

        try:
            missing = self.state_path.is_symlink() or not self.state_path.is_file()
        except OSError as exc:
            raise FailedWriteRecordRefused(
                f"direct writer journal is not accessible: {exc}"
            ) from exc
        if missing:
            raise FailedWriteRecordRefused(
                "no direct writer journal exists at the canonical path"
            )
        with self._record_locks():
            try:
                state, record = self._proven_failure_record()
            except (FailedWriteRecordRefused, FailedWriteHistoryUnreadable):
                raise
            except Exception as exc:
                raise FailedWriteRecordRefused(f"{type(exc).__name__}: {exc}") from exc
            self._write_state(state)
        return record

    def _proven_failure_record(self) -> tuple[dict[str, Any], dict[str, Any]]:
        state = self._read_state()
        pending = self._pending(state)
        if pending is None:
            last = state.get("last_attempt")
            last_status = last.get("status") if isinstance(last, dict) else None
            if last_status == STATUS_REVEAL_NOT_APPLIED:
                return self._reveal_not_applied_record(state, last)
            raise FailedWriteRecordRefused(
                f"journal has no pending intent (last attempt: {last_status})"
            )
        if pending["phase"] != PHASE_FINALIZED_FAILED:
            raise FailedWriteRecordRefused(
                f"pending intent is {pending['phase']!r}, not "
                f"{PHASE_FINALIZED_FAILED!r}; only the validator's recovery "
                "may resolve it"
            )
        intent = pending["intent"]
        if intent.get("validator_hotkey") != str(
            getattr(self.keypair, "ss58_address", "")
        ):
            raise FailedWriteRecordRefused("pending intent names another signer")
        extrinsic_hash, era_reference, period = self._signed_intent(pending)
        proof = self._prove_finalized_failure(
            intent,
            extrinsic_hash=extrinsic_hash,
            era_reference=era_reference,
            period=period,
        )
        receipt = DirectSubmissionReceipt(
            status=STATUS_FINALIZED_FAILED,
            attempt_id=str(pending["attempt_id"]),
            extrinsic_hash=extrinsic_hash,
            block_hash=proof["block_hash"],
            block_number=proof["block_number"],
            recovered=True,
        )
        state["last_attempt"] = {
            "attempt_id": pending["attempt_id"],
            "status": STATUS_FINALIZED_FAILED,
            "identity": pending["identity"],
            "intent": intent,
            "receipt": receipt.as_document(),
            "failure": {
                **proof,
                "pending_phase": pending["phase"],
                "pending_receipt": pending["receipt"],
                "pending_error": pending["error"],
            },
        }
        state["pending"] = None
        record = {
            "attempt_id": pending["attempt_id"],
            "extrinsic_hash": extrinsic_hash,
            "block_number": proof["block_number"],
            "block_hash": proof["block_hash"],
            "extrinsic_index": proof["extrinsic_index"],
            "dispatch_error": proof["dispatch_error"],
        }
        return state, record

    def _reveal_not_applied_record(
        self, state: dict[str, Any], last: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Record a ``REVEAL_NOT_APPLIED`` stop as reviewed, or refuse.

        The validator proved the stop from finalized state when it wrote it:
        the exact commit stored through one block and gone at the next, with
        no ``TimelockedWeightsRevealed`` for this hotkey in that block. The
        chain never reveals a commit it no longer holds, so nothing of this
        attempt can still land, and recording it cannot double-write. The
        stop exists so that an operator looks before another commit is
        signed. This record is that operator's explicit step, so it reads no
        chain history; by the time an operator acts, a pruning node no longer
        serves those blocks anyway. It validates the journaled attempt in
        full, for this writer's signer and netuid, and changes only the
        status to ``REVEAL_NOT_APPLIED_RECORDED``: the proof, intent and
        anchor stay, so the anchor keeps fencing reuse.
        """

        intent = last.get("intent")
        if not isinstance(intent, dict) or intent.get("validator_hotkey") != str(
            getattr(self.keypair, "ss58_address", "")
        ):
            raise FailedWriteRecordRefused("stopped attempt names another signer")
        identity = last.get("identity")
        receipt = last.get("receipt")
        reveal = last.get("reveal")
        outcome = reveal.get("outcome") if isinstance(reveal, dict) else None
        if (
            set(last) != _COMMITTED_ATTEMPT_FIELDS
            or not isinstance(identity, dict)
            or _attempt_id(identity, intent) != last.get("attempt_id")
            or not isinstance(receipt, dict)
            or receipt.get("status") != STATUS_COMMITTED
            or receipt.get("attempt_id") != last.get("attempt_id")
            or receipt.get("extrinsic_hash") != intent.get("extrinsic_hash")
            or not _plain_nonnegative(receipt.get("block_number"))
            or not isinstance(reveal, dict)
            or set(reveal) != _REVEAL_FIELDS
            or not _plain_nonnegative(reveal["commit_epoch"])
            or not _plain_nonnegative(reveal["present_through_block"])
            or not isinstance(outcome, dict)
            or set(outcome) != {"applied", "consumed_block", "consumed_block_hash"}
            or outcome["applied"] is not False
            or not _plain_nonnegative(outcome["consumed_block"])
            or not (
                receipt["block_number"]
                <= reveal["present_through_block"]
                < outcome["consumed_block"]
            )
        ):
            raise FailedWriteRecordRefused("stopped timelocked attempt is malformed")
        # The journaled commit, rebuilt for this writer's netuid, and its
        # signer identity must still be exactly what was signed.
        extrinsic_hash, _era_reference, _period = self._signed_intent(last)
        if _commit_reveal_document(intent) is None:
            raise FailedWriteRecordRefused(
                "stopped attempt carries no timelocked commit"
            )
        self._confirmation_contract(last)
        consumed_hash = _canonical_hash(
            outcome["consumed_block_hash"], label="consumed block"
        )
        last["status"] = STATUS_REVEAL_NOT_APPLIED_RECORDED
        record = {
            "status": STATUS_REVEAL_NOT_APPLIED_RECORDED,
            "attempt_id": last["attempt_id"],
            "extrinsic_hash": extrinsic_hash,
            "consumed_block": outcome["consumed_block"],
            "consumed_block_hash": consumed_hash,
        }
        return state, record

    @staticmethod
    def _history(label: str, read: Callable[..., Any], *args: Any, **kwargs: Any):
        """Run one node read the proof needs; a failed read proves nothing."""

        try:
            return read(*args, **kwargs)
        except Exception as exc:
            raise FailedWriteHistoryUnreadable(
                f"{label}: {type(exc).__name__}: {exc}"
            ) from exc

    def _history_block_hash(self, substrate: Any, block_number: int) -> str:
        raw = self._history(
            f"hash of block {block_number}",
            _uncached_block_hash,
            substrate,
            block_number,
        )
        if raw is None:
            raise FailedWriteHistoryUnreadable(
                f"node has no hash for block {block_number}"
            )
        return _canonical_hash(raw, label=f"block {block_number} hash")

    def _prove_finalized_failure(
        self,
        intent: Mapping[str, Any],
        *,
        extrinsic_hash: str,
        era_reference: int,
        period: int,
    ) -> dict[str, Any]:
        """Read the failed inclusion from finalized blocks, or refuse.

        Every node read goes through ``_history``: an RPC error, discarded
        state or a missing block proves nothing and is reported as unreadable
        history, not as a refusal. What the node does serve is checked. Every
        height is read uncached, as recovery reads it. The whole era must be
        finalized, so the scan covers every block the signature could ever
        land in. An extrinsic's position in its block's list is the
        ``extrinsic_idx`` of its events, as the pinned client pairs them
        (``sync_substrate.py:157, 201``), and the error is named from the
        runtime of that block.
        """

        substrate = self.subtensor.substrate
        if self._history_block_hash(substrate, 0) != FINNEY_GENESIS_HASH:
            raise FailedWriteRecordRefused(
                "the node's chain is not the pinned Finney genesis"
            )
        finalized_number, finalized_hash = self._history(
            "finalized head", finalized_head, self.subtensor
        )
        era_end = era_reference + period - 1
        if finalized_number < era_end:
            raise FailedWriteRecordRefused(
                f"mortal era {era_reference}-{era_end} is not finalized "
                f"(finalized head {finalized_number})"
            )
        matches: list[tuple[int, str, int]] = []
        for block_number in range(era_reference, era_reference + period):
            block_hash = self._history_block_hash(substrate, block_number)
            block = self._history(
                f"finalized block {block_number}",
                substrate.get_block,
                block_hash=block_hash,
            )
            if block is None:
                raise FailedWriteHistoryUnreadable(
                    f"node does not hold finalized block {block_number}"
                )
            extrinsics = block.get("extrinsics") if isinstance(block, Mapping) else None
            if not isinstance(extrinsics, (list, tuple)):
                raise FailedWriteRecordRefused(
                    f"finalized block {block_number} has no readable extrinsics"
                )
            for index, item in enumerate(extrinsics):
                # The pinned client decodes each extrinsic to an object that
                # carries its hash beside the decoded value.
                observed = getattr(item, "value", None)
                if not isinstance(observed, Mapping):
                    raise FailedWriteRecordRefused(
                        f"extrinsic {block_number}-{index} is not readable"
                    )
                raw_hash = getattr(item, "extrinsic_hash", None)
                if _canonical_hash(raw_hash, label="era extrinsic") != extrinsic_hash:
                    continue
                # The signer is bound twice. The journaled hash is blake2b-256 of
                # the whole signed extrinsic, address and signature included,
                # on both sides (scalecodec 0.5.0 GenericExtrinsic.extrinsic_hash,
                # ``types.c:65655-65656``; signed bytes built at
                # ``sync_substrate.py:2407-2436``). And the decoded call must
                # name the journaled hotkey as its address (``_exact_call``).
                if not self._exact_call(observed, intent):
                    raise FailedWriteRecordRefused(
                        "signed hash resolved to a different chain call"
                    )
                matches.append((block_number, block_hash, index))
        if not matches:
            raise FailedWriteRecordRefused(
                "signed hash is not in any finalized block of its era"
            )
        if len(matches) != 1:
            raise FailedWriteRecordRefused(
                "signed hash appears more than once in its finalized era"
            )
        block_number, block_hash, index = matches[0]
        events = self._history(
            f"events of finalized block {block_number}",
            substrate.get_events,
            block_hash=block_hash,
        )
        if not isinstance(events, (list, tuple)):
            raise FailedWriteRecordRefused(
                f"finalized block {block_number} has no readable events"
            )
        outcomes: list[tuple[bool, object]] = []
        # The pinned client returns the decoded records as plain mappings
        # (``sync_substrate.py:1563-1582``).
        for event_record in events:
            if not isinstance(event_record, Mapping):
                raise FailedWriteRecordRefused("an event record is not readable")
            if event_record.get("extrinsic_idx") != index:
                continue
            event = event_record.get("event")
            if not isinstance(event, Mapping):
                raise FailedWriteRecordRefused("an extrinsic event is not readable")
            # TransactionFeePaid is deliberately not used to bind the signer:
            # its ``who`` is the fee payer, and subtensor charges this call to
            # the signing hotkey's owning coldkey (subtensor ``main`` c004ceb
            # and ``mainnet`` d3f40e4: ``runtime/src/fee_filters.rs:18``,
            # ``runtime/src/transaction_payment_wrapper.rs`` validate at
            # ``:280-301`` on main, ``:264-287`` on mainnet;
            # ``pallet_transaction_payment`` ``lib.rs:951-954, 960-978`` at the
            # pinned polkadot-sdk ``cacb431``).
            kind = (event.get("module_id"), event.get("event_id"))
            if kind == ("System", "ExtrinsicSuccess"):
                outcomes.append((True, None))
            elif kind == ("System", "ExtrinsicFailed"):
                outcomes.append((False, event.get("attributes")))
        if any(succeeded for succeeded, _attributes in outcomes):
            raise FailedWriteRecordRefused(
                f"extrinsic {block_number}-{index} dispatch succeeded"
            )
        if len(outcomes) != 1:
            raise FailedWriteRecordRefused(
                f"extrinsic {block_number}-{index} has {len(outcomes)} "
                "ExtrinsicFailed events, not one"
            )
        runtime = self._history(
            f"runtime of finalized block {block_number}",
            substrate.init_runtime,
            block_hash=block_hash,
        )
        return {
            "block_number": block_number,
            "block_hash": block_hash,
            "extrinsic_index": index,
            "dispatch_error": _decoded_dispatch_error(
                outcomes[0][1], getattr(runtime, "metadata", None)
            ),
            "finalized_head": [finalized_number, finalized_hash],
        }

    def submit(
        self,
        plan: DirectWeightPlan,
        *,
        cycle_deadline_monotonic: float,
    ) -> DirectSubmissionReceipt:
        """Persist one signed intent, broadcast once, and prove stored finality.

        The pinned client returns from a finalization watch only when the node
        reports the extrinsic finalized; a write the node drops or refuses
        raises, and is journaled ambiguous for the next cycle's recovery. If a
        reported finalization is contradicted by finalized history, which
        proves the hash absent from its whole mortal era, the journal records
        the same terminal receipt recovery would and that
        ``EXPIRED_WITHOUT_INCLUSION`` receipt is returned: nothing was written
        and no pending intent remains.
        """

        presign_deadline = _presign_deadline(cycle_deadline_monotonic)
        _require_presign_time(presign_deadline, stage="writer entry")
        kwargs = self._validate_plan(plan)
        _require_presign_time(presign_deadline, stage="plan validation")
        with self._locked():
            _require_presign_time(presign_deadline, stage="writer lock acquisition")
            state = self._read_state()
            _require_presign_time(presign_deadline, stage="journal preflight")
            if self._pending(state) is not None:
                raise DirectSubmissionAmbiguous(
                    "a prior signed direct intent must be recovered first"
                )
            # Nothing is signed, commit or plain, over a REVEAL_NOT_APPLIED
            # stop the operator has not recorded.
            stop = _reveal_not_applied_stop(state)
            if stop is not None:
                raise stop
            last_attempt = state.get("last_attempt")
            if (
                isinstance(last_attempt, dict)
                and last_attempt.get("status") == STATUS_COMMITTED
            ):
                # A stored commit reveals on the chain's schedule whatever this
                # process does next. Nothing is signed, commit or plain, until
                # recovery proves what that reveal did.
                raise DirectValidatorError(
                    "the last timelocked commit is not proven revealed yet"
                )
            previous_anchor = self._last_anchor(state)
            if (
                previous_anchor is not None
                and plan.snapshot.block_number <= previous_anchor
            ):
                raise DirectValidatorError(
                    "direct validator already attempted this finalized anchor"
                )

            _require_presign_time(presign_deadline, stage="before genesis RPC")
            observed_genesis_hash(self.subtensor)
            _require_presign_time(presign_deadline, stage="genesis RPC")
            fresh = self.snapshot_reader(self.subtensor, self.keypair)
            _require_presign_time(presign_deadline, stage="fresh snapshot RPC")
            self._require_fresh_snapshot(plan, fresh, presign_deadline=presign_deadline)
            eligibility = self._require_finalized_eligibility(
                plan, fresh, presign_deadline=presign_deadline
            )
            _require_presign_time(presign_deadline, stage="eligibility preflight")
            commit_context = (
                None
                if self.commit_reveal is None
                else self._require_commit_reveal_context(
                    fresh, presign_deadline=presign_deadline
                )
            )
            commit_document: dict[str, Any] | None = None
            substrate = self.subtensor.substrate
            try:
                nonce = substrate.get_account_next_index(plan.snapshot.validator_hotkey)
                _require_presign_time(presign_deadline, stage="nonce RPC")
                if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
                    raise ValueError("account nonce is invalid")
                if commit_context is None:
                    call = self.call_builder(kwargs)
                else:
                    commit_document = self._timelocked_commit(
                        kwargs, commit_context, presign_deadline=presign_deadline
                    )
                    call = self.commit_call_builder(
                        {
                            "netuid": kwargs["netuid"],
                            "mecid": kwargs["mecid"],
                            "commit": commit_document["commit"],
                            "reveal_round": commit_document["reveal_round"],
                            "commit_reveal_version": commit_document[
                                "commit_reveal_version"
                            ],
                        }
                    )
                _require_presign_time(
                    presign_deadline, stage="immediately before signing"
                )
                signed = substrate.create_signed_extrinsic(
                    call=call,
                    keypair=self.keypair,
                    nonce=nonce,
                    era={
                        "period": MORTAL_PERIOD_BLOCKS,
                        "current": fresh.block_number,
                    },
                )
                extrinsic_hash = _canonical_hash(
                    getattr(signed, "extrinsic_hash", None),
                    label="signed extrinsic",
                )
            except DirectSubmissionAmbiguous:
                raise
            except DirectValidatorError:
                raise
            except Exception as exc:
                raise DirectValidatorError(
                    "direct extrinsic could not be signed"
                ) from exc
            self._require_broadcast_window(
                substrate,
                era_reference=fresh.block_number,
                presign_deadline=presign_deadline,
            )

            identity = plan.identity()
            intent = {
                "extrinsic_hash": extrinsic_hash,
                "validator_hotkey": plan.snapshot.validator_hotkey,
                "nonce": nonce,
                "era_reference_block": fresh.block_number,
                "mortal_period_blocks": MORTAL_PERIOD_BLOCKS,
                "kwargs": kwargs,
                "eligibility": eligibility,
            }
            if commit_document is not None:
                # The plaintext vector stays in kwargs; this is what the
                # signed call carries instead of it, and what recovery and the
                # reveal proof check against.
                intent["commit_reveal"] = commit_document
            attempt_id = _attempt_id(identity, intent)
            pending: dict[str, Any] = {
                "attempt_id": attempt_id,
                "phase": "signed_intent",
                "identity": identity,
                "intent": intent,
                "receipt": None,
                "error": None,
            }
            state["pending"] = pending
            self._write_state(state)

            try:
                with _broadcast_watch_waits(substrate):
                    response = substrate.submit_extrinsic(
                        signed,
                        wait_for_inclusion=True,
                        wait_for_finalization=True,
                    )
                response_hash = getattr(response, "extrinsic_hash", None)
                if (
                    response_hash is not None
                    and _canonical_hash(response_hash, label="submission response")
                    != extrinsic_hash
                ):
                    raise DirectSubmissionContradiction(
                        "submission response names another extrinsic"
                    )
            except Exception as exc:
                pending["phase"] = "ambiguous"
                pending["error"] = type(exc).__name__
                state["pending"] = pending
                self._write_state(state)
                if isinstance(exc, DirectSubmissionContradiction):
                    raise
                raise DirectSubmissionAmbiguous(
                    "direct submission result is ambiguous; recover, never retry"
                ) from exc

            try:
                status, located = self._await_finalized_history(pending)
            except DirectValidatorError as exc:
                # The extrinsic was broadcast, so never leave the journal
                # reading like a signed intent that never reached the chain.
                pending["phase"] = (
                    "confirmation_contradiction"
                    if isinstance(exc, DirectSubmissionContradiction)
                    else "ambiguous"
                )
                pending["error"] = type(exc).__name__
                state["pending"] = pending
                self._write_state(state)
                raise
            if status == "finalized" and located is not None:
                try:
                    confirmed, reveal = self._confirm_effect(
                        pending, located, recovered=False
                    )
                except DirectSubmissionContradiction as exc:
                    pending["phase"] = "confirmation_contradiction"
                    pending["receipt"] = located.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                except DirectSubmissionAmbiguous as exc:
                    pending["phase"] = "included_awaiting_confirmation"
                    pending["receipt"] = located.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                return self._finish(state, pending, confirmed, reveal=reveal)
            if status == "expired" and located is not None:
                # The watch returned, so the node reported these bytes
                # finalized, yet _locate read every block of the era from the
                # node, uncached, without this hash and saw the finalized head
                # reach the era's last block: the same proof recover() acts
                # on. The chain, not the report, is authoritative, and no node
                # can include the bytes any more, so record the terminal
                # receipt now rather than an ambiguity for the next cycle. The
                # reported block is logged because a node that reports
                # finality for a block the chain does not hold needs a look.
                try:
                    reported = _canonical_hash(
                        getattr(response, "block_hash", None),
                        label="reported finalization block",
                    )
                except DirectSubmissionAmbiguous:
                    reported = "an unusable block hash"
                _LOG.warning(
                    "node reported extrinsic %s finalized in %s, but finalized "
                    "history holds no such inclusion in its mortal era; "
                    "recording %s",
                    extrinsic_hash,
                    reported,
                    STATUS_EXPIRED,
                )
                return self._finish(state, pending, located)
            if status == "failed":
                pending["phase"] = PHASE_FINALIZED_FAILED
                state["pending"] = pending
                self._write_state(state)
                raise DirectSubmissionFinalizedFailure(
                    "direct extrinsic finalized with failure"
                )
            pending["phase"] = "ambiguous"
            state["pending"] = pending
            self._write_state(state)
            raise DirectSubmissionAmbiguous(
                "submission returned without exact finalized history; recover"
            )


__all__ = [
    "DirectCommitNotRevealed",
    "DirectSubmissionAmbiguous",
    "DirectSubmissionContradiction",
    "DirectSubmissionFinalizedFailure",
    "DirectSubmissionReceipt",
    "DirectWeightWriter",
    "FailedWriteHistoryUnreadable",
    "FailedWriteRecordRefused",
    "BROADCAST_ERA_MARGIN_BLOCKS",
    "BROADCAST_WATCH_MAX_RETRIES",
    "BROADCAST_WATCH_RETRY_TIMEOUT_SECONDS",
    "CONFIRMATION_WAIT_SECONDS",
    "DIRECT_RPC_MAX_RETRIES",
    "DIRECT_RPC_RETRY_TIMEOUT_SECONDS",
    "FINALIZED_HISTORY_WAIT_SECONDS",
    "DIRECT_STATE_ROOT",
    "STATE_SCHEMA",
    "STATUS_AWAITING_REVEAL",
    "STATUS_COMMITTED",
    "STATUS_CONFIRMED",
    "PHASE_FINALIZED_FAILED",
    "STATUS_EXPIRED",
    "STATUS_FINALIZED_FAILED",
    "STATUS_RECOVERED",
    "STATUS_REVEALED",
    "STATUS_REVEAL_NOT_APPLIED",
    "STATUS_REVEAL_NOT_APPLIED_RECORDED",
    "STATUS_REVEAL_UNPROVEN",
    "bound_rpc_waits",
    "canonical_state_path",
    "cycle_lock_path_for_state",
    "direct_state_scope",
]
