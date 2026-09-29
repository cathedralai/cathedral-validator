"""Timelocked commit-reveal support for the direct writer, off unless opted in.

On a subnet with commit-reveal enabled the chain refuses a plain
``set_mechanism_weights`` (``CommitRevealEnabled``). A validator instead
submits ``commit_timelocked_mechanism_weights`` carrying its weight vector
encrypted to a future drand round, and the chain itself decrypts and applies
it; there is no reveal extrinsic. Everything here is pinned to sources read at
the runtime Finney runs (spec 470, subtensor tag ``v470`` = 923fd1fa):

* The commit call and its checks: ``pallets/subtensor/src/macros/
  dispatches.rs:2024-2042`` and ``subnets/weights.rs:321-420``. The call needs
  commit-reveal enabled, ``commit_reveal_version`` equal to the stored
  ``CommitRevealWeightsVersion`` (4), a registered hotkey and the ordinary
  weight rate limit, then appends ``(hotkey, commit_block, ciphertext,
  reveal_round)`` under the epoch it lands in and sets ``LastUpdate``.
* The automatic reveal: ``coinbase/block_step.rs:15-17, 88-106`` and
  ``coinbase/reveal_commits.rs:39-211``. Every block, before the epoch runs,
  commits keyed ``current_epoch - reveal_period`` are taken; one whose drand
  pulse is on chain is decrypted, its ``WeightsTlockPayload`` decoded, its
  ``hotkey`` checked against the committer, and ``do_set_mechanism_weights``
  applied. Success emits ``TimelockedWeightsRevealed(netuid_index, who)``.
  Any failure is only logged and the commit is dropped; a commit whose pulse
  is missing is kept and retried every block of its reveal epoch, then
  removed.
* The payload and encryption: bittensor-drand 2.0.0 (the version the release
  lock pins, tag ``v2.0.0``), ``src/drand.rs:21-27, 55-110, 160-204``, which
  is byte-for-byte the struct the chain decodes (``reveal_commits.rs:19-26``).
  The pinned SDK builds commits the same way
  (bittensor 10.5.0 ``core/extrinsics/weights.py:81-109``).

This module holds only pure, independently tested helpers. The writer owns
every chain read, the journal, signing and recovery.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Callable

from .direct_contract import DirectValidatorError

# Operator opt-in. Absent or empty keeps the writer exactly as before.
COMMIT_REVEAL_OPT_IN_ENV = "CATHEDRAL_VALIDATOR_COMMIT_REVEAL"
_OPT_IN = re.compile(r"timelocked-v4-reveal-period-([1-9][0-9]{0,2})")
# The chain's bounds on RevealPeriodEpochs (pallets/subtensor/src/lib.rs:281-283).
MIN_REVEAL_PERIOD_EPOCHS = 1
MAX_REVEAL_PERIOD_EPOCHS = 100

COMMIT_REVEAL_CALL_FUNCTION = "commit_timelocked_mechanism_weights"
COMMIT_REVEAL_CALL = f"SubtensorModule.{COMMIT_REVEAL_CALL_FUNCTION}"
# Must equal the stored CommitRevealWeightsVersion (default 4, lib.rs:1284-1286;
# 4 on Finney when this was written). It names the bittensor-drand payload
# format, so it is pinned with the library, never configured.
COMMIT_REVEAL_VERSION = 4
# BoundedVec bound on the ciphertext (pallets/subtensor/src/lib.rs:62).
MAX_COMMIT_BYTES = 5000
# Finney's Aura slot is 12000 ms. bittensor-drand turns blocks into seconds
# with this value when it picks the reveal round.
BLOCK_TIME_SECONDS = 12
# drand quicknet (bittensor-drand src/constants.rs:16-20).
DRAND_GENESIS_SECONDS = 1_692_803_367
DRAND_PERIOD_SECONDS = 3
DRAND_ROUNDS_PER_BLOCK = BLOCK_TIME_SECONDS // DRAND_PERIOD_SECONDS
# bittensor-drand targets the pulse this many blocks after the predicted
# first reveal block (src/constants.rs:39).
DRAND_SECURITY_BLOCK_OFFSET = 3
# How far, in drand rounds, the library's reveal round and the local clock may
# stray from the values derived from the chain's own ingested drand head. One
# round is three seconds, so this is five minutes: far above the normal
# finality and ingestion lag (about 10 to 20 rounds), and far below the length
# of a reveal epoch, so a commit that passes still reveals inside its epoch.
DRAND_ROUND_TOLERANCE = 100
# bittensor-drand's tempo bound (src/constants.rs:6).
_DRAND_MAX_TEMPO = 50_400


@dataclass(frozen=True)
class CommitRevealOptIn:
    """The chain policy an operator expects: timelocked v4 with this period."""

    reveal_period_epochs: int

    def __post_init__(self) -> None:
        value = self.reveal_period_epochs
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not MIN_REVEAL_PERIOD_EPOCHS <= value <= MAX_REVEAL_PERIOD_EPOCHS
        ):
            raise DirectValidatorError("commit-reveal opt-in reveal period is invalid")

    @property
    def version(self) -> int:
        return COMMIT_REVEAL_VERSION


def parse_commit_reveal_opt_in(value: object) -> CommitRevealOptIn | None:
    """Read the operator's opt-in, or refuse anything but the one grammar.

    ``None`` or an empty value is no opt-in. The only accepted value is
    ``timelocked-v4-reveal-period-<N>``: it names the payload version and the
    reveal period the operator expects the chain to run, and the writer
    refuses to sign unless the chain matches both.
    """

    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.isascii():
        raise DirectValidatorError(
            f"{COMMIT_REVEAL_OPT_IN_ENV} must be timelocked-v4-reveal-period-<N>"
        )
    match = _OPT_IN.fullmatch(value)
    if match is None:
        raise DirectValidatorError(
            f"{COMMIT_REVEAL_OPT_IN_ENV} must be timelocked-v4-reveal-period-<N>"
        )
    return CommitRevealOptIn(reveal_period_epochs=int(match.group(1)))


@dataclass(frozen=True)
class EpochSchedule:
    """The chain storage bittensor-drand v2 reads, all at one finalized block.

    Field for field the library's ``EpochScheduleState``
    (``src/epoch_schedule.rs:15-22``); ``current_block`` is the block read.
    """

    last_epoch_block: int
    pending_epoch_at: int
    subnet_epoch_index: int
    tempo: int
    blocks_since_last_step: int
    current_block: int

    def document(self) -> dict[str, int]:
        return {
            "block": self.current_block,
            "tempo": self.tempo,
            "last_epoch_block": self.last_epoch_block,
            "pending_epoch_at": self.pending_epoch_at,
            "subnet_epoch_index": self.subnet_epoch_index,
            "blocks_since_last_step": self.blocks_since_last_step,
        }


def _should_run_epoch(state: EpochSchedule, block: int) -> bool:
    # bittensor-drand src/epoch_schedule.rs:43-57.
    if state.tempo == 0:
        return False
    if state.pending_epoch_at > 0 and block >= state.pending_epoch_at:
        return True
    if state.blocks_since_last_step > _DRAND_MAX_TEMPO:
        return True
    return max(0, block - state.last_epoch_block) >= state.tempo


def _epoch_before_coinbase(state: EpochSchedule, block: int) -> int:
    # bittensor-drand src/epoch_schedule.rs:61-68.
    base = state.subnet_epoch_index
    return base + 1 if _should_run_epoch(state, block) else base


def _run_coinbase(state: EpochSchedule, block: int) -> EpochSchedule:
    # bittensor-drand src/epoch_schedule.rs:74-86.
    advanced = EpochSchedule(
        last_epoch_block=state.last_epoch_block,
        pending_epoch_at=state.pending_epoch_at,
        subnet_epoch_index=state.subnet_epoch_index,
        tempo=state.tempo,
        blocks_since_last_step=state.blocks_since_last_step + 1,
        current_block=block,
    )
    if _should_run_epoch(advanced, block):
        return EpochSchedule(
            last_epoch_block=block,
            pending_epoch_at=0,
            subnet_epoch_index=advanced.subnet_epoch_index + 1,
            tempo=advanced.tempo,
            blocks_since_last_step=0,
            current_block=block,
        )
    return advanced


def predict_first_reveal_block(state: EpochSchedule, reveal_period_epochs: int) -> int:
    """Port of bittensor-drand ``predict_first_reveal_block``.

    ``src/epoch_schedule.rs:106-141``: the commit lands in the block after the
    head, belongs to that block's look-ahead epoch, and first reveals in the
    block whose look-ahead epoch is ``reveal_period`` epochs later. Like the
    library it does not model ``MaxEpochsPerBlock`` deferral, which only ever
    makes the real reveal later.
    """

    if state.tempo == 0:
        raise DirectValidatorError("subnet tempo is zero; commits never reveal")
    extrinsic_block = state.current_block + 1
    target = _epoch_before_coinbase(state, extrinsic_block) + reveal_period_epochs
    bound = extrinsic_block + reveal_period_epochs * _DRAND_MAX_TEMPO + _DRAND_MAX_TEMPO
    previous = state
    for block in range(extrinsic_block, bound + 1):
        if _epoch_before_coinbase(previous, block) == target:
            return block
        previous = _run_coinbase(previous, block)
    raise DirectValidatorError("reveal block prediction exceeded its bound")


def next_epoch_fire_block(state: EpochSchedule) -> int:
    """First block after the head at which the subnet's next epoch fires.

    A commit included at or after this block is keyed to the next epoch, so
    it reveals one epoch later than the round it was encrypted to.
    """

    if state.tempo == 0:
        raise DirectValidatorError("subnet tempo is zero; commits never reveal")
    previous = state
    start = state.current_block + 1
    for block in range(start, start + _DRAND_MAX_TEMPO + 2):
        if _should_run_epoch(previous, block):
            return block
        previous = _run_coinbase(previous, block)
    raise DirectValidatorError("next epoch block exceeded its bound")


def drand_round_at(unix_seconds: float) -> int:
    """The drand round bittensor-drand assigns to a moment.

    ``src/drand.rs:189-193``: ``floor((t - genesis) / period)``, at least 1.
    """

    if not math.isfinite(unix_seconds):
        raise DirectValidatorError("wall clock is not a finite time")
    return max(
        1, math.floor((unix_seconds - DRAND_GENESIS_SECONDS) / DRAND_PERIOD_SECONDS)
    )


def chain_expected_reveal_round(
    *, drand_last_stored_round: int, sign_block: int, first_reveal_block: int
) -> int:
    """The reveal round bittensor-drand would pick, from chain facts only.

    The library adds ``(first_reveal + 3 - head) * block_time`` seconds to the
    wall clock. The chain's own drand head at the sign block stands in for the
    wall clock here, at four rounds per twelve-second block, so a commit whose
    round disagrees by more than the tolerance was built on a wrong clock.
    """

    blocks = first_reveal_block + DRAND_SECURITY_BLOCK_OFFSET - sign_block
    if blocks <= 0:
        raise DirectValidatorError("predicted reveal is not after the sign head")
    return drand_last_stored_round + DRAND_ROUNDS_PER_BLOCK * blocks


def canonical_bytes_hex(value: object) -> str | None:
    """Lower-case ``0x`` hex of chain bytes, or ``None`` if not bytes-like."""

    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, str):
        text = value.lower()
        if not text.startswith("0x"):
            return None
        body = text[2:]
        if len(body) % 2 or any(c not in "0123456789abcdef" for c in body):
            return None
        return text
    if isinstance(value, (list, tuple)) and all(
        not isinstance(item, bool) and isinstance(item, int) and 0 <= item <= 255
        for item in value
    ):
        return "0x" + bytes(value).hex()
    return None


def decoded_commit_rows(value: Any) -> list[tuple[str, int, str, int]] | None:
    """Decode one ``TimelockedWeightCommits`` value, or ``None`` if unusable.

    The pinned client returns each entry as ``[who, commit_block,
    "0x..ciphertext", reveal_round]`` (observed on Finney SN94).
    """

    raw = getattr(value, "value", value)
    if not isinstance(raw, (list, tuple)):
        return None
    rows: list[tuple[str, int, str, int]] = []
    for item in raw:
        item = getattr(item, "value", item)
        if not isinstance(item, (list, tuple)) or len(item) != 4:
            return None
        who, block, commit, round_number = item
        commit_hex = canonical_bytes_hex(commit)
        if (
            not isinstance(who, str)
            or not who
            or isinstance(block, bool)
            or not isinstance(block, int)
            or block < 0
            or commit_hex is None
            or isinstance(round_number, bool)
            or not isinstance(round_number, int)
            or round_number < 0
        ):
            return None
        rows.append((who, block, commit_hex, round_number))
    return rows


def default_commit_encryptor() -> Callable[..., tuple[bytes, int]]:
    """The pinned library function the SDK itself uses to build commits."""

    from bittensor_drand import get_encrypted_commit_v2

    return get_encrypted_commit_v2


__all__ = [
    "BLOCK_TIME_SECONDS",
    "COMMIT_REVEAL_CALL",
    "COMMIT_REVEAL_CALL_FUNCTION",
    "COMMIT_REVEAL_OPT_IN_ENV",
    "COMMIT_REVEAL_VERSION",
    "CommitRevealOptIn",
    "DRAND_ROUND_TOLERANCE",
    "DRAND_ROUNDS_PER_BLOCK",
    "EpochSchedule",
    "MAX_COMMIT_BYTES",
    "canonical_bytes_hex",
    "chain_expected_reveal_round",
    "decoded_commit_rows",
    "default_commit_encryptor",
    "drand_round_at",
    "next_epoch_fire_block",
    "parse_commit_reveal_opt_in",
    "predict_first_reveal_block",
]
