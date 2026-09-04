"""The v2 CyberGym round schedule: a 24h submit → evaluate → emit pipeline on chain blocks.

The mechanism runs in fixed rounds of ``ROUND_BLOCKS`` (24h ≈ 7200 blocks at 12s). Three rounds
are in flight at once, offset by one each (jared's spec, 2026-09-04):

    round R      SUBMIT+RUN  miners submit their agent; the backend screens it (round-1
                            similarity) and RUNS it in the sandbox under the run limits,
                            generating PoCs + trajectory. Submissions
                            CLOSE at ``SUBMISSION_CLOSE_OFFSET`` (block 6000 ~ 20h); the run
                            queue may spill past the round end into R+1 while validators are
                            already evaluating what finished.
    round R+1    EVALUATE   validators rebuild each corpus ONCE and benchmark every miner's PoC
                            against it (crash on vulnerable, clean on fixed); results are posted
                            and the backend averages the per-miner scores over the validators
                            that actually evaluated. At ``WEIGHT_SET_OFFSET`` the validator
                            composes round R's weights and sets them on chain.
    round R+2    EMIT       those weights are live, so round R's miners earn emission.

So a miner who submits in round R is paid in round R+2 — two rounds later.

**Weight cadence.** Bittensor zeros a validator's weights if it does not set them within the
subnet's window, so the validator must re-assert even when nothing changed. Between the once-a-
round authoritative compose at ``WEIGHT_SET_OFFSET``, the validator re-sets the SAME weights
every ``REASSERT_BLOCKS`` (300) to stay live. ``next_action`` folds both into one decision:
compose-and-set at the round boundary point, else re-assert if the keep-alive interval elapsed.

Everything here is a pure function of the block height and a couple of remembered block numbers,
so the runtime loop stays trivial and testable and two validators agree on when to act.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

#: 24h at ~12s/block. The one knob; the offsets below are within a single round.
ROUND_BLOCKS = 7200

#: Block offset WITHIN the evaluation round at which the validator composes and sets the
#: authoritative weights for the submission round that just closed. 6600 leaves ~600 blocks
#: (~2h) of margin before the round ends for the compose + on-chain set to land.
WEIGHT_SET_OFFSET = 6600

#: Keep-alive: re-assert the current weights at least this often so the chain does not zero
#: them between authoritative composes. Bittensor requirement, not a mechanism choice.
REASSERT_BLOCKS = 300

#: Submissions CLOSE at this offset in the submit round (block 6000 ~ 20h), leaving ~4h before the
#: round ends. The agent RUNS in the submit round, so closing early gives the sandbox queue time
#: to drain; anything still queued spills into the next round and is evaluated late or not at all
#: (an unevaluated miner is simply not averaged — see the eval side).
SUBMISSION_CLOSE_OFFSET = 6000

if not (0 < SUBMISSION_CLOSE_OFFSET <= WEIGHT_SET_OFFSET):  # pragma: no cover - config guard
    raise ValueError("submissions must close at or before the weight-set offset")

if not (0 <= WEIGHT_SET_OFFSET < ROUND_BLOCKS):  # pragma: no cover - config guard
    raise ValueError("WEIGHT_SET_OFFSET must fall inside a round")


class Phase(str, Enum):
    SUBMIT = "submit"        # accepting submissions AND running agents (before the close offset)
    DRAIN = "drain"          # submissions closed; the sandbox queue finishes running
    EVALUATE = "evaluate"    # (of the PREVIOUS round's submissions) benchmarking + weight compose


def phase(block: int) -> Phase:
    """The submit-side phase of the block's own round.

    Every round is simultaneously the SUBMIT round for its own miners and the EVALUATE round for
    the previous one — the pipeline is continuous, not a loop, so both are always true. This
    reports the submit-side state: accepting (before the close) or draining the run queue after.
    """
    return Phase.SUBMIT if block_offset(block) < SUBMISSION_CLOSE_OFFSET else Phase.DRAIN


def accepting_submissions(block: int) -> bool:
    """True while this round still accepts submissions (before the close offset)."""
    return block_offset(block) < SUBMISSION_CLOSE_OFFSET


class Action(str, Enum):
    COMPOSE_AND_SET = "compose_and_set"  # authoritative weight compose for the closed round
    REASSERT = "reassert"                # re-set the SAME weights to stay live
    WAIT = "wait"                        # nothing to do this block


def round_index(block: int) -> int:
    """The 0-based round a block falls in."""
    if not isinstance(block, int) or block < 0:
        raise ValueError("block must be a non-negative integer")
    return block // ROUND_BLOCKS


def round_bounds(round_idx: int) -> tuple[int, int]:
    """``(start_block, end_block_exclusive)`` for a round."""
    if round_idx < 0:
        raise ValueError("round_idx must be non-negative")
    start = round_idx * ROUND_BLOCKS
    return start, start + ROUND_BLOCKS


def block_offset(block: int) -> int:
    """How far into its round a block is (0 .. ROUND_BLOCKS-1)."""
    return block % ROUND_BLOCKS


def submission_round_being_scored(block: int) -> int:
    """The submission round whose results are composed during the block's (evaluation) round.

    A block in round R evaluates the submissions from round R-1. Round 0 has nothing before it,
    so it returns -1 (no round to score yet) — the caller composes an empty board (all burn).
    """
    return round_index(block) - 1


def is_weight_set_block(block: int) -> bool:
    """True at the single authoritative-compose point of the round (the ``WEIGHT_SET_OFFSET``)."""
    return block_offset(block) == WEIGHT_SET_OFFSET


@dataclass(frozen=True)
class ScheduleState:
    """What the validator remembers between blocks."""

    last_set_block: int | None = None          # last block it set weights at (any kind)
    last_composed_round: int | None = None      # last submission round it authoritatively composed


def next_action(block: int, state: ScheduleState) -> Action:
    """Decide what the validator should do at ``block``.

    COMPOSE_AND_SET once per round at ``WEIGHT_SET_OFFSET`` — but only if this round's
    authoritative compose has not already happened (idempotent across the many blocks the loop
    sees, and across a restart that reloads ``last_composed_round``). Otherwise REASSERT when
    ``REASSERT_BLOCKS`` have elapsed since the last set, else WAIT. The compose takes precedence,
    so the once-a-round weight update is never skipped in favour of a keep-alive.
    """
    if not isinstance(block, int) or block < 0:
        raise ValueError("block must be a non-negative integer")
    this_round = round_index(block)
    if is_weight_set_block(block) and state.last_composed_round != this_round:
        return Action.COMPOSE_AND_SET
    if state.last_set_block is None:
        # Never set weights yet: assert immediately so the validator does not sit dark waiting
        # for the first offset (which could be ~a whole round away after a fresh start).
        return Action.REASSERT
    if block - state.last_set_block >= REASSERT_BLOCKS:
        return Action.REASSERT
    return Action.WAIT


def record_action(block: int, action: Action, state: ScheduleState) -> ScheduleState:
    """The state after taking ``action`` at ``block`` — feed it back next block."""
    if action is Action.WAIT:
        return state
    composed = state.last_composed_round
    if action is Action.COMPOSE_AND_SET:
        composed = round_index(block)
    return ScheduleState(last_set_block=block, last_composed_round=composed)


__all__ = [
    "ROUND_BLOCKS", "WEIGHT_SET_OFFSET", "REASSERT_BLOCKS", "SUBMISSION_CLOSE_OFFSET",
    "phase", "accepting_submissions",
    "Phase", "Action", "ScheduleState",
    "round_index", "round_bounds", "block_offset",
    "submission_round_being_scored", "is_weight_set_block",
    "next_action", "record_action",
]
