"""The validator's round loop: benchmark, report, then compose the chain weights.

Ties the v2 pieces together (jared, 2026-09-04). Per block, `step` asks the schedule what to do:

* **during the evaluation round** — `benchmark_and_report`: pull the closed submission round's
  PoCs + proofs, rebuild each corpus from its proof and benchmark it, then POST the per-miner
  results back to the server. Every validator does this independently.
* **at the compose block (offset 6600)** — `compose_and_set`: fetch the server's AVERAGED
  per-miner scores (averaged across the validators that reported), compose the per-round KING
  board from them, and set the resulting weights on chain.
* **otherwise** — re-assert the same weights on the 300-block keep-alive so the chain does not
  zero this validator.

The weights come from the SERVER'S AVERAGE, not from this validator's own benchmark alone: that
is what makes every validator converge on one number instead of each setting its own, while the
benchmark each performs independently is what keeps the average honest.

Every boundary is injected — the HTTP client, the differential/corpus-rebuild, the weight setter,
and the nonce source — so the whole loop is testable with fakes and contains no I/O of its own.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Any, Callable, Protocol

from cathedral_thin.cybergym_round_eval import (
    BenchmarkFn,
    MinerRoundResult,
    Submission,
    evaluate_round,
)
from cathedral_thin.cybergym_round_schedule import (
    Action,
    ScheduleState,
    next_action,
    record_action,
    submission_round_being_scored,
)
from cathedral_thin.cybergym_round_scoring import RoundBoard, compose_round_board


class RoundRuntimeError(RuntimeError):
    """The round loop could not complete a step. Fails closed — never sets guessed weights."""


class RoundClient(Protocol):
    """The backend API the validator talks to (injected; production wraps HTTP)."""

    def fetch_submissions(self, round_id: int) -> Sequence[Submission]:
        """The closed round's submissions: each miner's PoCs + per-task rebuild proofs."""

    def post_results(self, round_id: int, results: Mapping[str, MinerRoundResult]) -> None:
        """Report this validator's benchmark verdicts; the server averages across validators."""

    def fetch_average_scores(self, round_id: int) -> Mapping[str, Decimal | int | str]:
        """The server's averaged per-miner round scores — the input the weights are composed from."""


#: (weights_by_hotkey) -> None. Production wraps the substrate set_weights extrinsic.
SetWeightsFn = Callable[[Mapping[str, Decimal]], None]
#: (round_id) -> the chain-anchored nonce that keys the payout-decisive tie-break.
NonceFn = Callable[[int], bytes]


@dataclass(frozen=True)
class RuntimeState:
    """What the loop carries between blocks."""

    schedule: ScheduleState = ScheduleState()
    last_weights: tuple[tuple[str, str], ...] = ()   # hotkey -> share (str), for re-assertion
    reported_round: int | None = None                 # last submission round we benchmarked+posted

    def weights(self) -> dict[str, Decimal]:
        return {hk: Decimal(v) for hk, v in self.last_weights}


def benchmark_and_report(
    round_id: int, *, client: RoundClient, benchmark: BenchmarkFn,
    task_weights: Mapping[str, Decimal] | None = None,
    deadline: Callable[[], bool] | None = None,
) -> dict[str, MinerRoundResult]:
    """Benchmark every submission of a closed round and report the verdicts to the server.

    ``deadline`` (usually "am I past the compose block?") lets the run stop cleanly: miners not
    reached are reported UNEVALUATED, which the server excludes from the average. Abstaining is
    the honest signal — scoring them 0 would drag them down for this validator's slowness.
    """
    if round_id < 0:
        raise RoundRuntimeError("no submission round to benchmark yet")
    submissions = list(client.fetch_submissions(round_id))
    results = evaluate_round(submissions, benchmark, task_weights=task_weights, deadline=deadline)
    client.post_results(round_id, results)
    return results


def compose_and_set(
    round_id: int, *, client: RoundClient, set_weights: SetWeightsFn, nonce: bytes,
) -> RoundBoard:
    """Fetch the server's averaged scores, compose the KING board, and set the weights on chain.

    An empty field composes an all-burn board and still sets weights (the CyberGym lane forfeits
    its allocation, which is the "no miner -> sandbox lane" rule); it never skips the set, because
    skipping would let the chain zero this validator.
    """
    scores = dict(client.fetch_average_scores(round_id)) if round_id >= 0 else {}
    board = compose_round_board(round_id, scores, nonce=nonce)
    set_weights({s.miner_hotkey: s.lane_share for s in board.standings if s.lane_share > 0})
    return board


def step(
    block: int,
    state: RuntimeState,
    *,
    client: RoundClient,
    benchmark: BenchmarkFn,
    set_weights: SetWeightsFn,
    nonce_for: NonceFn,
    task_weights: Mapping[str, Decimal] | None = None,
    deadline: Callable[[], bool] | None = None,
) -> tuple[RuntimeState, Action]:
    """Advance the loop one block. Returns the new state and the action actually taken.

    Benchmarking happens once per evaluation round, the first time we see a block in it and before
    the compose — so the server has this validator's verdicts to average by the time weights are
    composed. It is deliberately separate from the schedule's weight action: benchmarking is work,
    setting weights is the chain obligation, and a slow benchmark must never delay the keep-alive.
    """
    scored_round = submission_round_being_scored(block)
    # 1. Benchmark + report once per evaluation round (idempotent via reported_round).
    if scored_round >= 0 and state.reported_round != scored_round:
        try:
            benchmark_and_report(scored_round, client=client, benchmark=benchmark,
                                 task_weights=task_weights, deadline=deadline)
            state = replace(state, reported_round=scored_round)
        except Exception as exc:  # a failed report must not stop the weight obligation
            raise RoundRuntimeError(f"benchmark/report failed for round {scored_round}: {exc}") from exc

    # 2. Weight obligation, per the schedule.
    action = next_action(block, state.schedule)
    if action is Action.COMPOSE_AND_SET:
        board = compose_and_set(scored_round, client=client, set_weights=set_weights,
                                nonce=nonce_for(max(scored_round, 0)))
        weights = tuple((s.miner_hotkey, str(s.lane_share))
                        for s in board.standings if s.lane_share > 0)
        state = replace(state, last_weights=weights,
                        schedule=record_action(block, action, state.schedule))
    elif action is Action.REASSERT:
        set_weights(state.weights())
        state = replace(state, schedule=record_action(block, action, state.schedule))
    return state, action


__all__ = [
    "RoundRuntimeError", "RoundClient", "SetWeightsFn", "NonceFn", "RuntimeState",
    "benchmark_and_report", "compose_and_set", "step",
]
