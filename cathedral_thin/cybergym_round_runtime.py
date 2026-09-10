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
from typing import Callable, Protocol

from cathedral_thin.cybergym_round_eval import (
    BenchmarkFn,
    MinerRoundResult,
    Submission,
    evaluate_round,
)
from cathedral_thin.cybergym_round_schedule import (
    PRODUCTION,
    Action,
    RoundConfig,
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

    def fetch_round_tasks(self, round_id: int) -> Sequence[str]:
        """The round's authoritative task set — what every miner is scored OUT OF.

        Server-published and identical for everyone. Without it the denominator would be whatever
        each miner chose to submit, and withholding your failures would score 100.
        """

    def fetch_submissions(self, round_id: int) -> Sequence[Submission]:
        """The closed round's submissions: each miner's PoCs + per-task rebuild proofs."""

    def fetch_solver(self) -> Mapping[str, Any]:
        """What the backend says it enforces about the enclave that ran the agents."""

    def post_results(
        self, round_id: int, results: Mapping[str, MinerRoundResult]
    ) -> None:
        """Report this validator's benchmark verdicts; the server averages across validators."""

    def fetch_average_scores(self, round_id: int) -> Mapping[str, Decimal | int | str]:
        """The server's averaged per-miner round scores — the input the weights are composed from."""


@dataclass(frozen=True)
class LaneWeights:
    """One round's outcome for the CyberGym lane: the miner shares AND the forfeited share.

    The burn travels WITH the miner weights, in one object, because it was silently dropped when
    it did not. `compose_and_set` filtered the board's standings and handed those to the setter,
    so a round with no qualifying miner composed "forfeit the whole lane" and then set an EMPTY
    vector — which is not a forfeit, it is a malformed set. The lane's allocation went nowhere
    instead of to the sandbox lane, which is exactly the rule it was supposed to honour ("no
    miner -> all weight to the sandbox lane").

    `miners` are within-lane shares. `burn` is what no miner earned; the caller that merges the
    two lanes redirects it to the sandbox lane. Together they sum to 1.
    """

    miners: Mapping[str, Decimal]
    burn: Decimal = Decimal(0)

    def total(self) -> Decimal:
        return sum(self.miners.values(), Decimal(0)) + self.burn


#: (LaneWeights) -> None. Production wraps the substrate set_weights extrinsic, redirecting
#: `burn` to the sandbox lane. Taking the whole object is what stops the burn being dropped.
SetWeightsFn = Callable[[LaneWeights], None]
#: (round_id) -> the chain-anchored nonce that keys the payout-decisive tie-break.
NonceFn = Callable[[int], bytes]


@dataclass(frozen=True)
class RuntimeState:
    """What the loop carries between blocks."""

    schedule: ScheduleState = ScheduleState()
    last_weights: tuple[
        tuple[str, str], ...
    ] = ()  # hotkey -> share (str), for re-assertion
    #: The forfeited share to re-assert. Starts at 1: before this validator has composed anything
    #: it has no opinion about any miner, and the honest assertion is that the lane forfeits — not
    #: an empty vector, which asserts nothing while looking like a healthy weight set.
    last_burn: str = "1"
    reported_round: int | None = None  # last submission round we benchmarked+posted
    #: Why the last benchmark attempt failed, or None. Carried rather than raised: the weight
    #: obligation is owed to the chain whether or not the backend answered.
    last_benchmark_error: str | None = None

    def weights(self) -> LaneWeights:
        return LaneWeights(
            {hk: Decimal(v) for hk, v in self.last_weights}, Decimal(self.last_burn)
        )


def approved_workload_for(client: RoundClient, *, require: bool) -> str | None:
    """The measurement every submission must carry, read from the backend, or None to not check.

    `require` is the operator saying "only credit runs from the approved solver". If the backend
    then publishes no pin, this RAISES rather than returning None: silently not checking would
    leave the validator believing it enforces something it does not. It equally must not refuse
    the whole field for that — the caller records the failure and retries, which is an abstention,
    not a mass zero, because a backend that publishes nothing is not the miners' fault.
    """
    if not require:
        return None
    doc = client.fetch_solver()
    pin = str(doc.get("approved_workload_sha256") or "").strip().lower()
    if not doc.get("enforced") or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise RoundRuntimeError(
            "this validator requires the approved-solver pin, but the backend publishes none "
            f"(/v2/solver: {dict(doc)!r}). Refusing to report rather than pretending to check."
        )
    return pin


def benchmark_and_report(
    round_id: int,
    *,
    client: RoundClient,
    benchmark: BenchmarkFn,
    task_weights: Mapping[str, Decimal] | None = None,
    deadline: Callable[[], bool] | None = None,
    approved_workload: str | None = None,
    require_approved_solver: bool = False,
) -> dict[str, MinerRoundResult]:
    """Benchmark every submission of a closed round and report the verdicts to the server.

    ``deadline`` (usually "am I past the compose block?") lets the run stop cleanly: miners not
    reached are reported UNEVALUATED, which the server excludes from the average. Abstaining is
    the honest signal — scoring them 0 would drag them down for this validator's slowness.
    """
    if round_id < 0:
        raise RoundRuntimeError("no submission round to benchmark yet")
    approved_workload = approved_workload_for(client, require=require_approved_solver) \
        if approved_workload is None else approved_workload
    task_ids = list(client.fetch_round_tasks(round_id))
    if not task_ids:
        raise RoundRuntimeError(
            f"round {round_id} published no task set to score against"
        )
    submissions = list(client.fetch_submissions(round_id))
    results = evaluate_round(
        submissions,
        benchmark,
        task_ids=task_ids,
        task_weights=task_weights,
        deadline=deadline,
        approved_workload=approved_workload,
    )
    client.post_results(round_id, results)
    return results


def compose_and_set(
    round_id: int,
    *,
    client: RoundClient,
    set_weights: SetWeightsFn,
    nonce: bytes,
) -> RoundBoard:
    """Fetch the server's averaged scores, compose the KING board, and set the weights on chain.

    An empty field composes an all-burn board and still sets weights: the CyberGym lane forfeits
    its allocation to the sandbox lane (the "no miner -> sandbox lane" rule), carried as
    :attr:`LaneWeights.burn`. It never skips the set, because skipping would let the chain zero
    this validator.
    """
    scores = dict(client.fetch_average_scores(round_id)) if round_id >= 0 else {}
    board = compose_round_board(round_id, scores, nonce=nonce)
    set_weights(
        LaneWeights(
            {s.miner_hotkey: s.lane_share for s in board.standings if s.lane_share > 0},
            board.lane_burn,
        )
    )
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
    require_approved_solver: bool = False,
    cfg: RoundConfig = PRODUCTION,
) -> tuple[RuntimeState, Action]:
    """Advance the loop one block. Returns the new state and the action actually taken.

    Benchmarking happens once per evaluation round, the first time we see a block in it and before
    the compose — so the server has this validator's verdicts to average by the time weights are
    composed. It is deliberately separate from the schedule's weight action: benchmarking is work,
    setting weights is the chain obligation, and a failed or slow benchmark must never delay the
    keep-alive. A benchmark failure is recorded on the state and the weight action still runs; the
    round is retried on the next tick because ``reported_round`` is not advanced.
    """
    scored_round = submission_round_being_scored(block, cfg)
    # 1. Benchmark + report once per evaluation round (idempotent via reported_round).
    if scored_round >= 0 and state.reported_round != scored_round:
        try:
            benchmark_and_report(
                scored_round,
                client=client,
                benchmark=benchmark,
                task_weights=task_weights,
                deadline=deadline,
                require_approved_solver=require_approved_solver,
            )
            state = replace(
                state, reported_round=scored_round, last_benchmark_error=None
            )
        except Exception as exc:
            # A failed report must not stop the weight obligation, and until now it did: the
            # raise propagated out of step() before the weight action, so a backend the validator
            # merely READS from could stop it discharging a chain duty that has nothing to do
            # with the backend, and the chain would zero it for going quiet.
            #
            # `reported_round` is deliberately NOT advanced, so the next tick retries the
            # benchmark. Only the weights go out regardless.
            state = replace(
                state,
                last_benchmark_error=f"benchmark/report failed for round {scored_round}: {exc}",
            )

    # 2. Weight obligation, per the schedule.
    action = next_action(block, state.schedule, cfg)
    if action is Action.COMPOSE_AND_SET:
        board = compose_and_set(
            scored_round,
            client=client,
            set_weights=set_weights,
            nonce=nonce_for(max(scored_round, 0)),
        )
        weights = tuple(
            (s.miner_hotkey, str(s.lane_share))
            for s in board.standings
            if s.lane_share > 0
        )
        state = replace(
            state,
            last_weights=weights,
            last_burn=str(board.lane_burn),
            schedule=record_action(block, action, state.schedule, cfg),
        )
    elif action is Action.REASSERT:
        set_weights(state.weights())
        state = replace(
            state, schedule=record_action(block, action, state.schedule, cfg)
        )
    return state, action


__all__ = [
    "RoundRuntimeError",
    "RoundClient",
    "LaneWeights",
    "SetWeightsFn",
    "NonceFn",
    "RuntimeState",
    "benchmark_and_report",
    "approved_workload_for",
    "compose_and_set",
    "step",
]
