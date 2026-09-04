"""Validator round evaluation: benchmark every submitted PoC, score the round, compose weights.

The evaluation half of the v2 pipeline (jared, 2026-09-04). In the evaluation round the validator:

1. pulls each miner's submission for the round being scored — the PoCs the agent produced in the
   sandbox (within its time/resource limit) plus the per-task PROOF needed to rebuild the corpus;
2. rebuilds each task's corpus ONCE and benchmarks EVERY miner's PoC for that task against it —
   the same vul-crash / fix-clean differential the reward path uses (the ``benchmark`` seam).
   **Grouping by task is what makes the round fit the window**: 200 miners x ~30 tasks is ~6000
   PoCs but only ~30 distinct corpora, so rebuilding per miner would do 200x the container work
   for nothing. Benchmarking a PoC is cheap (run the input against two prebuilt binaries); it is
   the corpus BUILD that costs, so it is paid once per task;
3. scores each miner base-100 (solved / total), composes the per-round KING board, and returns
   the weight vector to set on chain (at the schedule's compose block).

Everything here is pure over its inputs with the differential and the corpus-rebuild injected as
one ``benchmark`` seam, so it is testable without Docker and every validator that benchmarks the
same PoCs against the same proofs derives the identical weights (a consensus requirement — the
KING cutoff is payout-decisive).

Only PoCs the sandbox collected within the limit are present in a submission, so "consider only
PoCs within the time limit" is already enforced upstream; the validator benchmarks what it is
given and never re-runs the agent.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable

from cathedral_thin.cybergym_round_scoring import (
    RoundBoard,
    RoundScoringError,
    compose_round_board,
    round_score_base100,
)


class RoundEvalError(ValueError):
    """Malformed evaluation input. Fails closed."""


@dataclass(frozen=True)
class TaskProof:
    """What a validator needs to rebuild ONE task's corpus and benchmark a PoC against it."""

    task_id: str
    poc: bytes
    proof: Any  # the corpus-rebuild proof (image digests / build inputs); opaque to this module

    def __post_init__(self) -> None:
        if not self.task_id:
            raise RoundEvalError("task proof needs a task_id")
        if not isinstance(self.poc, (bytes, bytearray)):
            raise RoundEvalError("poc must be bytes")


@dataclass(frozen=True)
class Submission:
    """One miner's round submission: the agent it ran and the per-task PoCs+proofs it produced."""

    miner_hotkey: str
    agent_digest: str
    tasks: tuple[TaskProof, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.miner_hotkey:
            raise RoundEvalError("submission needs a miner_hotkey")
        seen = [t.task_id for t in self.tasks]
        if len(seen) != len(set(seen)):
            raise RoundEvalError("a submission benchmarks each task once; task ids repeat")


# (task_id, poc, proof) -> True iff the PoC crashes the vulnerable build AND spares the patched
# one, after rebuilding the task's corpus from the proof. Injected: production wires the real
# docker differential; tests inject a deterministic function.
BenchmarkFn = Callable[[str, bytes, Any], bool]


@dataclass(frozen=True)
class MinerRoundResult:
    miner_hotkey: str
    agent_digest: str
    solved: int
    total: int
    score: Decimal                       # base-100
    per_task: tuple[tuple[str, bool], ...]  # (task_id, solved) for audit
    #: False when this validator did not finish benchmarking this miner (ran out of round, or the
    #: corpus would not build). It reports the miner as UNEVALUATED with score 0, and the backend
    #: EXCLUDES it from the average — a validator that ran out of time must not drag a miner's
    #: score down, only abstain (jared, 2026-09-04).
    evaluated: bool = True


def benchmark_submission(
    submission: Submission, benchmark: BenchmarkFn, *, task_weights: Mapping[str, Decimal] | None = None,
) -> MinerRoundResult:
    """Benchmark every PoC in a submission and score it base-100.

    ``task_weights`` optionally difficulty-weights tasks (default: every task weight 1). A task
    whose benchmark RAISES counts as unsolved (a broken proof or PoC is not a solve) rather than
    aborting the miner's whole round.
    """
    per_task: list[tuple[str, bool]] = []
    solved_w = Decimal(0)
    total_w = Decimal(0)
    for t in submission.tasks:
        w = Decimal(task_weights.get(t.task_id, 1)) if task_weights else Decimal(1)
        total_w += w
        try:
            ok = bool(benchmark(t.task_id, bytes(t.poc), t.proof))
        except Exception:
            ok = False
        if ok:
            solved_w += w
        per_task.append((t.task_id, ok))
    return MinerRoundResult(
        miner_hotkey=submission.miner_hotkey,
        agent_digest=submission.agent_digest,
        solved=sum(1 for _, ok in per_task if ok),
        total=len(per_task),
        score=round_score_base100(solved_w, total_w),
        per_task=tuple(per_task),
    )


def evaluate_round(
    submissions: Sequence[Submission], benchmark: BenchmarkFn,
    *, task_weights: Mapping[str, Decimal] | None = None,
    deadline: Callable[[], bool] | None = None,
) -> dict[str, MinerRoundResult]:
    """Benchmark a whole round, rebuilding each corpus ONCE and reusing it across miners.

    Work is grouped BY TASK, not by miner: 200 miners x ~30 tasks is ~6000 PoCs but only ~30
    distinct corpora, and it is the corpus BUILD that costs — running one input against two
    prebuilt binaries is cheap. Rebuilding per miner would do 200x the container work for nothing
    and would not fit the evaluation window; grouping is what makes 200 submissions evaluable.

    ``deadline() -> True`` means the validator is out of time. Miners not yet benchmarked when it
    trips are returned UNEVALUATED (score 0, ``evaluated=False``) — the backend excludes those
    from the average, so a validator that ran out of time ABSTAINS rather than dragging a miner
    down. A miner partially benchmarked keeps the tasks it completed.
    """
    order: list[str] = []
    tasks_by_id: dict[str, list[tuple[str, TaskProof]]] = {}
    for sub in submissions:
        if sub.miner_hotkey in order:
            raise RoundEvalError(f"two submissions for {sub.miner_hotkey}; one per miner per round")
        order.append(sub.miner_hotkey)
        for tp in sub.tasks:
            tasks_by_id.setdefault(tp.task_id, []).append((sub.miner_hotkey, tp))

    agent_digest = {s.miner_hotkey: s.agent_digest for s in submissions}
    total_tasks = {s.miner_hotkey: len(s.tasks) for s in submissions}
    outcomes: dict[str, list[tuple[str, bool]]] = {hk: [] for hk in order}
    ran_out = False

    # One task at a time: the caller's benchmark rebuilds that task's corpus once and every
    # miner's PoC for it is run against the same build.
    for task_id in sorted(tasks_by_id):
        if deadline is not None and deadline():
            ran_out = True
            break
        for hotkey, tp in tasks_by_id[task_id]:
            try:
                ok = bool(benchmark(task_id, bytes(tp.poc), tp.proof))
            except Exception:
                ok = False
            outcomes[hotkey].append((task_id, ok))

    results: dict[str, MinerRoundResult] = {}
    for hk in order:
        per_task = outcomes[hk]
        complete = len(per_task) == total_tasks[hk]
        evaluated = complete and not (ran_out and not per_task)
        if not per_task and ran_out:
            # never got to this miner: abstain rather than score them zero
            results[hk] = MinerRoundResult(hk, agent_digest[hk], 0, total_tasks[hk],
                                           Decimal(0), (), evaluated=False)
            continue
        w = task_weights or {}
        solved_w = sum((Decimal(w.get(t, 1)) for t, ok in per_task if ok), Decimal(0))
        total_w = sum((Decimal(w.get(t, 1)) for t, _ in per_task), Decimal(0))
        results[hk] = MinerRoundResult(
            miner_hotkey=hk, agent_digest=agent_digest[hk],
            solved=sum(1 for _, ok in per_task if ok), total=len(per_task),
            score=round_score_base100(solved_w, total_w), per_task=tuple(per_task),
            evaluated=complete,
        )
    return results


def compose_round_weights(
    source_epoch: int, results: Mapping[str, MinerRoundResult], *, nonce: bytes | str,
) -> RoundBoard:
    """Compose the per-round KING board from benchmarked results -> the lane weight vector.

    The scores fed to the board are the benchmarked base-100 round scores, so the composed shares
    are a pure function of what was actually reproduced on chain-verifiable proofs — never a
    miner's self-report.
    """
    # UNEVALUATED miners are excluded, not scored zero: this validator abstained on them, and a
    # zero would be indistinguishable from "benchmarked and solved nothing". The backend applies
    # the same rule when averaging across validators.
    scores = {hk: r.score for hk, r in results.items() if r.evaluated}
    return compose_round_board(source_epoch, scores, nonce=nonce)


__all__ = [
    "RoundEvalError", "TaskProof", "Submission", "BenchmarkFn", "MinerRoundResult",
    "benchmark_submission", "evaluate_round", "compose_round_weights",
]
