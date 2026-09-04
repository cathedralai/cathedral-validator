"""Validator round evaluation: benchmark every submitted PoC, score the round, compose weights.

The evaluation half of the v2 pipeline (jared, 2026-09-04). In the evaluation round the validator:

1. pulls each miner's submission for the round being scored — the PoCs the agent produced in the
   sandbox (within its time/resource limit) plus the per-task PROOF needed to rebuild the corpus;
2. rebuilds each task's corpus from its proof, ONE BY ONE, and benchmarks the PoC — the same
   vul-crash / fix-clean differential the reward path uses (the ``benchmark`` seam);
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
) -> dict[str, MinerRoundResult]:
    """Benchmark every submission. One result per miner; a repeated hotkey is refused."""
    results: dict[str, MinerRoundResult] = {}
    for sub in submissions:
        if sub.miner_hotkey in results:
            raise RoundEvalError(f"two submissions for {sub.miner_hotkey}; one per miner per round")
        results[sub.miner_hotkey] = benchmark_submission(sub, benchmark, task_weights=task_weights)
    return results


def compose_round_weights(
    source_epoch: int, results: Mapping[str, MinerRoundResult], *, nonce: bytes | str,
) -> RoundBoard:
    """Compose the per-round KING board from benchmarked results -> the lane weight vector.

    The scores fed to the board are the benchmarked base-100 round scores, so the composed shares
    are a pure function of what was actually reproduced on chain-verifiable proofs — never a
    miner's self-report.
    """
    scores = {hk: r.score for hk, r in results.items()}
    return compose_round_board(source_epoch, scores, nonce=nonce)


__all__ = [
    "RoundEvalError", "TaskProof", "Submission", "BenchmarkFn", "MinerRoundResult",
    "benchmark_submission", "evaluate_round", "compose_round_weights",
]
