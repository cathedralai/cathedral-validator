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
    compose_round_board,
    round_score_base100,
)


class RoundEvalError(ValueError):
    """Malformed evaluation input. Fails closed."""


class BenchmarkUnavailable(Exception):
    """The differential could not be RUN — a dead Docker daemon, a missing image, no disk.

    Distinct from a PoC that simply did not reproduce, and the distinction decides a payout. A PoC
    that fails is the miner's result and scores zero. A differential we could not run is OUR
    failure, and reporting it as zero states something false about the miner to their cost.

    Raised by the benchmark seam; `evaluate_round` turns it into an abstention, exactly as it
    already does for a validator that ran out of time.
    """


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
    #: The enclave receipt for the run that produced these PoCs, as the backend published it.
    #: None means the run carried no usable receipt — which is a verdict about the evidence, not a
    #: missing field, and this validator can decide what to do about it (see `solver_refusal`).
    attestation: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.miner_hotkey:
            raise RoundEvalError("submission needs a miner_hotkey")
        seen = [t.task_id for t in self.tasks]
        if len(seen) != len(set(seen)):
            raise RoundEvalError(
                "a submission benchmarks each task once; task ids repeat"
            )


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
    score: Decimal  # base-100
    per_task: tuple[tuple[str, bool], ...]  # (task_id, solved) for audit
    #: False when this validator did not finish benchmarking this miner (ran out of round, or the
    #: corpus would not build). It reports the miner as UNEVALUATED with score 0, and the backend
    #: EXCLUDES it from the average — a validator that ran out of time must not drag a miner's
    #: score down, only abstain (jared, 2026-09-04).
    evaluated: bool = True


def solver_refusal(submission: Submission, approved_workload: str) -> str | None:
    """Why this submission fails the approved-solver pin, or None if it passes.

    The backend runs every agent itself, so its receipt is the only evidence of WHICH program
    produced a PoC — and "we enforced the pin" is a claim the backend makes about itself. Checking
    it here is what makes the measurement worth taking: our corpus is public bugs with published
    reference PoCs, so an enclave run of a lookup table is as genuinely attested as an enclave run
    of an agent that derived the crash. Only the measurement separates them.

    Fails closed on every missing piece: no receipt, the wrong measurement, a hardware quote that
    did not verify, a report that did not bind this dispatch, or a run that did not read the
    payload the backend says it sent.
    """
    att = submission.attestation
    if not att:
        return "no attestation: nothing says which program produced these PoCs"
    measured = str(att.get("workload_sha256") or "")
    if not measured:
        return "attestation carries no workload_sha256"
    if measured.lower() != approved_workload.lower():
        return f"measured {measured}, not the approved solver {approved_workload}"
    if not att.get("intel_verified"):
        return "the hardware quote did not verify"
    if not att.get("report_data_match"):
        return "the receipt does not bind this dispatch"
    # Only demanded when the backend reports on it at all: an older backend omits the key, and
    # refusing every miner over a field that does not exist would be this validator's fault, not
    # theirs. Present-and-false is a real failure and is refused.
    if "payload_bound" in att and not att.get("payload_bound"):
        return "the enclave did not read the payload the backend sent"
    return None


def _refused_result(
    submission: Submission, denominator: Sequence[str] | None
) -> MinerRoundResult:
    """A refused submission scores zero, EVALUATED — a verdict, not an abstention.

    The distinction decides a payout. Abstaining says "I could not judge this", which the backend
    excludes from the average; refusing says "I judged the evidence and it does not hold up", which
    must count. Nothing is benchmarked: the PoCs may well crash the target, but a crash nobody can
    attribute to an approved solver is exactly what this lane refuses to pay for.
    """
    tasks = list(denominator) if denominator is not None else [t.task_id for t in submission.tasks]
    return MinerRoundResult(
        miner_hotkey=submission.miner_hotkey,
        agent_digest=submission.agent_digest,
        solved=0,
        total=len(tasks),
        score=Decimal(0),
        per_task=tuple((t, False) for t in tasks),
    )


def benchmark_submission(
    submission: Submission,
    benchmark: BenchmarkFn,
    *,
    task_ids: Sequence[str] | None = None,
    task_weights: Mapping[str, Decimal] | None = None,
) -> MinerRoundResult:
    """Benchmark every PoC in a submission and score it base-100.

    ``task_ids`` is the ROUND's authoritative task set and is what the score is out of. Passing it
    is what keeps the denominator off the miner (see :func:`evaluate_round`); it defaults to the
    submitted set only so a single-submission call in a test stays convenient.

    ``task_weights`` optionally difficulty-weights tasks (default: every task weight 1). A task
    whose benchmark RAISES counts as unsolved (a broken proof or PoC is not a solve) rather than
    aborting the miner's whole round.
    """
    authoritative = (
        list(task_ids)
        if task_ids is not None
        else [t.task_id for t in submission.tasks]
    )
    allowed = set(authoritative)
    submitted = {t.task_id: t for t in submission.tasks if t.task_id in allowed}
    per_task: list[tuple[str, bool]] = []
    for task_id in authoritative:
        tp = submitted.get(task_id)
        if tp is None:
            per_task.append((task_id, False))  # not attempted is not solved
            continue
        try:
            ok = bool(benchmark(task_id, bytes(tp.poc), tp.proof))
        except Exception:
            ok = False
        per_task.append((task_id, ok))
    w = task_weights or {}
    solved_w = sum((Decimal(w.get(t, 1)) for t, ok in per_task if ok), Decimal(0))
    total_w = sum((Decimal(w.get(t, 1)) for t, _ in per_task), Decimal(0))
    return MinerRoundResult(
        miner_hotkey=submission.miner_hotkey,
        agent_digest=submission.agent_digest,
        solved=sum(1 for _, ok in per_task if ok),
        total=len(per_task),
        score=round_score_base100(solved_w, total_w),
        per_task=tuple(per_task),
    )


def evaluate_round(
    submissions: Sequence[Submission],
    benchmark: BenchmarkFn,
    *,
    task_ids: Sequence[str] | None = None,
    task_weights: Mapping[str, Decimal] | None = None,
    deadline: Callable[[], bool] | None = None,
    approved_workload: str | None = None,
) -> dict[str, MinerRoundResult]:
    """Benchmark a whole round, rebuilding each corpus ONCE and reusing it across miners.

    Work is grouped BY TASK, not by miner: 200 miners x ~30 tasks is ~6000 PoCs but only ~30
    distinct corpora, and it is the corpus BUILD that costs — running one input against two
    prebuilt binaries is cheap. Rebuilding per miner would do 200x the container work for nothing
    and would not fit the evaluation window; grouping is what makes 200 submissions evaluable.

    ``task_ids`` is the round's authoritative task set, published by the server and identical for
    every miner. **The score is out of THAT set, never out of what a miner chose to submit.** With
    a per-submission denominator a miner submits only the tasks it solved and scores 100 while an
    honest miner that attempted all of them and solved five of six scores 83 — the cheat is simply
    withholding your failures, and it wins the king slot. Scoring against the published set closes
    it from both directions: an unsubmitted task counts unsolved, and a task the miner invented
    that is not in the set is ignored rather than padding the numerator.

    A benchmark raising :class:`BenchmarkUnavailable` means the differential could not be RUN, and
    the miner abstains for that task rather than being scored zero on it — one broken validator
    must not drag the whole field down for a fault that says nothing about any miner.

    ``deadline() -> True`` means the validator is out of time. Miners not yet benchmarked when it
    trips are returned UNEVALUATED (score 0, ``evaluated=False``) — the backend excludes those
    from the average, so a validator that ran out of time ABSTAINS rather than dragging a miner
    down. A miner partially benchmarked keeps the tasks it completed.
    """
    order: list[str] = []
    tasks_by_id: dict[str, list[tuple[str, TaskProof]]] = {}
    allowed = set(task_ids) if task_ids is not None else None
    #: Submissions whose evidence does not hold up, and why. Scored zero without benchmarking:
    #: the PoCs may well crash the target, but a crash nobody can attribute to the approved solver
    #: is what this lane exists not to pay for.
    refused: dict[str, str] = {}
    by_hotkey = {s.miner_hotkey: s for s in submissions}
    for sub in submissions:
        if sub.miner_hotkey in order:
            raise RoundEvalError(
                f"two submissions for {sub.miner_hotkey}; one per miner per round"
            )
        order.append(sub.miner_hotkey)
        if approved_workload:
            why = solver_refusal(sub, approved_workload)
            if why:
                refused[sub.miner_hotkey] = why
                continue
        for tp in sub.tasks:
            if allowed is not None and tp.task_id not in allowed:
                continue  # not in this round's set: ignored, never scored
            tasks_by_id.setdefault(tp.task_id, []).append((sub.miner_hotkey, tp))

    agent_digest = {s.miner_hotkey: s.agent_digest for s in submissions}
    # How many benchmark verdicts this miner should end up with — used only to tell "finished" from
    # "ran out of time". The SCORE denominator is the authoritative set below, not this.
    submitted_count = {
        s.miner_hotkey: sum(
            1 for tp in s.tasks if allowed is None or tp.task_id in allowed
        )
        for s in submissions
    }
    denominator = list(task_ids) if task_ids is not None else None
    outcomes: dict[str, list[tuple[str, bool]]] = {hk: [] for hk in order}
    #: Miners with at least one task we could not judge. Their score would understate them.
    unjudged: set[str] = set()
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
            except BenchmarkUnavailable:
                # We could not judge this one. Record nothing: the miner ends up short of its
                # expected verdicts and is reported UNEVALUATED below, rather than carrying a zero
                # that says its PoC failed when we never actually ran it.
                unjudged.add(hotkey)
                continue
            except Exception:
                # A broken PoC or a malformed proof IS the miner's result, and it is not a solve.
                ok = False
            outcomes[hotkey].append((task_id, ok))

    results: dict[str, MinerRoundResult] = {}
    for hk in order:
        if hk in refused:
            # A verdict, not an abstention: "I judged the evidence and it does not hold up" must
            # count against the miner, where "I could not judge this" must not.
            results[hk] = _refused_result(by_hotkey[hk], denominator)
            continue
        benchmarked = outcomes[hk]
        # Unjudged means incomplete however many other tasks succeeded: a partial score reported
        # as evaluated is a number we know to be too low.
        complete = len(benchmarked) == submitted_count[hk] and hk not in unjudged
        if not benchmarked and (ran_out or hk in unjudged) and submitted_count[hk]:
            # never got to this miner: abstain rather than score them zero
            results[hk] = MinerRoundResult(
                hk,
                agent_digest[hk],
                0,
                submitted_count[hk],
                Decimal(0),
                (),
                evaluated=False,
            )
            continue
        # Pad the authoritative set: a task this miner never submitted is an unsolved task, and it
        # belongs in the audit trail as one rather than silently shrinking the denominator.
        got = dict(benchmarked)
        per_task = (
            [(t, got.get(t, False)) for t in denominator]
            if denominator is not None
            else benchmarked
        )
        w = task_weights or {}
        solved_w = sum((Decimal(w.get(t, 1)) for t, ok in per_task if ok), Decimal(0))
        total_w = sum((Decimal(w.get(t, 1)) for t, _ in per_task), Decimal(0))
        results[hk] = MinerRoundResult(
            miner_hotkey=hk,
            agent_digest=agent_digest[hk],
            solved=sum(1 for _, ok in per_task if ok),
            total=len(per_task),
            score=round_score_base100(solved_w, total_w),
            per_task=tuple(per_task),
            evaluated=complete,
        )
    return results


def compose_round_weights(
    source_epoch: int,
    results: Mapping[str, MinerRoundResult],
    *,
    nonce: bytes | str,
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
    "RoundEvalError",
    "BenchmarkUnavailable",
    "TaskProof",
    "Submission",
    "BenchmarkFn",
    "MinerRoundResult",
    "benchmark_submission",
    "solver_refusal",
    "evaluate_round",
    "compose_round_weights",
]
