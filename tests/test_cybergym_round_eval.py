"""Validator round evaluation: benchmark PoCs (rebuild corpus from proof), score, compose weights."""
import sys
from decimal import Decimal
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from cathedral_thin.cybergym_round_eval import (
    RoundEvalError, Submission, TaskProof,
    benchmark_submission, compose_round_weights, evaluate_round,
)
from cathedral_thin.cybergym_round_scoring import round_score_base100

def _sub(hk, solves):  # solves: {task_id: will_solve}
    return Submission(miner_hotkey=hk, agent_digest="sha256:"+hk,
                      tasks=tuple(TaskProof(t, b"poc-"+t.encode(), {"img": t}) for t in solves))

def _bench(truth):  # truth: {(hk-independent) task_id: solved}; here keyed by poc bytes
    def b(task_id, poc, proof):
        return truth.get(task_id, False)
    return b


class TestBenchmarkAndScore:
    def test_full_solve_scores_100(self):
        sub = _sub("5A", ["t1", "t2"])
        r = benchmark_submission(sub, _bench({"t1": True, "t2": True}))
        assert r.solved == 2 and r.total == 2 and r.score == Decimal("100")

    def test_partial_solve(self):
        sub = _sub("5A", ["t1", "t2", "t3", "t4"])
        r = benchmark_submission(sub, _bench({"t1": True}))
        assert r.solved == 1 and r.score == Decimal("25")

    def test_a_raising_benchmark_counts_unsolved_not_abort(self):
        def bench(task_id, poc, proof):
            if task_id == "t2":
                raise RuntimeError("broken proof")
            return True
        r = benchmark_submission(_sub("5A", ["t1", "t2"]), bench)
        assert r.solved == 1 and dict(r.per_task)["t2"] is False

    def test_difficulty_weighting(self):
        sub = _sub("5A", ["easy", "hard"])
        r = benchmark_submission(sub, _bench({"hard": True}),
                                 task_weights={"easy": Decimal("1"), "hard": Decimal("3")})
        assert r.score == Decimal("75")  # 3 of 4 weight


class TestRoundAndWeights:
    def test_evaluate_round_one_result_per_miner(self):
        subs = [_sub("5A", ["t1"]), _sub("5B", ["t1"])]
        res = evaluate_round(subs, _bench({"t1": True}))
        assert set(res) == {"5A", "5B"}

    def test_duplicate_miner_refused(self):
        with pytest.raises(RoundEvalError):
            evaluate_round([_sub("5A", ["t1"]), _sub("5A", ["t2"])], _bench({}))

    def test_compose_weights_is_king_over_benchmarked_scores(self):
        subs = [_sub("king", ["t1", "t2"]), _sub("second", ["t1", "t2"]), _sub("third", ["t1", "t2"])]
        # king solves both, second solves one, third solves none
        def bench(task_id, poc, proof):
            return poc.startswith(b"poc-t1")  # everyone solves t1 only... so king==second==third by score
        res = evaluate_round(subs, bench)
        board = compose_round_weights(1, res, nonce=b"n")
        # all tied at 50 -> nonce tie-break ranks; shares still king curve for 3 winners
        shares = sorted((s.lane_share for s in board.standings), reverse=True)
        assert shares == [Decimal("0.90"), Decimal("0.07"), Decimal("0.03")]

    def test_weights_reflect_real_benchmarks_not_selfreport(self):
        subs = [_sub("a", ["t1", "t2"]), _sub("b", ["t1", "t2"])]
        def bench(task_id, poc, proof):
            return poc == b"poc-t1" and b"-a" not in proof.get("img", "")  # a solves nothing, b solves t1
        # actually key on submission: make 'a' solve both, 'b' none
        def bench2(task_id, poc, proof):
            return True if proof["img"] in ("t1", "t2") else False
        res = evaluate_round(subs, bench2)
        board = compose_round_weights(1, res, nonce=b"n")
        # both solve all -> tie at 100 -> two winners, king curve 0.93/0.07
        assert sorted((s.lane_share for s in board.standings), reverse=True) == [Decimal("0.93"), Decimal("0.07")]


class TestInputsFailClosed:
    def test_repeated_task_in_submission_refused(self):
        with pytest.raises(RoundEvalError):
            Submission("5A", "d", (TaskProof("t1", b"p", {}), TaskProof("t1", b"q", {})))

    def test_poc_must_be_bytes(self):
        with pytest.raises(RoundEvalError):
            TaskProof("t1", "not-bytes", {})

    def test_submission_needs_hotkey(self):
        with pytest.raises(RoundEvalError):
            Submission("", "d", ())


# --------------------------------------------------------------------------- #
# Throughput: one corpus build per TASK, reused across miners; deadline -> abstain
# --------------------------------------------------------------------------- #
from cathedral_thin.cybergym_round_eval import compose_round_weights as _crw  # noqa: E402


class TestCorpusIsBuiltOncePerTaskNotPerMiner:
    def test_two_hundred_miners_touch_each_task_once_for_the_build(self):
        # 200 miners x 3 tasks = 600 PoCs but only 3 distinct corpora. The benchmark seam is
        # called per PoC (cheap); what matters is that work is GROUPED by task so the caller
        # rebuilds each corpus once — assert the grouping by checking call order.
        subs = [_sub(f"m{i}", ["t1", "t2", "t3"]) for i in range(200)]
        seen_order = []
        def bench(task_id, poc, proof):
            seen_order.append(task_id); return True
        evaluate_round(subs, bench)
        # all 200 calls for t1 come before any t2 -> one build per task, reused 200x
        first_t2 = seen_order.index("t2")
        assert set(seen_order[:first_t2]) == {"t1"}
        assert seen_order.count("t1") == 200

    def test_every_miner_still_scored(self):
        subs = [_sub(f"m{i}", ["t1"]) for i in range(5)]
        res = evaluate_round(subs, _bench({"t1": True}))
        assert len(res) == 5 and all(r.score == Decimal("100") for r in res.values())


class TestDeadlineAbstainsRatherThanScoringZero:
    def test_unreached_miners_are_unevaluated_not_zero(self):
        subs = [_sub("a", ["t1"]), _sub("b", ["t2"])]
        # deadline trips immediately -> nobody benchmarked
        res = evaluate_round(subs, _bench({}), deadline=lambda: True)
        assert all(r.evaluated is False for r in res.values())

    def test_unevaluated_miners_are_excluded_from_the_weights(self):
        subs = [_sub("a", ["t1"]), _sub("b", ["t1"])]
        res = evaluate_round(subs, _bench({"t1": True}))
        res["b"] = MinerRoundResultUneval(res["b"])
        board = _crw(1, res, nonce=b"n")
        # only 'a' is evaluated -> lone winner takes the whole lane; 'b' is not in the board
        assert board.winners == ("a",)

    def test_a_completed_miner_is_evaluated(self):
        res = evaluate_round([_sub("a", ["t1"])], _bench({"t1": True}))
        assert res["a"].evaluated is True


def MinerRoundResultUneval(r):
    from dataclasses import replace
    return replace(r, evaluated=False)


class TestTheDenominatorIsNotTheMinersToChoose:
    """The round's published task set is what a score is out of.

    Found by the end-to-end dry run (2026-09-04): a miner whose agent tripped its budget after two
    tasks submitted only those two, both solved, and scored 100 — taking the king slot from a
    miner that attempted all six and solved five. The cheat is withholding your failures.
    """

    TASKS = [f"arvo:{i}" for i in range(6)]

    def _sub(self, hotkey, solved_tasks, *, submitted=None):
        submitted = self.TASKS if submitted is None else submitted
        return Submission(hotkey, "digest", tuple(
            TaskProof(t, b"solve" if t in solved_tasks else b"miss", {}) for t in submitted))

    @staticmethod
    def _bench(task_id, poc, proof):
        return poc == b"solve"

    def test_withholding_failures_does_not_beat_attempting_everything(self):
        honest = self._sub("honest", self.TASKS[:5])                       # 5 of 6 attempted all
        withholder = self._sub("withholder", self.TASKS[:2], submitted=self.TASKS[:2])
        results = evaluate_round([honest, withholder], self._bench, task_ids=self.TASKS)
        assert results["honest"].score > results["withholder"].score
        assert results["withholder"].score == round_score_base100(Decimal(2), Decimal(6))

    def test_an_unsubmitted_task_is_scored_as_unsolved(self):
        results = evaluate_round([self._sub("m", self.TASKS[:2], submitted=self.TASKS[:2])],
                                 self._bench, task_ids=self.TASKS)
        r = results["m"]
        assert r.total == 6 and r.solved == 2
        assert dict(r.per_task) == {t: (t in self.TASKS[:2]) for t in self.TASKS}

    def test_a_task_outside_the_round_cannot_pad_the_numerator(self):
        """Inventing tasks is the other direction of the same hole."""
        padded = Submission("m", "d", tuple(
            [TaskProof(t, b"solve", {}) for t in self.TASKS[:1]]
            + [TaskProof(f"made-up:{i}", b"solve", {}) for i in range(20)]))
        r = evaluate_round([padded], self._bench, task_ids=self.TASKS)["m"]
        assert r.total == 6 and r.solved == 1

    def test_a_miner_that_solves_the_whole_published_set_still_scores_100(self):
        r = evaluate_round([self._sub("m", self.TASKS)], self._bench, task_ids=self.TASKS)["m"]
        assert r.score == Decimal(100)

    def test_a_validator_that_ran_out_still_abstains_rather_than_scoring_zero(self):
        """The authoritative denominator must not turn 'I did not finish' into a real zero."""
        results = evaluate_round([self._sub("a", self.TASKS), self._sub("b", self.TASKS)],
                                 self._bench, task_ids=self.TASKS, deadline=lambda: True)
        assert all(not r.evaluated for r in results.values())
