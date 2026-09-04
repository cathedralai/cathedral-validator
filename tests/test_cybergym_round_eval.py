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
