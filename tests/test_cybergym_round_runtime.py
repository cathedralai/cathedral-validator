"""The validator round loop: benchmark+report, then compose weights from the server average."""
import sys
from decimal import Decimal
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from cathedral_thin.cybergym_round_eval import Submission, TaskProof
from cathedral_thin.cybergym_round_runtime import (
    RoundRuntimeError, RuntimeState, benchmark_and_report, compose_and_set, step,
)
from cathedral_thin.cybergym_round_schedule import Action, ROUND_BLOCKS, WEIGHT_SET_OFFSET


class FakeClient:
    def __init__(self, submissions=None, averages=None):
        self._subs = submissions or []
        self._avgs = averages or {}
        self.posted = []
        self.fetched_avg_for = []
    def fetch_submissions(self, round_id):
        return self._subs
    def post_results(self, round_id, results):
        self.posted.append((round_id, dict(results)))
    def fetch_average_scores(self, round_id):
        self.fetched_avg_for.append(round_id)
        return self._avgs


def _sub(hk, tasks):
    return Submission(hk, "sha256:"+hk, tuple(TaskProof(t, b"p"+t.encode(), {"img": t}) for t in tasks))

SOLVE_ALL = lambda tid, poc, proof: True
SOLVE_NONE = lambda tid, poc, proof: False


class TestBenchmarkAndReport:
    def test_it_benchmarks_and_posts(self):
        c = FakeClient(submissions=[_sub("a", ["t1", "t2"]), _sub("b", ["t1", "t2"])])
        res = benchmark_and_report(3, client=c, benchmark=SOLVE_ALL)
        assert set(res) == {"a", "b"} and res["a"].score == Decimal("100")
        assert c.posted and c.posted[0][0] == 3

    def test_no_round_yet_refused(self):
        with pytest.raises(RoundRuntimeError):
            benchmark_and_report(-1, client=FakeClient(), benchmark=SOLVE_ALL)


class TestComposeAndSetUsesTheServerAverage:
    def test_weights_come_from_the_averaged_scores_not_our_own_benchmark(self):
        # our benchmark says nobody solved; the server average says 'a' leads -> weights follow
        # the AVERAGE, which is what makes validators converge on one number.
        c = FakeClient(averages={"a": 90, "b": 40})
        got = {}
        board = compose_and_set(2, client=c, set_weights=lambda w: got.update(w), nonce=b"n")
        assert c.fetched_avg_for == [2]
        assert got == {"a": Decimal("0.93"), "b": Decimal("0.07")}
        assert board.winners == ("a", "b")

    def test_empty_field_still_sets_weights_and_burns(self):
        c = FakeClient(averages={})
        calls = []
        board = compose_and_set(2, client=c, set_weights=lambda w: calls.append(w), nonce=b"n")
        assert board.lane_burn == Decimal("1")
        assert calls == [{}]      # still set (never skip — the chain would zero us)


class TestStep:
    def _step(self, block, state, client, **kw):
        return step(block, state, client=client, benchmark=kw.get("bench", SOLVE_ALL),
                    set_weights=kw.get("sw", lambda w: None), nonce_for=lambda r: b"nonce")

    def test_benchmarks_once_per_evaluation_round(self):
        c = FakeClient(submissions=[_sub("a", ["t1"])], averages={"a": 100})
        st = RuntimeState()
        # two blocks in round 1 -> only one benchmark+post for round 0
        st, _ = self._step(ROUND_BLOCKS + 10, st, c)
        st, _ = self._step(ROUND_BLOCKS + 20, st, c)
        assert len(c.posted) == 1 and c.posted[0][0] == 0
        assert st.reported_round == 0

    def test_compose_at_the_offset_sets_weights_from_the_average(self):
        c = FakeClient(submissions=[_sub("a", ["t1"])], averages={"a": 100, "b": 50})
        got = {}
        st = RuntimeState()
        st, action = self._step(ROUND_BLOCKS + WEIGHT_SET_OFFSET, st, c, sw=lambda w: got.update(w))
        assert action is Action.COMPOSE_AND_SET
        assert got == {"a": Decimal("0.93"), "b": Decimal("0.07")}
        assert st.last_weights  # remembered for re-assertion

    def test_reassert_replays_the_same_weights(self):
        c = FakeClient(submissions=[], averages={"a": 100})
        seen = []
        st = RuntimeState()
        st, _ = self._step(ROUND_BLOCKS + WEIGHT_SET_OFFSET, st, c, sw=lambda w: seen.append(dict(w)))
        st, action = self._step(ROUND_BLOCKS + WEIGHT_SET_OFFSET + 300, st, c,
                                sw=lambda w: seen.append(dict(w)))
        assert action is Action.REASSERT
        assert seen[-1] == seen[0]      # the SAME weights re-set, per Bittensor's cadence

    def test_round_zero_has_nothing_to_benchmark(self):
        c = FakeClient()
        st, action = self._step(10, RuntimeState(), c)
        assert c.posted == []           # nothing to score yet
        assert action is Action.REASSERT  # but still assert weights (never sit dark)

    def test_a_failing_report_raises_rather_than_silently_skipping(self):
        class Boom(FakeClient):
            def post_results(self, *a, **k): raise RuntimeError("server down")
        with pytest.raises(RoundRuntimeError):
            self._step(ROUND_BLOCKS + 5, RuntimeState(), Boom(submissions=[_sub("a", ["t1"])]))
