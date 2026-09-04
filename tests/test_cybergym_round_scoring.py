"""Per-round KING scoring owned by the validator (not a rolling tournament)."""
import sys
from decimal import Decimal
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from cathedral_thin.cybergym_round_scoring import (
    RUNNER_UP_SHARES, RoundScoringError, award_shares, compose_round_board, round_score_base100,
)
NONCE = b"round-nonce"


class TestKingCurve:
    def test_every_miner_count(self):
        assert award_shares(0) == []
        assert award_shares(1) == [Decimal("1")]
        assert award_shares(2) == [Decimal("0.93"), Decimal("0.07")]
        assert award_shares(3) == [Decimal("0.90"), Decimal("0.07"), Decimal("0.03")]
        assert award_shares(4) == [Decimal("0.87"), Decimal("0.07"), Decimal("0.03"), Decimal("0.03")]
        assert award_shares(5) == [Decimal("0.84"), Decimal("0.07"), Decimal("0.03"), Decimal("0.03"), Decimal("0.03")]

    def test_six_plus_capped_at_five(self):
        assert award_shares(9) == award_shares(5)

    def test_nonempty_sums_to_one(self):
        for n in range(1, 8):
            assert sum(award_shares(n)) == Decimal("1")

    def test_runner_up_constant(self):
        assert RUNNER_UP_SHARES == (Decimal("0.07"), Decimal("0.03"), Decimal("0.03"), Decimal("0.03"))


class TestBase100:
    def test_completion(self):
        assert round_score_base100(0, 0) == Decimal("0")
        assert round_score_base100(10, 10) == Decimal("100")
        assert round_score_base100(1, 4) == Decimal("25")

    def test_fails_closed(self):
        with pytest.raises(RoundScoringError):
            round_score_base100(5, 4)


class TestBoard:
    def test_one_miner_takes_the_lane(self):
        b = compose_round_board(1, {"a": 50}, nonce=NONCE)
        assert b.winners == ("a",) and b.standings[0].lane_share == Decimal("1")

    def test_king_and_tail(self):
        b = compose_round_board(1, {"a": 90, "b": 80, "c": 70}, nonce=NONCE)
        sh = {s.miner_hotkey: s.lane_share for s in b.standings}
        assert sh == {"a": Decimal("0.90"), "b": Decimal("0.07"), "c": Decimal("0.03")}

    def test_zero_scores_burn_the_lane(self):
        b = compose_round_board(1, {"x": 0}, nonce=NONCE)
        assert b.winners == () and b.lane_burn == Decimal("1")

    def test_empty_field_burns(self):
        assert compose_round_board(1, {}, nonce=NONCE).lane_burn == Decimal("1")

    def test_deterministic_and_nonce_keyed(self):
        a = compose_round_board(1, {"a": 50, "b": 50}, nonce=b"n1").winners
        assert a == compose_round_board(1, {"a": 50, "b": 50}, nonce=b"n1").winners

    def test_bad_nonce_refused(self):
        for bad in (None, 0, b"", ""):
            with pytest.raises(RoundScoringError):
                compose_round_board(1, {"a": 50}, nonce=bad)
