"""The v2 round schedule: 24h submit->evaluate->emit pipeline, weight at 6600, re-assert every 300."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_thin.cybergym_round_schedule import (
    REASSERT_BLOCKS,
    ROUND_BLOCKS,
    WEIGHT_SET_OFFSET,
    Action,
    ScheduleState,
    block_offset,
    is_weight_set_block,
    next_action,
    record_action,
    round_bounds,
    round_index,
    submission_round_being_scored,
)


class TestRoundGeometry:
    def test_round_is_7200_blocks(self):
        assert ROUND_BLOCKS == 7200 and WEIGHT_SET_OFFSET == 6600 and REASSERT_BLOCKS == 300

    def test_round_index_and_bounds(self):
        assert round_index(0) == 0 and round_index(7199) == 0 and round_index(7200) == 1
        assert round_bounds(1) == (7200, 14400)

    def test_offset(self):
        assert block_offset(6600) == 6600 and block_offset(7200) == 0 and block_offset(14400 + 5) == 5

    def test_negative_block_refused(self):
        with pytest.raises(ValueError):
            round_index(-1)


class TestThePipelineOffset:
    def test_evaluation_round_scores_the_previous_submission_round(self):
        # a block in round 2 composes round 1's submissions
        assert submission_round_being_scored(2 * ROUND_BLOCKS + 100) == 1

    def test_round_zero_has_nothing_before_it(self):
        assert submission_round_being_scored(50) == -1  # empty board -> all burn

    def test_submit_now_paid_two_rounds_later(self):
        # submitted in round R; the compose that scores R happens in round R+1; emission R+2.
        submit_round = 4
        # the block in R+1 that composes R:
        compose_block = (submit_round + 1) * ROUND_BLOCKS + WEIGHT_SET_OFFSET
        assert submission_round_being_scored(compose_block) == submit_round


class TestWeightSetPoint:
    def test_it_fires_only_at_the_offset(self):
        assert is_weight_set_block(WEIGHT_SET_OFFSET)
        assert is_weight_set_block(ROUND_BLOCKS + WEIGHT_SET_OFFSET)
        assert not is_weight_set_block(WEIGHT_SET_OFFSET - 1)
        assert not is_weight_set_block(0)


class TestNextAction:
    def test_compose_and_set_at_the_offset_once_per_round(self):
        st = ScheduleState(last_set_block=6600 - 10, last_composed_round=None)
        assert next_action(6600, st) is Action.COMPOSE_AND_SET
        st2 = record_action(6600, Action.COMPOSE_AND_SET, st)
        # the same round's later blocks do NOT recompose
        assert next_action(6600, st2) is Action.WAIT or next_action(6601, st2) is not Action.COMPOSE_AND_SET
        assert st2.last_composed_round == 0

    def test_compose_is_idempotent_across_a_restart(self):
        # reloaded state says round 0 already composed; hitting 6600 again must not recompose
        st = ScheduleState(last_set_block=6600, last_composed_round=0)
        assert next_action(6600, st) is not Action.COMPOSE_AND_SET

    def test_reassert_every_300_blocks(self):
        st = ScheduleState(last_set_block=1000, last_composed_round=0)
        assert next_action(1000 + REASSERT_BLOCKS, st) is Action.REASSERT
        assert next_action(1000 + REASSERT_BLOCKS - 1, st) is Action.WAIT

    def test_first_ever_action_asserts_immediately(self):
        # never set weights -> don't sit dark until the first offset
        assert next_action(42, ScheduleState()) is Action.REASSERT

    def test_compose_takes_precedence_over_reassert(self):
        # at the offset AND 300+ blocks stale: compose wins (the authoritative update)
        st = ScheduleState(last_set_block=6600 - 400, last_composed_round=None)
        assert next_action(6600, st) is Action.COMPOSE_AND_SET

    def test_record_wait_is_a_noop(self):
        st = ScheduleState(last_set_block=5, last_composed_round=0)
        assert record_action(9, Action.WAIT, st) == st

    def test_a_full_round_walk_composes_once_and_reasserts_on_cadence(self):
        st = ScheduleState()
        composes = 0; reasserts = 0
        # walk one round at 100-block granularity from a fresh validator
        for b in range(0, ROUND_BLOCKS, 100):
            a = next_action(b, st)
            if a is Action.COMPOSE_AND_SET: composes += 1
            elif a is Action.REASSERT: reasserts += 1
            st = record_action(b, a, st)
        # exactly one authoritative compose in the round; several keep-alives; never dark too long
        assert composes == 1
        assert reasserts >= 1
