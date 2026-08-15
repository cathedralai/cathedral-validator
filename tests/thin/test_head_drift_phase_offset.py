"""The head-drift retry must not re-enter the block cycle at the phase that lost.

A tick takes about as long as a Finney block, so an immediate retry samples the
same phase it just failed at. That made a budget of 8 retries behave like one
attempt made 8 times: measured over 120 consecutive live ticks the outcome was
bimodal (29 ticks won with 0 retries, 26 hit the cap of 8) rather than the
monotonic decay an independent per-attempt race produces, and ~17% of ticks were
abandoned having written nothing.

What is under test is the decorrelation property itself. Asserting only that the
delay is "within bounds" would pass for `return 0.0` and for a fixed constant,
which are precisely the two behaviours that caused the bug.
"""

from __future__ import annotations

import scaffold.validator_thin as vt


BLOCK_SECS = 12.0


def test_the_offset_covers_a_whole_block_period():
    """A partial offset still correlates with block arrival.

    If draws only ever landed in, say, the first third of a period, a tick whose
    losing phase sat in the last third could never be moved off it. Full-period
    coverage is the property that makes the next sample independent.
    """
    draws = [vt._head_drift_phase_offset(BLOCK_SECS) for _ in range(2000)]

    assert min(draws) < BLOCK_SECS * 0.05
    assert max(draws) > BLOCK_SECS * 0.95


def test_the_offset_stays_inside_one_block():
    """Bounded above, so a retry cannot silently cost more than the race it
    is trying to win. Eight retries must stay small against an epoch."""
    draws = [vt._head_drift_phase_offset(BLOCK_SECS) for _ in range(2000)]

    assert all(0.0 <= d <= BLOCK_SECS for d in draws)
    assert vt.SN39_PRE_SIGN_HEAD_DRIFT_RETRIES * BLOCK_SECS < 120.0


def test_consecutive_offsets_differ():
    """The regression that would restore the bug.

    A constant delay, including zero, lands on the same phase every time. This
    fails for `return 0.0` and for any fixed value, which is the point.
    """
    draws = [vt._head_drift_phase_offset(BLOCK_SECS) for _ in range(50)]

    assert len(set(draws)) > 40


def test_a_nonpositive_width_offsets_nothing():
    """Guards the arithmetic rather than the timing: a misconfigured or zero
    width must degrade to 'no offset', never to an exception inside the retry
    path, because raising there would convert a timing loss into a dead tick."""
    assert vt._head_drift_phase_offset(0.0) == 0.0
    assert vt._head_drift_phase_offset(-1.0) == 0.0


def test_the_rearm_delay_alone_lands_on_the_same_phase():
    """Why the re-arm needed the offset too, not only the inner retry.

    The re-arm documents itself as starting the next attempt at "an
    independently drawn offset into a block", but its base delay is a whole
    number of block times, and sleeping an exact multiple of the period returns
    to the same phase just as reliably as sleeping nothing.
    """
    assert vt.SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS % BLOCK_SECS == 0
