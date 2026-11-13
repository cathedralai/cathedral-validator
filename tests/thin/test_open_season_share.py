"""The open-season share: bounded, default zero, fail open (AB#320)."""

from __future__ import annotations

import random
from fractions import Fraction

import pytest

from cathedral_thin.independent.constants import CANARY_HOTKEY, REFUSE_HOTKEYS, W
from cathedral_thin.independent_runtime import open_season
from cathedral_thin.independent_runtime.open_season import (
    DEFAULT_OPEN_SEASON_FRACTION,
    MAX_OPEN_SEASON_FRACTION,
    STATUS_DISABLED,
    STATUS_FAILED_OPEN,
    STATUS_NO_DELIVERY,
    STATUS_PAID,
    score_open_season,
)

VALIDATOR_UID = 30
REGISTERED = {"hk-a": 1, "hk-b": 2, "hk-c": 3, "hk-validator": VALIDATOR_UID}
CAP = 6553  # floor(W / 10)


def _feed(rows):
    return lambda: dict(rows)


def _forbidden():
    raise AssertionError("the feed must not be read")


def _score(
    hours,
    uptime,
    *,
    fraction=MAX_OPEN_SEASON_FRACTION,
    budget=W,
    registered=REGISTERED,
    excluded=frozenset(),
):
    return score_open_season(
        budget=budget,
        registered=registered,
        validator_uid=VALIDATOR_UID,
        delivered_hours=hours if callable(hours) else _feed(hours),
        uptime=uptime if callable(uptime) else _feed(uptime),
        fraction=fraction,
        excluded_hotkeys=excluded,
    )


def _assert_fleet_keeps_all(share, status, budget=W):
    assert share.status == status
    assert share.fleet_units == budget
    assert share.rows == ()
    assert share.weights_by_uid == ()
    assert share.open_season_units == 0


# Default zero


def test_default_fraction_is_zero_and_reads_no_feed():
    assert DEFAULT_OPEN_SEASON_FRACTION == 0
    share = score_open_season(
        budget=W,
        registered=REGISTERED,
        validator_uid=VALIDATOR_UID,
        delivered_hours=_forbidden,
        uptime=_forbidden,
    )
    _assert_fleet_keeps_all(share, STATUS_DISABLED)
    assert share.fraction == 0


@pytest.mark.parametrize("zero", [0, Fraction(0)])
def test_explicit_zero_is_disabled(zero):
    share = _score(_forbidden, _forbidden, fraction=zero)
    _assert_fleet_keeps_all(share, STATUS_DISABLED)


# Bounds


def test_maximum_is_one_tenth():
    assert MAX_OPEN_SEASON_FRACTION == Fraction(1, 10)


def test_max_fraction_pays_exactly_the_cap():
    share = _score({"hk-a": 5}, {"hk-a": Fraction(1)})
    assert share.status == STATUS_PAID
    assert share.weights_by_uid == ((1, CAP),)
    assert share.fleet_units == W - CAP


@pytest.mark.parametrize(
    "bad",
    [
        Fraction(-1, 100),
        Fraction(1, 10) + Fraction(1, W),
        Fraction(1, 2),
        1,
        0.05,
        True,
        "0.05",
        None,
    ],
)
def test_out_of_range_or_inexact_fraction_fails_open_unclamped(bad):
    share = _score(_forbidden, _forbidden, fraction=bad)
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)
    assert share.fraction == 0


@pytest.mark.parametrize(
    "fraction", [Fraction(1, 100), Fraction(1, 20), Fraction(1, 10)]
)
def test_paid_share_is_floor_of_fraction_times_budget(fraction):
    share = _score({"hk-a": 3, "hk-b": 7}, {"hk-a": 1, "hk-b": 1}, fraction=fraction)
    assert share.open_season_units == int(fraction * W)
    assert share.fleet_units + share.open_season_units == W


@pytest.mark.parametrize("budget", [-1, W + 1, True, 1.0])
def test_invalid_budget_fails_open(budget):
    share = _score(_forbidden, _forbidden, budget=budget)
    assert share.status == STATUS_FAILED_OPEN
    assert share.rows == ()


# Scaling by delivered hours and uptime


def test_split_scales_with_delivered_hours():
    share = _score({"hk-a": 1, "hk-b": 3}, {"hk-a": 1, "hk-b": 1}, budget=40000)
    assert dict(share.weights_by_uid) == {1: 1000, 2: 3000}
    assert share.fleet_units == 36000


def test_split_scales_with_uptime():
    share = _score(
        {"hk-a": 10, "hk-b": 10},
        {"hk-a": Fraction(1, 4), "hk-b": Fraction(3, 4)},
        budget=40000,
    )
    assert dict(share.weights_by_uid) == {1: 1000, 2: 3000}


def test_split_scales_by_hours_times_uptime():
    # a: 6 * 1/2 = 3, b: 2 * 1/2 = 1, c: 4 * 1 = 4
    share = _score(
        {"hk-a": 6, "hk-b": 2, "hk-c": 4},
        {"hk-a": Fraction(1, 2), "hk-b": Fraction(1, 2), "hk-c": 1},
        budget=64000,
    )
    assert dict(share.weights_by_uid) == {1: 2400, 2: 800, 3: 3200}
    rows = {row.hotkey: row for row in share.rows}
    assert rows["hk-a"].units == 3
    assert rows["hk-c"].evidence()["uptime"] == "1"


def test_fractional_hours_are_exact():
    share = _score(
        {"hk-a": Fraction(1, 3), "hk-b": Fraction(2, 3)},
        {"hk-a": 1, "hk-b": 1},
        budget=30000,
    )
    assert dict(share.weights_by_uid) == {1: 1000, 2: 2000}


def test_zero_uptime_earns_nothing():
    share = _score({"hk-a": 5, "hk-b": 5}, {"hk-a": 0, "hk-b": 1})
    assert share.weights_by_uid == ((2, CAP),)


def test_missing_uptime_counts_as_zero():
    share = _score({"hk-a": 5, "hk-b": 5}, {"hk-b": Fraction(1, 2)})
    assert share.weights_by_uid == ((2, CAP),)


def test_uptime_without_hours_is_ignored():
    share = _score({"hk-a": 5}, {"hk-a": 1, "hk-b": 1, "unregistered": 1})
    assert share.weights_by_uid == ((1, CAP),)


def test_tiny_units_floor_to_zero_and_are_dropped():
    share = _score(
        {"hk-a": 1_000_000, "hk-b": 1},
        {"hk-a": 1, "hk-b": 1},
        budget=100,
    )
    # floor(100 / 10) = 10, all to a; b floors to 0 and gets no bonus.
    assert share.weights_by_uid == ((1, 10),)
    assert len(share.rows) == 2
    assert share.fleet_units == 90


# Who can be paid


def test_unregistered_hotkey_is_ignored_and_does_not_dilute():
    with_stranger = _score(
        {"hk-a": 1, "hk-b": 3, "stranger": 1000}, {"hk-a": 1, "hk-b": 1, "stranger": 1}
    )
    without = _score({"hk-a": 1, "hk-b": 3}, {"hk-a": 1, "hk-b": 1})
    assert with_stranger.weights_by_uid == without.weights_by_uid


def test_validator_uid_is_never_paid():
    share = _score({"hk-validator": 9, "hk-a": 1}, {"hk-validator": 1, "hk-a": 1})
    assert share.weights_by_uid == ((1, CAP),)


def test_refused_and_canary_hotkeys_are_never_paid():
    refused = sorted(REFUSE_HOTKEYS)[0]
    registered = {**REGISTERED, refused: 50, CANARY_HOTKEY: 51}
    share = _score(
        {refused: 9, CANARY_HOTKEY: 9, "hk-a": 1},
        {refused: 1, CANARY_HOTKEY: 1, "hk-a": 1},
        registered=registered,
    )
    assert share.weights_by_uid == ((1, CAP),)


def test_excluded_hotkeys_burn_and_fleet_are_never_paid():
    share = _score(
        {"hk-a": 1, "hk-b": 9, "hk-c": 9},
        {"hk-a": 1, "hk-b": 1, "hk-c": 1},
        excluded=frozenset({"hk-b", "hk-c"}),
    )
    assert share.weights_by_uid == ((1, CAP),)


def test_only_ineligible_delivery_leaves_fleet_whole():
    share = _score({"hk-validator": 9, "stranger": 9}, {"hk-validator": 1})
    _assert_fleet_keeps_all(share, STATUS_NO_DELIVERY)


# No delivery


def test_empty_hours_feed_skips_uptime_and_keeps_fleet_whole():
    share = _score({}, _forbidden)
    _assert_fleet_keeps_all(share, STATUS_NO_DELIVERY)


def test_all_zero_hours_keep_fleet_whole():
    share = _score({"hk-a": 0, "hk-b": 0}, {"hk-a": 1, "hk-b": 1})
    _assert_fleet_keeps_all(share, STATUS_NO_DELIVERY)


# Fail open on feed or scoring errors


def _raises(exc):
    def feed():
        raise exc

    return feed


@pytest.mark.parametrize(
    "exc", [RuntimeError("feed down"), TimeoutError(), ValueError("bad json")]
)
def test_hours_feed_error_keeps_fleet_whole(exc):
    share = _score(_raises(exc), {"hk-a": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)
    assert share.fraction == MAX_OPEN_SEASON_FRACTION


@pytest.mark.parametrize("exc", [RuntimeError("score down"), KeyError("x")])
def test_uptime_feed_error_keeps_fleet_whole(exc):
    share = _score({"hk-a": 1}, _raises(exc))
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


class _LazyBroken(dict):
    def items(self):
        yield "hk-a", 1
        raise OSError("stream reset")


def test_error_while_iterating_a_feed_keeps_fleet_whole():
    share = _score(lambda: _LazyBroken(), {"hk-a": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)
    assert share.reason == "OSError"


@pytest.mark.parametrize(
    "hours",
    [
        {"hk-a": 1, "hk-b": -1},
        {"hk-a": 1, "hk-b": 1.5},
        {"hk-a": 1, "hk-b": True},
        {"hk-a": 1, "hk-b": "2"},
        {"hk-a": 1, "hk-b": None},
        {"hk-a": 1, "": 1},
        {"hk-a": 1, 7: 1},
    ],
)
def test_one_malformed_hours_row_fails_whole_share_open(hours):
    share = _score(hours, {"hk-a": 1, "hk-b": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


@pytest.mark.parametrize(
    "uptime",
    [
        {"hk-a": 1, "hk-b": Fraction(11, 10)},
        {"hk-a": 1, "hk-b": -1},
        {"hk-a": 1, "hk-b": 0.9},
        {"hk-a": 1, "hk-b": float("nan")},
        {"hk-a": 1, "hk-b": False},
    ],
)
def test_one_malformed_uptime_row_fails_whole_share_open(uptime):
    share = _score({"hk-a": 1, "hk-b": 1}, uptime)
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


def test_feed_returning_non_mapping_fails_open():
    share = _score(lambda: None, {"hk-a": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


@pytest.mark.parametrize("uid", [-1, W + 1, True, "1"])
def test_invalid_registered_uid_fails_open(uid):
    share = _score({"hk-a": 1}, {"hk-a": 1}, registered={"hk-a": uid})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


def test_two_hotkeys_on_one_uid_fails_open():
    share = _score(
        {"hk-a": 1, "hk-b": 1},
        {"hk-a": 1, "hk-b": 1},
        registered={"hk-a": 4, "hk-b": 4},
    )
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


def test_apportioner_error_fails_open(monkeypatch):
    def broken(*_args, **_kwargs):
        raise RuntimeError("apportion bug")

    monkeypatch.setattr(open_season, "_lane_weights", broken)
    share = _score({"hk-a": 1}, {"hk-a": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


def test_inexact_apportionment_fails_open(monkeypatch):
    monkeypatch.setattr(open_season, "_lane_weights", lambda rows, budget, h: {1: 1})
    share = _score({"hk-a": 1}, {"hk-a": 1})
    _assert_fleet_keeps_all(share, STATUS_FAILED_OPEN)


# Determinism and invariants


def test_input_order_does_not_change_the_split():
    hours = [("hk-a", 1), ("hk-b", 1), ("hk-c", 1)]
    first = _score(dict(hours), {"hk-a": 1, "hk-b": 1, "hk-c": 1})
    second = _score(dict(reversed(hours)), {"hk-c": 1, "hk-b": 1, "hk-a": 1})
    assert first == second
    # 6553 over three equal rows: remainder 1 goes to the first hotkey.
    assert dict(first.weights_by_uid) == {1: 2185, 2: 2184, 3: 2184}


def test_evidence_is_plain_data():
    share = _score({"hk-a": Fraction(3, 2)}, {"hk-a": Fraction(2, 3)})
    assert share.evidence() == {
        "status": STATUS_PAID,
        "fraction": "1/10",
        "budget": W,
        "fleet_units": W - CAP,
        "rows": [
            {
                "hotkey": "hk-a",
                "uid": 1,
                "hours": "3/2",
                "uptime": "2/3",
                "units": "1",
                "weight": CAP,
            }
        ],
        "reason": "",
    }


def test_random_inputs_stay_bounded_and_exact():
    rng = random.Random(320)
    for _ in range(400):
        count = rng.randint(1, 12)
        registered = {f"hk-{i}": i for i in range(count)}
        hours = {
            f"hk-{i}": Fraction(rng.randint(0, 500), rng.randint(1, 60))
            for i in range(count)
        }
        uptime = {
            f"hk-{i}": Fraction(rng.randint(0, 100), 100)
            for i in range(count)
            if rng.random() < 0.9
        }
        fraction = Fraction(rng.randint(0, 10), 100)
        budget = rng.randint(0, W)
        share = _score(
            hours, uptime, fraction=fraction, budget=budget, registered=registered
        )
        assert share.status != STATUS_FAILED_OPEN
        cap = int(fraction * budget)
        assert share.fleet_units + share.open_season_units == budget
        assert share.open_season_units <= cap
        assert share.fleet_units >= budget - budget // 10
        if share.status == STATUS_PAID:
            assert share.open_season_units == cap
            assert all(weight > 0 for _uid, weight in share.weights_by_uid)
        else:
            assert share.fleet_units == budget
