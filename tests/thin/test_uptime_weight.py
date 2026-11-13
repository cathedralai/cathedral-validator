"""The uptime rule for compute weight (AB#327).

Weight times the uptime factor. Below 95 percent in a window the factor is
zero. Three such windows put the miner on probation (factor zero) until they
age out of the seven-window lookback.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_direct_validator as base
from cathedral_thin.independent.constants import W
from cathedral_thin.independent_runtime import approved_miners
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime.availability import AvailabilityRound
from cathedral_thin.independent_runtime.direct_contract import (
    DirectValidatorError,
    gated_split_vector,
)
from cathedral_thin.independent_runtime.direct_validator import (
    apply_uptime_rule,
    build_direct_plan,
)
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.telemetry import TelemetrySpool
from cathedral_thin.independent_runtime.uptime_weight import (
    MIN_ROUNDS_PER_WINDOW,
    PROBATION_LOOKBACK,
    SETTLE,
    UPTIME_RULE,
    settled_windows,
    uptime_factors,
)

ONE = base.MINER_ONE
TWO = base.MINER_TWO
OTHER = "5AlwaysUp"
# 13 Nov 2026 03:00 UTC: settled, so the latest judged window is 12 Nov.
NOW = datetime(2026, 11, 13, 3, 0, tzinfo=UTC)
DAY = timedelta(days=1)
LANE = 6553
BURN_UID = base.BURN_UID


def day(
    start: datetime,
    *,
    rounds: int = 100,
    down: int = 0,
    who: str = ONE,
    late_start: bool = False,
):
    """``rounds`` rounds spread over the UTC day at ``start``; ``who`` misses
    the last ``down`` of them (the first ``down`` with ``late_start``). OTHER
    is always up, so no round is empty."""

    step = DAY / rounds
    missed = range(down) if late_start else range(rounds - down, rounds)
    return [
        AvailabilityRound(
            observed_at=start + index * step,
            verified_hotkeys=frozenset({OTHER} if index in missed else {OTHER, who}),
        )
        for index in range(rounds)
    ]


def factor(rounds, hotkey: str = ONE, now: datetime = NOW):
    return uptime_factors(rounds, hotkeys=[hotkey], now=now)[hotkey]


YESTERDAY = datetime(2026, 11, 12, tzinfo=UTC)


# The window rule ----------------------------------------------------------


def test_exactly_95_percent_keeps_95_percent_of_the_weight() -> None:
    result = factor(day(YESTERDAY, rounds=100, down=5))
    assert result.factor_bps == 9500
    assert result.failing_windows == 0
    assert result.probation is False


def test_just_below_95_percent_is_zero_for_the_window() -> None:
    # 1999 of 2104 rounds is 9500.95... -> 9500 bps; one more miss -> 9496.
    assert factor(day(YESTERDAY, rounds=2104, down=105)).factor_bps == 9500
    result = factor(day(YESTERDAY, rounds=2104, down=106))
    assert result.factor_bps == 0
    assert result.last_window.bps == 9496
    assert result.failing_windows == 1
    assert result.probation is False


def test_full_uptime_is_a_full_factor() -> None:
    assert factor(day(YESTERDAY)).factor_bps == 10_000


def test_the_factor_is_the_uptime_not_a_step() -> None:
    assert factor(day(YESTERDAY, rounds=100, down=3)).factor_bps == 9700


def test_a_window_with_too_few_rounds_is_not_judged() -> None:
    thin = day(YESTERDAY, rounds=MIN_ROUNDS_PER_WINDOW - 1, down=5)
    assert factor(thin).factor_bps == 10_000
    assert factor(thin).last_window is None
    judged = day(YESTERDAY, rounds=MIN_ROUNDS_PER_WINDOW, down=5)
    assert factor(judged).factor_bps == 0


def test_validator_downtime_does_not_count_against_the_miner() -> None:
    # The validator finalized only 40 rounds; the miner was up in all of them.
    assert factor(day(YESTERDAY, rounds=40)).factor_bps == 10_000


def test_a_round_where_nobody_verified_is_not_counted() -> None:
    # The verifier was out: every miner spooled with zero machines.
    rounds = day(YESTERDAY, rounds=100)
    outage = [
        AvailabilityRound(
            observed_at=YESTERDAY + timedelta(seconds=30 + index),
            verified_hotkeys=frozenset(),
        )
        for index in range(20)
    ]
    assert factor(rounds + outage).factor_bps == 10_000


def test_rounds_before_a_miner_was_first_up_are_not_counted() -> None:
    # Onboarding: up from round 50 on, so the day is 50 of 50.
    onboarding = day(YESTERDAY, rounds=100, down=50, late_start=True)
    assert factor(onboarding).factor_bps == 10_000
    # Down at the start of the next day is a real miss.
    rounds = day(YESTERDAY - DAY, rounds=100, down=50, late_start=True) + day(
        YESTERDAY, rounds=100, down=50, late_start=True
    )
    assert factor(rounds).factor_bps == 0


def test_a_round_spooled_twice_counts_once() -> None:
    rounds = day(YESTERDAY, rounds=100, down=5)
    up_again = [
        replace(item, verified_hotkeys=frozenset({OTHER, ONE})) for item in rounds
    ]
    # Same observed_at: the miner counts as up in those rounds (union).
    assert factor(rounds + up_again).factor_bps == 10_000
    assert factor(rounds + rounds).factor_bps == 9500


def test_a_miner_never_seen_up_keeps_a_full_factor() -> None:
    assert factor(day(YESTERDAY), hotkey="5Nobody").factor_bps == 10_000


# Window edges and settling --------------------------------------------------


def test_window_edges_are_utc_midnight() -> None:
    rounds = day(YESTERDAY, rounds=100)
    # A miss at 23:59:59 on 12 Nov is in the judged window; at 00:00:00 on 13
    # Nov it is in the current, unjudged one.
    late = AvailabilityRound(
        observed_at=YESTERDAY + DAY - timedelta(seconds=1),
        verified_hotkeys=frozenset({OTHER}),
    )
    midnight = replace(late, observed_at=YESTERDAY + DAY)
    assert factor(rounds + [late] * 5 + [midnight]).factor_bps == 10_000 * 100 // 101
    assert factor(rounds + [midnight]).factor_bps == 10_000


def test_the_previous_day_is_judged_only_after_it_settles() -> None:
    assert settled_windows(YESTERDAY + DAY + SETTLE)[0] == YESTERDAY
    assert settled_windows(YESTERDAY + DAY + SETTLE - timedelta(seconds=1))[0] == (
        YESTERDAY - DAY
    )
    assert len(settled_windows(NOW)) == PROBATION_LOOKBACK
    rounds = day(YESTERDAY, rounds=100, down=10)
    assert factor(rounds, now=YESTERDAY + DAY + timedelta(minutes=30)).factor_bps == (
        10_000
    )
    assert factor(rounds, now=YESTERDAY + DAY + SETTLE).factor_bps == 0


def test_a_naive_clock_is_refused() -> None:
    with pytest.raises(ValueError):
        uptime_factors([], hotkeys=[ONE], now=NOW.replace(tzinfo=None))


# Probation -------------------------------------------------------------------


def failing_days(*offsets: int, good_days: int = PROBATION_LOOKBACK):
    # A full day before the lookback, so the miner was first up before it.
    rounds = day(YESTERDAY - good_days * DAY, rounds=100)
    for back in range(good_days):
        start = YESTERDAY - back * DAY
        rounds += day(start, rounds=100, down=10 if back in offsets else 0)
    return rounds


def test_two_failing_windows_are_not_probation() -> None:
    # Failing 5 and 6 days ago, full yesterday.
    result = factor(failing_days(5, 6))
    assert result.failing_windows == 2
    assert result.probation is False
    assert result.factor_bps == 10_000


def test_three_failing_windows_are_probation() -> None:
    result = factor(failing_days(2, 5, 6))
    assert result.failing_windows == 3
    assert result.probation is True
    # Yesterday was full, probation still pays zero.
    assert result.last_window.bps == 10_000
    assert result.factor_bps == 0


def test_probation_ends_when_a_failing_window_ages_out() -> None:
    rounds = failing_days(2, 5, 6)
    assert factor(rounds).probation is True
    # One day later the window six days back is seven back: out of the lookback.
    later = rounds + day(YESTERDAY + DAY, rounds=100)
    result = factor(later, now=NOW + DAY)
    assert result.failing_windows == 2
    assert result.probation is False
    assert result.factor_bps == 10_000


def test_a_failing_window_older_than_the_lookback_is_ignored() -> None:
    old = day(YESTERDAY - PROBATION_LOOKBACK * DAY, rounds=100, down=50)
    result = factor(old + failing_days(0, 1))
    assert result.failing_windows == 2
    assert result.probation is False


# The vector -----------------------------------------------------------------


def split(uptime=None):
    hotkeys = {19: ONE, 20: TWO}
    uids, weights = gated_split_vector(
        ((19, 1), (20, 1)),
        hotkeys,
        approved_hotkeys=frozenset({ONE, TWO}),
        escape_units=(),
        escape_uid_hotkeys={},
        burn_uid=BURN_UID,
        uptime_bps=uptime,
    )
    assert sum(weights) == W
    return dict(zip(uids, weights, strict=True))


def test_the_cut_goes_to_the_burn_not_to_other_miners() -> None:
    full = split()
    assert full == {BURN_UID: W - LANE, 19: 3277, 20: 3276}
    cut = split({19: 9700})
    assert cut[20] == full[20]
    assert cut[19] == 3277 * 9700 // 10_000
    assert cut[BURN_UID] == W - cut[19] - cut[20]


def test_a_zero_factor_drops_the_miner_from_the_vector() -> None:
    assert split({19: 0}) == {BURN_UID: W - 3276, 20: 3276}


@pytest.mark.parametrize("bad", [10_000, -1, True, "9500"])
def test_an_invalid_factor_is_refused(bad) -> None:
    with pytest.raises(DirectValidatorError):
        split({19: bad})


# The plan, the writer and the cycle ----------------------------------------


@pytest.fixture(autouse=True)
def approve(monkeypatch):
    monkeypatch.setattr(
        approved_miners, "APPROVED_COMPUTE_HOTKEYS", frozenset({ONE, TWO})
    )


def plan():
    miners = (base.MINER_ONE_AXON, base.MINER_TWO_AXON)
    return build_direct_plan(
        base.snapshot(miners=miners),
        base.round_result(
            base.machine_row("1"),
            base.machine_row("2", uid=20, hotkey=TWO),
            miners=miners,
        ),
    )


def events(rounds):
    """Spooled telemetry events, reduced to what the rule reads."""

    return [
        {
            "observed_at": item.observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "miners": [
                {"hotkey": hotkey, "distinct_verified_compute": 1}
                for hotkey in sorted(item.verified_hotkeys)
            ],
        }
        for item in rounds
    ]


def test_full_uptime_leaves_the_plan_byte_identical() -> None:
    planned = plan()
    history = events(day(YESTERDAY) + day(YESTERDAY, who=TWO))
    scaled, summary = apply_uptime_rule(planned, lambda: history, now=NOW)
    assert scaled is planned
    assert summary["status"] == "FULL"
    assert "uptime" not in scaled.identity()


def test_low_uptime_scales_the_plan_and_binds_it() -> None:
    planned = plan()
    history = events(day(YESTERDAY, rounds=100, down=3))
    scaled, summary = apply_uptime_rule(planned, lambda: history, now=NOW)
    assert summary["status"] == "APPLIED"
    assert summary["hotkeys"][ONE]["factor_bps"] == 9700
    assert summary["hotkeys"][TWO]["factor_bps"] == 10_000
    assert scaled.uptime_bps_by_uid == ((19, 9700),)
    assert scaled.identity()["uptime"] == {
        "rule": UPTIME_RULE,
        "bps_by_uid": [[19, 9700]],
    }
    assert scaled.evidence_digest != planned.evidence_digest
    weights = dict(zip(scaled.wire_uids, scaled.wire_weights, strict=True))
    assert weights[19] == 3277 * 9700 // 10_000
    assert weights[20] == 3276
    assert sum(scaled.wire_weights) == W


def test_probation_zeroes_the_miner_in_the_plan() -> None:
    history = events(failing_days(1, 2, 3))
    scaled, _summary = apply_uptime_rule(plan(), lambda: history, now=NOW)
    assert scaled.uptime_bps_by_uid == ((19, 0),)
    assert 19 not in scaled.wire_uids


def test_an_unlisted_miner_is_not_judged(monkeypatch) -> None:
    planned = plan()
    history = events(day(YESTERDAY, rounds=100, down=50, who=TWO))
    monkeypatch.setattr(approved_miners, "APPROVED_COMPUTE_HOTKEYS", frozenset({ONE}))
    scaled, summary = apply_uptime_rule(planned, lambda: history, now=NOW)
    assert set(summary["hotkeys"]) == {ONE}
    assert scaled is planned


def test_no_spool_or_a_broken_spool_fails_open() -> None:
    planned = plan()
    unchanged, summary = apply_uptime_rule(planned, None, now=NOW)
    assert unchanged is planned
    assert summary["status"] == "NO_HISTORY"

    def broken():
        raise OSError("disk")

    unchanged, summary = apply_uptime_rule(planned, broken, now=NOW)
    assert unchanged is planned
    assert summary == {"rule": UPTIME_RULE, "status": "UNAVAILABLE", "error": "OSError"}


def _scaled():
    history = events(day(YESTERDAY, rounds=100, down=3))
    scaled, _summary = apply_uptime_rule(plan(), lambda: history, now=NOW)
    return scaled


def test_the_writer_signs_an_uptime_scaled_plan(tmp_path: Path, monkeypatch) -> None:
    scaled = _scaled()
    instance, _subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=scaled)

    receipt = base.submit_before_deadline(instance, scaled)

    assert receipt.status == STATUS_CONFIRMED
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["identity"]["uptime"] == {
        "rule": UPTIME_RULE,
        "bps_by_uid": [[19, 9700]],
    }


@pytest.mark.parametrize(
    "tamper",
    [
        {"uptime_rule": "other"},
        {"uptime_bps_by_uid": ((19, 10_000),)},
        {"uptime_bps_by_uid": ((19, 9700), (19, 9700))},
        {"uptime_bps_by_uid": ((7, 9700),)},
        {"uptime_bps_by_uid": (), "uptime_rule": UPTIME_RULE},
    ],
)
def test_the_writer_refuses_inconsistent_uptime_rows(
    tmp_path: Path, monkeypatch, tamper
) -> None:
    tampered = replace(_scaled(), **tamper)
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=tampered)
    with pytest.raises(DirectValidatorError):
        base.submit_before_deadline(instance, tampered)
    assert subtensor.substrate.sign_calls == 0
    assert not instance.state_path.exists()


def test_the_cycle_applies_the_rule_from_the_spool(tmp_path: Path, monkeypatch) -> None:
    miners = (base.MINER_ONE_AXON, base.MINER_TWO_AXON)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: base.snapshot(miners=miners),
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: base.round_result(
            base.machine_row("1"),
            base.machine_row("2", uid=20, hotkey=TWO),
            miners=miners,
        ),
    )
    # The cycle reads the wall clock; pin the day so yesterday has settled.
    real_datetime = runtime.datetime

    class Clock(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(runtime, "datetime", Clock)
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    history = events(day(YESTERDAY, rounds=100, down=10))
    monkeypatch.setattr(spool, "history", lambda: history)
    submitted = []
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED, as_document=lambda: {"status": STATUS_CONFIRMED}
    )

    def submit(value, **_kwargs):
        submitted.append(value)
        return receipt

    result = runtime.run_direct_cycle(
        subtensor=object(),
        keypair=base.FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(recover=lambda: None, submit=submit),
        telemetry_sink=spool,
        report_recovery=base.no_expired_recovery,
    )

    assert result["uptime"]["status"] == "APPLIED"
    assert result["uptime"]["hotkeys"][ONE]["factor_bps"] == 0
    assert submitted[0].uptime_bps_by_uid == ((19, 0),)
    assert 19 not in result["wire_uids"]
    assert result["wire_weights"][result["wire_uids"].index(20)] == 3276
