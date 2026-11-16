"""AB#326: seven-day availability per hotkey, from finalized spooled rounds."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import NETUID
from cathedral_thin.independent_runtime.availability import (
    AVAILABILITY_WINDOW,
    AvailabilityRound,
    HotkeyAvailability,
    rolling_availability,
)
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    DirectSubmissionReceipt,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.telemetry import (
    PendingTelemetryStore,
    TelemetryError,
    TelemetrySpool,
    _expected_event_id,
    _sign_telemetry_event,
    build_telemetry_candidate,
    candidate_with_availability,
    latest_telemetry_event,
    validate_public_telemetry_event,
)

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
A = "hotkey-a"
B = "hotkey-b"


def _round(at: datetime, *verified: str) -> AvailabilityRound:
    return AvailabilityRound(observed_at=at, verified_hotkeys=frozenset(verified))


# Window math -----------------------------------------------------------------


def test_window_is_seven_days() -> None:
    assert AVAILABILITY_WINDOW == timedelta(days=7)


def test_window_excludes_its_start_and_includes_now() -> None:
    rounds = [
        _round(NOW - timedelta(days=7), A),  # exactly at the start: out
        _round(NOW - timedelta(days=7) + timedelta(seconds=1)),  # in, A not verified
        _round(NOW, A),  # now: in
    ]
    assert rolling_availability(rounds, hotkeys=[A], now=NOW) == {
        A: HotkeyAvailability(verified_rounds=1, rounds=2)
    }


def test_rounds_after_now_are_ignored() -> None:
    rounds = [_round(NOW, A), _round(NOW + timedelta(seconds=1), A)]
    assert rolling_availability(rounds, hotkeys=[A], now=NOW)[A] == (
        HotkeyAvailability(verified_rounds=1, rounds=1)
    )


def test_denominator_is_every_round_and_absence_is_not_verified() -> None:
    hour = timedelta(hours=1)
    rounds = [
        _round(NOW - 3 * hour, A),
        _round(NOW - 2 * hour, A, B),
        _round(NOW - hour, A),
        _round(NOW, A, B),
    ]
    scores = rolling_availability(rounds, hotkeys=[A, B, "newcomer"], now=NOW)
    assert scores[A].as_document() == {"verified_rounds": 4, "rounds": 4, "bps": 10000}
    assert scores[B].as_document() == {"verified_rounds": 2, "rounds": 4, "bps": 5000}
    assert scores["newcomer"].as_document() == {
        "verified_rounds": 0,
        "rounds": 4,
        "bps": 0,
    }


def test_bps_rounds_down() -> None:
    hour = timedelta(hours=1)
    rounds = [_round(NOW, A), _round(NOW - hour, A), _round(NOW - 2 * hour)]
    assert rolling_availability(rounds, hotkeys=[A], now=NOW)[A].bps == 6666


def test_a_round_spooled_twice_counts_once() -> None:
    rounds = [_round(NOW - timedelta(hours=1)), _round(NOW, A), _round(NOW, A)]
    assert rolling_availability(rounds, hotkeys=[A], now=NOW)[A] == (
        HotkeyAvailability(verified_rounds=1, rounds=2)
    )


def test_no_round_in_the_window_scores_nobody() -> None:
    assert (
        rolling_availability([_round(NOW - timedelta(days=8), A)], hotkeys=[A], now=NOW)
        == {}
    )


def test_a_full_week_of_25_minute_rounds() -> None:
    step = timedelta(minutes=25)
    rounds = [_round(NOW - index * step, A) for index in range(500)]
    # 7 days / 25 min = 403.2, so 404 rounds sit in (now - 7d, now].
    score = rolling_availability(rounds, hotkeys=[A], now=NOW)[A]
    assert (score.verified_rounds, score.rounds, score.bps) == (404, 404, 10000)


def test_naive_clock_is_refused() -> None:
    with pytest.raises(ValueError):
        rolling_availability([], hotkeys=[A], now=NOW.replace(tzinfo=None))


# Spool to signed event ---------------------------------------------------------

VALIDATOR = Keypair.create_from_uri("//Alice")
TDX_MINER = Keypair.create_from_uri("//Bob")
SNP_MINER = Keypair.create_from_uri("//Charlie")


def _plan(verified: bool = True) -> DirectWeightPlan:
    # With no verified machine the whole vector sits on UID 42, the shape of
    # an escape-only round, so the event stays a valid finalized vector.
    return DirectWeightPlan(
        snapshot=FinalizedMetagraphSnapshot(
            block_number=123,
            block_hash="0x" + "a" * 64,
            validator_uid=30,
            validator_hotkey=VALIDATOR.ss58_address,
            miners=(
                ServingAxon(41, TDX_MINER.ss58_address, "1.1.1.1", 8081),
                ServingAxon(42, SNP_MINER.ss58_address, "8.8.8.8", 8081),
            ),
            skipped_axons={},
            netuid=NETUID,
        ),
        qvl_digest="4b6f" + "0" * 60,
        evidence_digest="sha256:" + "b" * 64,
        machine_ids_by_uid=((41, ("machine-41",) if verified else ()), (42, ())),
        raw_scores=((41, 1 if verified else 0), (42, 0)),
        uid_hotkeys=((41, TDX_MINER.ss58_address), (42, SNP_MINER.ss58_address)),
        wire_uids=(41,) if verified else (42,),
        wire_weights=(65535,),
    )


def _row() -> dict[str, object]:
    return {
        "uid": 41,
        "hotkey": TDX_MINER.ss58_address,
        "machine_id": "machine-41",
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_units": 20,
        "counted_units": 20,
        "tee_kind": "tdx",
        "phase_timings_ms": {"binding": 1, "evidence": 1, "qvl": 1, "sat": 1},
    }


def _receipt(block: int) -> DirectSubmissionReceipt:
    return DirectSubmissionReceipt(
        status="CONFIRMED",
        attempt_id="sha256:" + "c" * 64,
        extrinsic_hash="0x" + "d" * 64,
        block_hash="0x" + "e" * 64,
        block_number=block,
        recovered=False,
    )


def _publish(spool: TelemetrySpool, at: datetime, *, verified: bool = True) -> dict:
    plan = _plan(verified)
    candidate = build_telemetry_candidate(
        result_rows=(_row(),) if verified else (), plan=plan, observed_at=at
    )
    pending = PendingTelemetryStore(spool)
    pending.prepare(candidate, plan, _receipt(124))
    event = pending.finalize(keypair=VALIDATOR, expected_receipt=_receipt(124))
    assert event is not None
    return event


def _availability(event: dict) -> dict[str, dict[str, int]]:
    return {miner["hotkey"]: miner["availability_7d"] for miner in event["miners"]}


def test_first_round_counts_itself(tmp_path) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    event = _publish(spool, NOW)
    assert _availability(event) == {
        TDX_MINER.ss58_address: {"verified_rounds": 1, "rounds": 1, "bps": 10000},
        SNP_MINER.ss58_address: {"verified_rounds": 0, "rounds": 1, "bps": 0},
    }
    assert latest_telemetry_event(spool.path) == event


def test_history_in_the_spool_feeds_the_published_value(tmp_path) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    _publish(spool, NOW - timedelta(days=8))  # outside the window
    _publish(spool, NOW - timedelta(days=2), verified=False)
    _publish(spool, NOW - timedelta(days=1))
    event = _publish(spool, NOW)
    assert _availability(event)[TDX_MINER.ss58_address] == {
        "verified_rounds": 2,
        "rounds": 3,
        "bps": 6666,
    }
    assert validate_public_telemetry_event(event) == event


def test_window_ends_at_the_rounds_own_time_not_the_wall_clock(tmp_path) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    _publish(spool, NOW)
    # A round finalized late (commit-reveal or recovery) still counts itself
    # even when the spool already holds a later round.
    event = _publish(spool, NOW - timedelta(hours=1))
    assert _availability(event)[TDX_MINER.ss58_address]["rounds"] == 1


def test_old_spooled_events_without_the_field_still_count(tmp_path) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    legacy = build_telemetry_candidate(
        result_rows=(_row(),), plan=_plan(), observed_at=NOW - timedelta(hours=1)
    )
    legacy["submission"] = {
        "status": "CONFIRMED",
        "block_number": 124,
        "block_hash": "0x" + "e" * 64,
        "recovered": False,
    }
    legacy["event_id"] = _expected_event_id(legacy)
    spool.append(_sign_telemetry_event(legacy, keypair=VALIDATOR, netuid=NETUID))
    event = _publish(spool, NOW)
    assert _availability(event)[TDX_MINER.ss58_address]["rounds"] == 2


def test_a_spooled_duplicate_does_not_change_the_value(tmp_path) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    first = _publish(spool, NOW)
    candidate = build_telemetry_candidate(
        result_rows=(_row(),), plan=_plan(), observed_at=NOW
    )
    again = candidate_with_availability(candidate, spool.history())
    assert [miner["availability_7d"] for miner in again["miners"]] == [
        miner["availability_7d"] for miner in first["miners"]
    ]


def test_unreadable_history_publishes_the_round_without_the_field(
    tmp_path, monkeypatch
) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")

    def broken() -> list:
        raise TelemetryError("telemetry spool cannot be read")

    monkeypatch.setattr(spool, "history", broken)
    event = _publish(spool, NOW)
    assert all("availability_7d" not in miner for miner in event["miners"])


@pytest.mark.parametrize(
    "value",
    [
        {"verified_rounds": 1, "rounds": 0, "bps": 0},
        {"verified_rounds": 2, "rounds": 1, "bps": 20000},
        {"verified_rounds": 1, "rounds": 3, "bps": 3334},
        {"verified_rounds": 0, "rounds": 3, "bps": 0},  # row is verified this round
        {"verified_rounds": 1, "rounds": 1},
        {"verified_rounds": 1, "rounds": 1, "bps": 10000, "extra": 1},
        {"verified_rounds": True, "rounds": 1, "bps": 10000},
        "10000",
    ],
)
def test_validator_refuses_inconsistent_availability(tmp_path, value) -> None:
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    event = deepcopy(_publish(spool, NOW))
    event.pop("signature")
    event["miners"][0]["availability_7d"] = value
    event["event_id"] = _expected_event_id(event)
    # Signing validates first, so the validator cannot sign such an event.
    with pytest.raises(TelemetryError, match="availability"):
        _sign_telemetry_event(event, keypair=VALIDATOR, netuid=NETUID)


def test_cross_repo_availability_fixture_validates() -> None:
    """The same bytes are pinned in cathedral-site's telemetry tests."""

    path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "cathedral_validator_telemetry_v2_availability_python.json"
    )
    fixture = json.loads(path.read_text(encoding="ascii"))
    assert validate_public_telemetry_event(fixture) == fixture
    assert [miner["availability_7d"] for miner in fixture["miners"]] == [
        {"verified_rounds": 2, "rounds": 3, "bps": 6666},
        {"verified_rounds": 0, "rounds": 3, "bps": 0},
    ]
