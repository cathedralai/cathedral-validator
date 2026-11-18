"""Planned maintenance is free; an unannounced exit is penalized (AB#328)."""

from __future__ import annotations

import base64

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent_runtime import maintenance as m

NET, NETUID = "test", 584
HOUR = 3600
DRAIN_AT = 1_800_000_000
UNTIL = DRAIN_AT + 4 * HOUR
ROUND = 1500  # 25-minute rounds


@pytest.fixture(scope="module")
def miner() -> Keypair:
    return Keypair.create_from_uri("//Alice")


@pytest.fixture(scope="module")
def other() -> Keypair:
    return Keypair.create_from_uri("//Bob")


def notice(kp: Keypair, **over):
    args = dict(
        network=NET,
        netuid=NETUID,
        hotel_id="m1",
        drain_at=DRAIN_AT,
        until=UNTIL,
        issued_at=DRAIN_AT - 48 * HOUR,
    )
    args.update(over)
    return m.sign_drain_notice(kp, **args)


def record(doc, received_at=DRAIN_AT - 48 * HOUR):
    return {"notice": doc, "received_at": received_at}


def rounds_with_outage(start: int, end: int):
    """Rounds every 25 minutes over two days around the drain; down in [start, end)."""
    t = DRAIN_AT - 48 * ROUND  # aligned so a round lands on drain_at
    out = []
    while t < DRAIN_AT + 24 * HOUR:
        out.append((t, not (start <= t < end)))
        t += ROUND
    return out


def windows(*records):
    return m.maintenance_windows(records, network=NET, netuid=NETUID)


def test_signed_notice_verifies(miner):
    n = m.verify_drain_notice(notice(miner), network=NET, netuid=NETUID)
    assert (n.hotkey, n.hotel_id, n.drain_at, n.until) == (
        miner.ss58_address,
        "m1",
        DRAIN_AT,
        UNTIL,
    )


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d.update(until=d["until"] + 1),
        lambda d: d.update(hotel_id="m2"),
        lambda d: d.update(notice_id="sha256:" + "0" * 64),
        lambda d: d.update(extra=1),
        lambda d: d.pop("issued_at"),
        lambda d: d["signature"].update(algorithm="ed25519"),
        lambda d: d["signature"].update(
            value_base64=base64.b64encode(b"x" * 63).decode()
        ),
    ],
)
def test_tampered_notice_is_refused(miner, tamper):
    doc = notice(miner)
    doc["signature"] = dict(doc["signature"])
    tamper(doc)
    with pytest.raises(m.MaintenanceNoticeError):
        m.verify_drain_notice(doc, network=NET, netuid=NETUID)


def test_notice_signed_by_another_key_is_refused(miner, other):
    doc = notice(other)
    doc["hotkey"] = miner.ss58_address
    doc["notice_id"] = m.notice_id_for(doc)
    with pytest.raises(m.MaintenanceNoticeError, match="does not verify"):
        m.verify_drain_notice(doc, network=NET, netuid=NETUID)


def test_notice_does_not_replay_on_another_netuid(miner):
    with pytest.raises(m.MaintenanceNoticeError, match="another network"):
        m.verify_drain_notice(notice(miner), network=NET, netuid=94)
    with pytest.raises(m.MaintenanceNoticeError, match="another network"):
        m.verify_drain_notice(notice(miner), network="finney", netuid=NETUID)


def test_planned_maintenance_costs_nothing(miner):
    w = windows(record(notice(miner)))
    assert len(w) == 1
    rounds = rounds_with_outage(DRAIN_AT, UNTIL)
    got = m.availability_with_maintenance(miner.ss58_address, "m1", rounds, w)
    assert got.excused_rounds > 0
    assert got.unannounced_down_rounds == 0
    assert got.bps == 10000
    assert (
        m.classify_outage(miner.ss58_address, "m1", DRAIN_AT, w)
        == m.PLANNED_MAINTENANCE
    )


def test_unannounced_exit_is_penalized(miner):
    rounds = rounds_with_outage(DRAIN_AT, UNTIL)
    got = m.availability_with_maintenance(miner.ss58_address, "m1", rounds, ())
    assert got.excused_rounds == 0
    assert got.unannounced_down_rounds == 10  # 4 hours of 25-minute rounds
    assert got.bps < 10000
    assert got.bps == (got.rounds - 10) * 10000 // got.rounds
    assert (
        m.classify_outage(miner.ss58_address, "m1", DRAIN_AT, ()) == m.UNANNOUNCED_EXIT
    )


def test_lead_boundary_is_measured_from_received_at(miner):
    doc = notice(miner)
    exact = windows(record(doc, received_at=DRAIN_AT - m.MIN_DRAIN_NOTICE_SECONDS))
    late = windows(record(doc, received_at=DRAIN_AT - m.MIN_DRAIN_NOTICE_SECONDS + 1))
    assert len(exact) == 1
    assert late == ()


def test_backdated_issued_at_does_not_help(miner):
    # The miner claims it wrote the notice a week ago; the broker got it an hour ago.
    doc = notice(miner, issued_at=DRAIN_AT - 7 * 24 * HOUR)
    assert windows(record(doc, received_at=DRAIN_AT - HOUR)) == ()
    rounds = rounds_with_outage(DRAIN_AT, UNTIL)
    got = m.availability_with_maintenance(
        miner.ss58_address,
        "m1",
        rounds,
        windows(record(doc, received_at=DRAIN_AT - HOUR)),
    )
    assert got.unannounced_down_rounds == 10


def test_far_future_or_overlong_notice_is_not_accepted(miner):
    far = record(
        notice(miner), received_at=DRAIN_AT - m.MAX_DRAIN_NOTICE_LEAD_SECONDS - 1
    )
    long = record(notice(miner, until=DRAIN_AT + m.MAX_MAINTENANCE_WINDOW_SECONDS + 1))
    assert windows(far) == ()
    assert windows(long) == ()
    assert (
        len(
            windows(
                record(notice(miner, until=DRAIN_AT + m.MAX_MAINTENANCE_WINDOW_SECONDS))
            )
        )
        == 1
    )


def test_window_is_half_open_and_downtime_after_until_is_penalized(miner):
    w = windows(record(notice(miner)))
    key = miner.ss58_address
    assert m.classify_outage(key, "m1", DRAIN_AT - 1, w) == m.UNANNOUNCED_EXIT
    assert m.classify_outage(key, "m1", DRAIN_AT, w) == m.PLANNED_MAINTENANCE
    assert m.classify_outage(key, "m1", UNTIL - 1, w) == m.PLANNED_MAINTENANCE
    assert m.classify_outage(key, "m1", UNTIL, w) == m.UNANNOUNCED_EXIT
    # Overstaying by two hours: the extra rounds count as downtime.
    got = m.availability_with_maintenance(
        key, "m1", rounds_with_outage(DRAIN_AT, UNTIL + 2 * HOUR), w
    )
    assert got.excused_rounds == 10
    assert got.unannounced_down_rounds == 5
    assert got.bps < 10000


def test_notice_for_one_hotel_does_not_excuse_another(miner, other):
    w = windows(record(notice(miner)))
    rounds = rounds_with_outage(DRAIN_AT, UNTIL)
    assert (
        m.availability_with_maintenance(
            miner.ss58_address, "m2", rounds, w
        ).unannounced_down_rounds
        == 10
    )
    assert (
        m.availability_with_maintenance(
            other.ss58_address, "m1", rounds, w
        ).unannounced_down_rounds
        == 10
    )


def test_bad_records_give_no_window(miner):
    good = notice(miner)
    assert (
        windows(
            {"notice": good},
            {"received_at": 1},
            record({}),
            record(good, received_at=True),
        )
        == ()
    )


def test_broker_record_shape_round_trips(miner):
    # The broker stores the notice as a Go struct and re-encodes it with its
    # own key order and spacing; the id is recomputed from the canonical body.
    import json

    doc = notice(miner)
    reencoded = json.loads(json.dumps(doc, indent=2, sort_keys=False))
    assert len(windows(record(reencoded))) == 1
