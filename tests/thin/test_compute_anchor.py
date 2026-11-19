"""Compute anchor (AB#822): pay the compute lane by delivered customer room-seconds.

The release ships in shadow: the delivery feed is read and reported in the
cycle event, and the plan and the vector stay byte-identical. Enforce splits
the compute lane over delivered room-seconds of approved hotkeys with a
verified machine, and burns it when the feed cannot be read.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import replace
from fractions import Fraction
from types import SimpleNamespace

import pytest

import test_delivery_receipts as signed
import test_direct_validator as base
from cathedral_thin.independent.constants import W
from cathedral_thin.independent_runtime import approved_miners, direct_contract
from cathedral_thin.independent_runtime import delivery_receipts as delivery
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import escape_receipts
from cathedral_thin.independent_runtime.direct_contract import (
    COMPUTE_LANE_SHARE,
    DirectValidatorError,
    _lane_weights,
)
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.escape_receipts import (
    EscapeReceiptConfig,
    EscapeReceiptError,
)
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes

LANE = int(COMPUTE_LANE_SHARE * W)
ONE = base.MINER_ONE_AXON
TWO = base.MINER_TWO_AXON
# A cycle clock 20 minutes past an hour: the hour that just closed is settled
# for the anchor (15 minutes or more), so it ends the lookback.
UNTIL = 1_800_000_000 // 3600 * 3600
SINCE = UNTIL - 24 * 3600
CLOCK = float(UNTIL + 20 * 60)
FEED_URL = "https://api.example/v1/miners/delivery/published"


@pytest.fixture(autouse=True)
def delivery_signer(monkeypatch):
    """Stand the test key in for the pinned contest signer set."""

    monkeypatch.setattr(delivery, "PINNED_CONTEST_SIGNERS", signed.SIGNERS)


@pytest.fixture
def mode(monkeypatch):
    def set_mode(value: str) -> None:
        monkeypatch.setattr(direct_contract, "COMPUTE_ANCHOR_MODE", value)

    return set_mode


def approve(monkeypatch, *hotkeys: str) -> None:
    monkeypatch.setattr(approved_miners, "APPROVED_COMPUTE_HOTKEYS", frozenset(hotkeys))


def receipt(hotkey: str, seconds: int, *, start: int = UNTIL - 3600, room: str = "r"):
    return signed.make(
        hotkey=hotkey, start=start, rooms=((f"{room}-{hotkey}-{start}", seconds),)
    )


def feed_bytes(*receipts: object) -> bytes:
    return json.dumps({"receipts": list(receipts)}).encode()


def reader(*receipts: object):
    """A delivery read that serves ``receipts`` through the real scorer.

    It reads at CLOCK whatever the caller's clock, so a cycle (which reads
    the wall clock) scores the same fixed hours.
    """

    body = feed_bytes(*receipts)

    def read(source: str, *, clock: float, timeout: float):
        return delivery.read_anchor_delivery(
            FEED_URL, clock=CLOCK, timeout=timeout, fetch=lambda _url: body
        )

    return read


def failing_read(source: str, *, clock: float, timeout: float):
    raise EscapeReceiptError("escape receipt feed HTTP 404")


def verified_plan(*counts: tuple[base.ServingAxon, int]):
    miners = tuple(miner for miner, _count in counts)
    rows = tuple(
        base.machine_row(str(index), uid=miner.uid, hotkey=miner.hotkey)
        for miner, count in counts
        for index in range(count)
    )
    return runtime.build_direct_plan(
        base.snapshot(miners=miners), base.round_result(*rows, miners=miners)
    )


def anchor(planned, read, **kwargs):
    return runtime.apply_compute_anchor(
        planned, FEED_URL, now=CLOCK, read=read, **kwargs
    )


def identity_bytes(planned) -> bytes:
    return canonical_document_bytes(planned.identity())


def vector(planned) -> dict[int, int]:
    return dict(zip(planned.wire_uids, planned.wire_weights, strict=True))


# The release constants ------------------------------------------------------


def test_the_release_ships_shadow_with_the_polaris_feed_by_default() -> None:
    assert direct_contract.COMPUTE_ANCHOR_MODE == "shadow"
    assert direct_contract.COMPUTE_ANCHOR_MODES == {"off", "shadow", "enforce"}
    assert (
        direct_contract.DELIVERY_FEED_DEFAULT_SOURCE
        == "https://api.polaris.computer/v1/miners/delivery/published"
    )


def test_the_source_is_the_default_unless_the_operator_file_overrides_it(
    tmp_path,
) -> None:
    env = delivery.DELIVERY_RECEIPTS_SOURCE_ENV
    assert (
        delivery.delivery_source_from_environment({})
        == direct_contract.DELIVERY_FEED_DEFAULT_SOURCE
    )
    assert delivery.delivery_source_from_environment({env: "off"}) is None
    assert delivery.delivery_source_from_environment({env: ""}) is None
    assert delivery.delivery_source_from_environment({env: "  "}) is None
    assert delivery.delivery_source_from_environment({env: FEED_URL}) == FEED_URL
    path = str(tmp_path / "feed.json")
    assert delivery.delivery_source_from_environment({env: path}) == path
    with pytest.raises(EscapeReceiptError):
        delivery.delivery_source_from_environment({env: "http://plain.example/x"})


# The read -------------------------------------------------------------------


def test_since_and_until_are_sent_and_the_lookback_is_24_settled_hours() -> None:
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        return feed_bytes()

    result = delivery.read_anchor_delivery(
        FEED_URL, clock=CLOCK, timeout=5.0, fetch=fetch
    )
    [url] = seen
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert query["since"] == str(SINCE)
    assert query["until"] == str(UNTIL)
    assert (result.since, result.until) == (SINCE, UNTIL)
    assert result.body_bytes == len(feed_bytes())
    # 14 minutes after an hour closes it is not yet settled for the anchor.
    assert delivery.anchor_lookback(UNTIL + 14 * 60) == (SINCE - 3600, UNTIL - 3600)
    assert delivery.anchor_lookback(UNTIL + 15 * 60) == (SINCE, UNTIL)


def test_the_escape_read_still_sends_only_its_own_since() -> None:
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        return feed_bytes()

    escape_receipts.load_receipt_feed(
        FEED_URL, fetch=fetch, window_seconds=3600, now=CLOCK
    )
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(seen[0]).query))
    assert set(query) == {"limit", "since"}


def test_the_oldest_hour_is_counted_and_nothing_outside_the_24_hours() -> None:
    receipts = (
        receipt(base.MINER_ONE, 100, start=SINCE),  # oldest hour of the range
        receipt(base.MINER_ONE, 200, start=UNTIL - 3600),  # newest closed hour
        receipt(base.MINER_ONE, 400, start=SINCE - 3600),  # one hour too old
        receipt(base.MINER_ONE, 800, start=UNTIL),  # not yet closed
    )
    result = reader(*receipts)(FEED_URL, clock=CLOCK, timeout=5.0)
    assert result.seconds_by_hotkey == {base.MINER_ONE: 300}
    assert result.delivery_round.refused == {"expired": 1, "future": 1}


def test_room_seconds_are_exact_integers() -> None:
    assert delivery.room_seconds(Fraction(7201, 3600)) == 7201
    with pytest.raises(delivery.DeliveryReceiptError):
        delivery.room_seconds(Fraction(1, 7200))


def test_a_read_at_the_receipt_ceiling_is_a_feed_error(monkeypatch) -> None:
    monkeypatch.setattr(delivery, "MAX_FEED_RECEIPTS", 1)
    with pytest.raises(delivery.DeliveryReceiptError, match="ceiling"):
        reader(receipt(base.MINER_ONE, 10))(FEED_URL, clock=CLOCK, timeout=5.0)


# Shadow ---------------------------------------------------------------------


def test_shadow_leaves_the_plan_byte_identical_and_reports_delivery(mode) -> None:
    mode("shadow")
    planned = verified_plan((ONE, 1), (TWO, 2))
    before = identity_bytes(planned)
    same, summary = anchor(
        planned, reader(receipt(base.MINER_ONE, 1800), receipt(base.MINER_TWO, 60))
    )
    assert same is planned
    assert identity_bytes(same) == before
    assert "compute_anchor" not in same.identity()
    assert summary["mode"] == "shadow"
    assert summary["feed_status"] == "OK"
    assert summary["body_bytes"] > 0
    assert summary["uids"] == {
        str(ONE.uid): {
            "hotkey": base.MINER_ONE,
            "verified_machines": 1,
            "delivered_room_seconds": 1800,
        },
        str(TWO.uid): {
            "hotkey": base.MINER_TWO,
            "verified_machines": 2,
            "delivered_room_seconds": 60,
        },
    }
    assert "compute_lane_burned" not in summary


def test_a_feed_error_in_shadow_changes_nothing(mode) -> None:
    mode("shadow")
    planned = verified_plan((ONE, 1))
    same, summary = anchor(planned, failing_read)
    assert same is planned
    assert summary["feed_status"] == "ERROR"
    assert summary["error"] == "escape receipt feed HTTP 404"
    assert "compute_lane_burned" not in summary


# Enforce --------------------------------------------------------------------


def test_enforce_splits_the_compute_lane_by_room_seconds(mode) -> None:
    mode("enforce")
    planned = verified_plan((ONE, 1), (TWO, 3))
    anchored, summary = anchor(
        planned, reader(receipt(base.MINER_ONE, 3000), receipt(base.MINER_TWO, 1000))
    )
    hotkeys = dict(planned.uid_hotkeys)
    expected = _lane_weights(((ONE.uid, 3000), (TWO.uid, 1000)), LANE, hotkeys)
    assert {uid: vector(anchored)[uid] for uid in (ONE.uid, TWO.uid)} == expected
    assert expected[ONE.uid] > expected[TWO.uid]  # machines no longer decide
    assert vector(anchored)[base.BURN_UID] == W - LANE
    assert anchored.compute_anchor_units == ((ONE.uid, 3000), (TWO.uid, 1000))
    # Machine counts are still what the plan verified.
    assert anchored.raw_scores == planned.raw_scores
    assert anchored.machine_ids_by_uid == planned.machine_ids_by_uid
    bound = anchored.identity()["compute_anchor"]
    assert bound["mode"] == "enforce"
    assert bound["units_by_uid"] == [[ONE.uid, 3000], [TWO.uid, 1000]]
    assert len(bound["feed"]["accepted_digests"]) == 2
    assert anchored.evidence_digest != planned.evidence_digest
    assert summary["units_by_uid"] == [[ONE.uid, 3000], [TWO.uid, 1000]]


def test_enforce_with_zero_delivery_burns_the_lane(mode) -> None:
    mode("enforce")
    anchored, summary = anchor(verified_plan((ONE, 2)), reader())
    assert vector(anchored) == {base.BURN_UID: W}
    assert summary["feed_status"] == "OK"
    assert "compute_lane_burned" not in summary


def test_a_feed_error_in_enforce_burns_the_lane(mode) -> None:
    mode("enforce")
    planned = verified_plan((ONE, 2))
    anchored, summary = anchor(planned, failing_read)
    assert vector(anchored) == {base.BURN_UID: W}
    assert summary["compute_lane_burned"] == "delivery feed is unavailable"
    assert anchored.identity()["compute_anchor"]["units_by_uid"] == []


def test_a_disabled_feed_in_enforce_burns_the_lane(mode) -> None:
    mode("enforce")
    anchored, summary = runtime.apply_compute_anchor(
        verified_plan((ONE, 2)), None, now=CLOCK, read=failing_read
    )
    assert summary["feed_status"] == "DISABLED"
    assert vector(anchored) == {base.BURN_UID: W}
    assert summary["compute_lane_burned"] == "delivery feed is disabled"


def test_an_unapproved_hotkey_with_delivery_gets_zero(mode, monkeypatch) -> None:
    mode("enforce")
    approve(monkeypatch, base.MINER_ONE)
    planned = verified_plan((ONE, 1), (TWO, 1))
    anchored, _summary = anchor(
        planned, reader(receipt(base.MINER_ONE, 100), receipt(base.MINER_TWO, 3600))
    )
    assert TWO.uid not in vector(anchored)
    assert vector(anchored)[ONE.uid] == LANE
    assert anchored.compute_anchor_units == ((ONE.uid, 100),)


def test_delivery_without_a_verified_machine_gets_zero(mode) -> None:
    mode("enforce")
    planned = verified_plan((ONE, 1), (TWO, 0))
    anchored, summary = anchor(
        planned, reader(receipt(base.MINER_ONE, 100), receipt(base.MINER_TWO, 3600))
    )
    assert TWO.uid not in vector(anchored)
    assert vector(anchored)[ONE.uid] == LANE
    assert summary["uids"][str(TWO.uid)] == {
        "hotkey": base.MINER_TWO,
        "verified_machines": 0,
        "delivered_room_seconds": 3600,
    }


def test_out_of_time_is_a_feed_error_and_the_read_never_starts(mode) -> None:
    mode("enforce")
    called: list[float] = []

    def read(source: str, *, clock: float, timeout: float):
        called.append(timeout)
        return reader()(source, clock=clock, timeout=timeout)

    anchored, summary = anchor(
        verified_plan((ONE, 1)),
        read,
        deadline_monotonic=time.monotonic()
        + escape_receipts.FEED_DEADLINE_SLACK_SECONDS
        - 1,
    )
    assert called == []
    assert summary["error"] == "cycle deadline"
    assert vector(anchored) == {base.BURN_UID: W}


def test_a_shadow_read_is_capped_and_keeps_the_writer_reserve(mode) -> None:
    mode("shadow")
    called: list[float] = []

    def read(source: str, *, clock: float, timeout: float):
        called.append(timeout)
        return reader()(source, clock=clock, timeout=timeout)

    plan = verified_plan((ONE, 1))
    # Plenty of time: the read is capped at the shadow limit.
    anchor(plan, read, deadline_monotonic=time.monotonic() + 600)
    assert called and called[-1] <= runtime.SHADOW_ANCHOR_FEED_TIMEOUT_SECONDS
    # Less than the writer reserve left: the read never starts, weights unchanged.
    called.clear()
    shadowed, summary = anchor(
        plan,
        read,
        deadline_monotonic=time.monotonic()
        + runtime.SHADOW_ANCHOR_WRITER_RESERVE_SECONDS
        - 1,
    )
    assert called == []
    assert summary["error"] == "cycle deadline"
    assert shadowed is plan


# The writer -----------------------------------------------------------------


def test_the_writer_signs_an_enforce_plan(tmp_path, monkeypatch, mode) -> None:
    mode("enforce")
    anchored, _summary = anchor(
        verified_plan((ONE, 1)), reader(receipt(base.MINER_ONE, 900))
    )
    instance, subtensor, _ = base.writer(tmp_path, monkeypatch, planned=anchored)
    assert base.submit_before_deadline(instance, anchored).status == STATUS_CONFIRMED
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["identity"]["compute_anchor"]["units_by_uid"] == [
        [ONE.uid, 900]
    ]
    assert subtensor.substrate.submit_calls == 1


@pytest.mark.parametrize(
    "tamper",
    [
        # Units that do not match the signed vector.
        lambda plan: replace(plan, compute_anchor_units=((19, 1), (20, 1))),
        lambda plan: replace(plan, compute_anchor_units=()),
        # A unit for a UID with no verified machine this cycle.
        lambda plan: replace(
            plan,
            raw_scores=((19, 1), (20, 0)),
            compute_anchor_units=((19, 900), (20, 900)),
        ),
        # Not whole positive room-seconds.
        lambda plan: replace(plan, compute_anchor_units=((19, 0),)),
        # An enforce release never signs a machine-count plan.
        lambda plan: replace(plan, compute_anchor_mode="off", compute_anchor_units=()),
    ],
)
def test_the_writer_refuses_mismatched_anchor_units(
    tmp_path, monkeypatch, mode, tamper
) -> None:
    mode("enforce")
    anchored, _summary = anchor(
        verified_plan((ONE, 1), (TWO, 1)),
        reader(receipt(base.MINER_ONE, 900), receipt(base.MINER_TWO, 300)),
    )
    tampered = tamper(anchored)
    instance, subtensor, _ = base.writer(tmp_path, monkeypatch, planned=tampered)
    with pytest.raises(DirectValidatorError):
        base.submit_before_deadline(instance, tampered)
    assert subtensor.substrate.submit_calls == 0


def test_a_shadow_release_refuses_an_enforce_plan(tmp_path, monkeypatch, mode) -> None:
    mode("enforce")
    anchored, _summary = anchor(
        verified_plan((ONE, 1)), reader(receipt(base.MINER_ONE, 900))
    )
    mode("shadow")
    instance, subtensor, _ = base.writer(tmp_path, monkeypatch, planned=anchored)
    with pytest.raises(DirectValidatorError, match="release mode"):
        base.submit_before_deadline(instance, anchored)
    assert subtensor.substrate.submit_calls == 0


# The cycle ------------------------------------------------------------------


def run_cycle(monkeypatch, *, escape_config=None, source=FEED_URL):
    miners = (ONE, TWO)
    rows = (
        base.machine_row("1", uid=ONE.uid, hotkey=ONE.hotkey),
        base.machine_row("2", uid=TWO.uid, hotkey=TWO.hotkey),
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: base.round_result(*rows, miners=miners),
    )
    submitted: list = []
    receipt_doc = SimpleNamespace(
        status=STATUS_CONFIRMED, as_document=lambda: {"status": STATUS_CONFIRMED}
    )
    writer_object = SimpleNamespace(
        recover=lambda: None,
        submit=lambda plan, **_kwargs: submitted.append(plan) or receipt_doc,
    )
    event = runtime.run_direct_cycle(
        subtensor=base.SnapshotSubtensor(base.Metagraph(miners=miners)),
        keypair=base.FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=base.qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=writer_object,
        report_recovery=base.no_expired_recovery,
        escape_config=escape_config,
        compute_anchor_source=source,
    )
    [plan] = submitted
    return event, plan


def test_a_shadow_cycle_signs_exactly_what_an_off_cycle_signs(
    monkeypatch, mode
) -> None:
    monkeypatch.setattr(
        runtime,
        "read_anchor_delivery",
        reader(receipt(base.MINER_ONE, 1200), receipt(base.MINER_TWO, 30)),
    )
    mode("off")
    off_event, off_plan = run_cycle(monkeypatch)
    mode("shadow")
    shadow_event, shadow_plan = run_cycle(monkeypatch)
    assert identity_bytes(shadow_plan) == identity_bytes(off_plan)
    assert shadow_plan == off_plan
    assert "compute_anchor" not in off_event
    assert "compute_lane" not in shadow_event
    reported = shadow_event["compute_anchor"]
    assert reported["mode"] == "shadow"
    assert reported["feed_status"] == "OK"
    assert reported["uids"][str(ONE.uid)]["delivered_room_seconds"] == 1200
    assert reported["uids"][str(TWO.uid)]["delivered_room_seconds"] == 30
    assert {
        key: shadow_event[key] for key in ("wire_uids", "wire_weights", "raw_scores")
    } == {key: off_event[key] for key in ("wire_uids", "wire_weights", "raw_scores")}


def test_a_feed_error_burns_the_lane_in_an_enforce_cycle_only(
    monkeypatch, mode
) -> None:
    monkeypatch.setattr(runtime, "read_anchor_delivery", failing_read)
    mode("shadow")
    shadow_event, _plan = run_cycle(monkeypatch)
    assert shadow_event["compute_anchor"]["feed_status"] == "ERROR"
    assert "compute_lane" not in shadow_event
    assert base.BURN_UID in shadow_event["wire_uids"]
    assert len(shadow_event["wire_uids"]) == 3
    mode("enforce")
    enforce_event, _plan = run_cycle(monkeypatch)
    assert enforce_event["compute_lane"] == {
        "status": "BURNED_UNPROVEN",
        "reason": "delivery feed is unavailable",
    }
    assert (enforce_event["wire_uids"], enforce_event["wire_weights"]) == (
        [base.BURN_UID],
        [W],
    )


def test_a_slow_delivery_feed_does_not_starve_the_escape_read(
    monkeypatch, mode
) -> None:
    mode("shadow")
    order: list[str] = []

    def escape_load(source, **_kwargs):
        order.append("escape")
        return []

    def slow_anchor(source: str, *, clock: float, timeout: float):
        order.append("anchor")
        # The anchor's budget leaves the escape lane's slack for the write.
        assert 0 < timeout <= escape_receipts.FEED_TOTAL_TIMEOUT_SECONDS
        raise EscapeReceiptError("escape receipt feed is unavailable")

    monkeypatch.setattr(runtime, "load_receipt_feed", escape_load)
    monkeypatch.setattr(runtime, "read_anchor_delivery", slow_anchor)
    config = EscapeReceiptConfig(
        source="https://api.example/escape",
        fraction=Fraction(1, 10),
        window_seconds=3600,
    )
    event, _plan = run_cycle(monkeypatch, escape_config=config)
    assert order == ["escape", "anchor"]
    assert event["escape_receipts"]["status"] == "NO_BREAKS"
    assert event["compute_anchor"]["feed_status"] == "ERROR"


def test_a_cycle_without_a_source_reports_disabled_and_reads_nothing(
    monkeypatch, mode
) -> None:
    mode("shadow")
    monkeypatch.setattr(
        runtime,
        "read_anchor_delivery",
        lambda *_a, **_k: pytest.fail("a disabled feed was read"),
    )
    event, _plan = run_cycle(monkeypatch, source=None)
    assert event["compute_anchor"]["feed_status"] == "DISABLED"
