"""Signed delivery feed (AB#319): the validator consumes the control plane's room-hour receipts."""

from __future__ import annotations

import base64
import json
from fractions import Fraction
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral_thin.independent_runtime import delivery_receipts as delivery
from cathedral_thin.independent_runtime.escape_receipts import (
    CONTEST_SIGNER_SET_SCHEMA,
    EscapeReceiptError,
    canonical_bytes,
    parse_contest_signers,
    verify_escape_receipt,
)

GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures" / "delivery_feed_golden.json").read_text()
)
KEY = Ed25519PrivateKey.from_private_bytes(b"\x19" * 32)
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(b"\x20" * 32)
H0 = 1_762_992_000
NOW = H0 + 9000
ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
BOB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
ATTEST = "a" * 64


def pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def signer_set(*rows):
    keys = list(rows) or [
        {"id": "contest-2026-11b", "not_before": 0, "pubkey_b64": pub_b64(KEY)}
    ]
    return parse_contest_signers({"schema": CONTEST_SIGNER_SET_SCHEMA, "keys": keys})


SIGNERS = signer_set()


def make(
    *,
    hotkey=ALICE,
    start=H0,
    rooms=(("miner-x.r1", 1800),),
    key=KEY,
    key_id="contest-2026-11b",
    attestation=ATTEST,
    **overrides,
):
    body = {
        "schema": delivery.RECEIPT_SCHEMA,
        "window_id": f"delivery-{start}",
        "window_start": start,
        "window_end": start + 3600,
        "miner_hotkey": hotkey,
        "room_seconds": sum(s for _, s in rooms),
        "rooms": [
            {"room_id": rid, "seconds": s, "attestation_sha256": attestation}
            for rid, s in rooms
        ],
    }
    body.update(overrides)
    receipt = dict(body)
    receipt["sig"] = base64.b64encode(key.sign(canonical_bytes(body))).decode()
    receipt["key_id"] = key_id
    receipt["signer"] = "control_plane"
    return receipt


def score(receipts, **kwargs):
    kwargs.setdefault("now", NOW)
    kwargs.setdefault("signers", SIGNERS)
    return delivery.score_delivered_hours(receipts, **kwargs)


# ---------------------------------------------------------------- the producer's own bytes


def test_golden_feed_signed_by_the_control_plane_verifies_and_scores():
    assert GOLDEN["signer_pubkey_b64"] == pub_b64(KEY)
    receipts = GOLDEN["feed"]["receipts"]
    assert len(receipts) == 3
    result = score(receipts, now=GOLDEN["now"])
    assert result.refused == {}
    assert len(result.accepted_digests) == 3
    # r1: 3000 s in hour 0 and 600 s in hour 1 for one miner; r2: 1800 s for the other.
    assert dict(result.hours_by_hotkey) == {
        ALICE: Fraction(3600, 3600),
        BOB: Fraction(1800, 3600),
    }


def test_golden_feed_through_the_feed_callable(tmp_path):
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(GOLDEN["feed"]))
    feed = delivery.delivered_hours_feed(
        str(path), signers=SIGNERS, clock=lambda: GOLDEN["now"]
    )
    assert dict(feed()) == {ALICE: Fraction(1), BOB: Fraction(1, 2)}


def test_golden_feed_is_refused_under_the_pinned_production_set():
    result = delivery.score_delivered_hours(
        GOLDEN["feed"]["receipts"], now=GOLDEN["now"]
    )
    assert result.hours_by_hotkey == {}
    assert result.refused == {"invalid": 3}


def test_an_escape_verifier_never_accepts_a_delivery_receipt():
    with pytest.raises(EscapeReceiptError):
        verify_escape_receipt(GOLDEN["feed"]["receipts"][0], signers=SIGNERS)


# ---------------------------------------------------------------- one receipt


def test_a_valid_receipt_verifies():
    item = delivery.verify_delivery_receipt(make(), signers=SIGNERS)
    assert (item.hotkey, item.window_start, item.rooms, item.key_id) == (
        ALICE,
        H0,
        (("miner-x.r1", 1800),),
        "contest-2026-11b",
    )


def _tampered_seconds():
    receipt = make()
    receipt["rooms"][0]["seconds"] = 3600
    receipt["room_seconds"] = 3600
    return receipt


@pytest.mark.parametrize(
    "receipt",
    [
        make(key=OTHER_KEY),
        make(key_id="unknown-key"),
        _tampered_seconds(),
        make(room_seconds=1),
        make(rooms=()),
        make(rooms=(("miner-x.r1", 0),)),
        make(rooms=(("miner-x.r1", 3601),)),
        make(rooms=(("miner-x.r1", 100), ("miner-x.r1", 100))),
        make(start=H0 + 1),
        make(window_end=H0 + 7200),
        make(window_id="delivery-0"),
        make(miner_hotkey=""),
        make(schema="escape_stage_c_receipt_v0"),
        make(extra="field"),
        {**make(), "signer": "hotel"},
        {**make(), "sig": "not base64!"},
        "not an object",
    ],
)
def test_malformed_or_unsigned_receipts_are_refused(receipt):
    with pytest.raises(EscapeReceiptError):
        delivery.verify_delivery_receipt(receipt, signers=SIGNERS)


@pytest.mark.parametrize("attestation", ["", "A" * 64, "a" * 63, None])
def test_a_room_without_attestation_is_refused(attestation):
    result = score([make(attestation=attestation)])
    assert result.hours_by_hotkey == {}
    assert result.refused == {"unattested_room": 1}


def test_a_revoked_key_or_one_not_yet_valid_at_the_hours_end_is_refused():
    revoked = signer_set(
        {
            "id": "contest-2026-11b",
            "not_before": 0,
            "pubkey_b64": pub_b64(KEY),
            "revoked": True,
        }
    )
    later = signer_set(
        {"id": "contest-2026-11b", "not_before": H0 + 3601, "pubkey_b64": pub_b64(KEY)}
    )
    covering = signer_set(
        {"id": "contest-2026-11b", "not_before": H0 + 3600, "pubkey_b64": pub_b64(KEY)}
    )
    for signers in (revoked, later):
        with pytest.raises(EscapeReceiptError):
            delivery.verify_delivery_receipt(make(), signers=signers)
    assert delivery.verify_delivery_receipt(make(), signers=covering).hotkey == ALICE


# ---------------------------------------------------------------- a round


def test_hours_sum_per_hotkey_across_windows_and_rooms():
    result = score(
        [
            make(rooms=(("miner-x.r1", 3600), ("miner-x.r2", 900))),
            make(start=H0 + 3600, rooms=(("miner-x.r1", 1800),)),
            make(hotkey=BOB, rooms=(("miner-y.r1", 360),)),
        ]
    )
    assert dict(result.hours_by_hotkey) == {
        ALICE: Fraction(6300, 3600),
        BOB: Fraction(1, 10),
    }
    assert result.refused == {}
    evidence = result.evidence()
    assert evidence["hours_by_hotkey"] == {ALICE: "7/4", BOB: "1/10"}
    assert evidence["signer_set_sha256"] == SIGNERS.source_sha256


def test_replay_duplicate_window_and_window_limits():
    one = make()
    result = score(
        [
            one,
            dict(one),  # replay of the same signed body
            make(rooms=(("miner-x.r9", 60),)),  # a second receipt for (hour, hotkey)
            make(start=H0 + 4 * 3600),  # ends after now plus skew
            make(start=H0 - 30 * 3600),  # older than the 24 h lookback
        ]
    )
    assert result.refused == {
        "replay": 1,
        "duplicate_window": 1,
        "future": 1,
        "expired": 1,
    }
    # The first by digest wins the hour.
    assert dict(result.hours_by_hotkey) in (
        {ALICE: Fraction(1800, 3600)},
        {ALICE: Fraction(60, 3600)},
    )


def test_a_room_counts_once_per_hour_across_hotkeys():
    result = score(
        [
            make(rooms=(("miner-x.r1", 1800),)),
            make(hotkey=BOB, rooms=(("miner-x.r1", 1800), ("miner-y.r1", 60))),
        ]
    )
    assert result.refused == {"duplicate_room": 1}
    assert sum(result.hours_by_hotkey.values()) == Fraction(1860, 3600)


def test_bad_entries_do_not_abort_the_round():
    result = score(
        [
            make(),
            None,
            7,
            {"schema": delivery.RECEIPT_SCHEMA},
            make(key=OTHER_KEY, hotkey=BOB),
        ]
    )
    assert dict(result.hours_by_hotkey) == {ALICE: Fraction(1, 2)}
    assert result.refused == {"invalid": 4}


def test_lookback_bounds():
    with pytest.raises(EscapeReceiptError):
        score([], lookback_seconds=0)
    with pytest.raises(EscapeReceiptError):
        score([], lookback_seconds=delivery.MAX_LOOKBACK_SECONDS + 1)
    assert score(
        [make(start=H0 - 30 * 3600)], lookback_seconds=7 * 24 * 3600
    ).hours_by_hotkey == {ALICE: Fraction(1, 2)}


def test_feed_errors_raise_for_the_fail_open_caller(tmp_path):
    missing = delivery.delivered_hours_feed(
        str(tmp_path / "absent.json"), signers=SIGNERS
    )
    with pytest.raises(EscapeReceiptError):
        missing()
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")
    with pytest.raises(EscapeReceiptError):
        delivery.delivered_hours_feed(str(garbage), signers=SIGNERS)()
    https = delivery.delivered_hours_feed(
        "https://feed.test/v1/miners/delivery/published",
        signers=SIGNERS,
        fetch=lambda url: json.dumps({"receipts": [make()]}).encode(),
        clock=lambda: NOW,
    )
    assert dict(https()) == {ALICE: Fraction(1, 2)}
