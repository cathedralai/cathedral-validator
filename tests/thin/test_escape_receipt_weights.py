"""Escape contest receipts as an SN94 weight source (default off)."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_direct_validator as base
from cathedral_thin.independent.constants import W
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import escape_receipts
from cathedral_thin.independent_runtime.direct_contract import DirectValidatorError
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.escape_receipts import (
    DEFAULT_REWARD_WINDOW_SECONDS,
    EscapeReceiptConfig,
    EscapeReceiptError,
    authorizing_body,
    canonical_bytes,
    escape_config_from_environment,
    score_escape_receipts,
    verify_escape_receipt,
)

REPO = Path(__file__).resolve().parents[2]
BREAKER = "5Breaker"
BREAKER_UID = 23
NOW = 1_800_000_000.0
TEST_KEY = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)


def receipt(
    *,
    key: Ed25519PrivateKey = TEST_KEY,
    window_id: str = "w-1",
    room_id: str = "room-1",
    hotkey: str | None = BREAKER,
    planted_at: float = NOW - 3600,
    commands: int = 1,
) -> dict[str, object]:
    nonce = hashlib.sha256(window_id.encode()).hexdigest()[:32]
    claim: dict[str, object] = {
        "schema": "escape_practice_claim_v0",
        "target": "host",
        "window_id": window_id,
        "room_id": room_id,
        "commands": [{"attested_room": room_id, "argv": ["id"]}] * commands,
        "proof_token": {"kind": "host_nonce", "window_id": window_id, "nonce": nonce},
    }
    if hotkey is not None:
        claim["breaker_hotkey"] = hotkey
    body = {
        "schema": "escape_stage_c_receipt_v0",
        "window_id": window_id,
        "room_id": room_id,
        "host_nonce": nonce,
        "nonce_origin": "control_plane",
        "planted_at": planted_at,
        "claim": claim,
    }
    signed = dict(body)
    signed["sig"] = base64.b64encode(key.sign(canonical_bytes(body))).decode("ascii")
    signed["signer"] = "control_plane"
    return signed


@pytest.fixture
def test_signer(monkeypatch) -> None:
    """Stand the test key in for the pinned key (we do not hold its seed)."""

    monkeypatch.setattr(escape_receipts, "PINNED_CONTEST_PUBKEY", TEST_KEY.public_key())


def registered_snapshot(**kwargs):
    snap = base.snapshot(**kwargs)
    registered = {base.VALIDATOR: 7, BREAKER: BREAKER_UID}
    registered.update({miner.hotkey: miner.uid for miner in snap.miners})
    return replace(snap, registered_hotkeys=registered)


def machine_plan():
    return base.build_direct_plan(
        registered_snapshot(), base.round_result(base.machine_row("1"))
    )


def config(fraction: str = "1/10", window: int = DEFAULT_REWARD_WINDOW_SECONDS):
    return EscapeReceiptConfig(
        source="/unused", fraction=Fraction(fraction), window_seconds=window
    )


def score(receipts, *, now: float = NOW, window: int = DEFAULT_REWARD_WINDOW_SECONDS):
    return score_escape_receipts(
        receipts,
        registered={BREAKER: BREAKER_UID, base.VALIDATOR: 7},
        validator_uid=7,
        now=now,
        window_seconds=window,
    )


# --- pinned key ------------------------------------------------------------


def test_vendored_key_file_matches_the_pinned_constant_and_sha256() -> None:
    raw = (REPO / "config/escape/contest-signer.ed25519.pub").read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == escape_receipts.PINNED_CONTEST_PUBKEY_FILE_SHA256
    )
    assert (
        raw.decode("ascii").splitlines()[0] == escape_receipts.PINNED_CONTEST_PUBKEY_B64
    )


def test_wrong_key_fails_against_the_pinned_key() -> None:
    forged = receipt(key=Ed25519PrivateKey.from_private_bytes(b"\x09" * 32))
    with pytest.raises(EscapeReceiptError, match="non-pinned key"):
        verify_escape_receipt(forged)
    assert score([forged]).units_by_uid == ()
    assert score([forged]).refused == {"invalid": 1}


def test_tampered_body_fails(test_signer) -> None:
    good = receipt()
    verify_escape_receipt(good)
    tampered = json.loads(json.dumps(good))
    tampered["claim"]["breaker_hotkey"] = "5Thief"
    with pytest.raises(EscapeReceiptError, match="non-pinned key"):
        verify_escape_receipt(tampered)


def test_signature_covers_exactly_the_upstream_authorizing_body(test_signer) -> None:
    good = receipt()
    good["extra_unsigned_field"] = "ignored"
    verified = verify_escape_receipt(good)
    expected = hashlib.sha256(canonical_bytes(authorizing_body(good))).hexdigest()
    assert verified.digest == "sha256:" + expected


def test_receipt_without_breaker_hotkey_is_refused(test_signer) -> None:
    with pytest.raises(EscapeReceiptError, match="breaker hotkey"):
        verify_escape_receipt(receipt(hotkey=None))
    assert score([receipt(hotkey=None)]).refused == {"no_breaker_hotkey": 1}


# --- scoring ---------------------------------------------------------------


def test_replay_is_counted_once(test_signer) -> None:
    one = receipt()
    result = score([one, json.loads(json.dumps(one)), one])
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"replay": 2}


def test_second_claim_for_the_same_room_and_window_is_counted_once(test_signer) -> None:
    result = score([receipt(commands=1), receipt(commands=2)])
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"duplicate_room": 1}


def test_distinct_rooms_each_count(test_signer) -> None:
    result = score(
        [receipt(room_id="a"), receipt(room_id="b"), receipt(window_id="w-2")]
    )
    assert result.units_by_uid == ((BREAKER_UID, 3),)


def test_expired_window_drops(test_signer) -> None:
    window = DEFAULT_REWARD_WINDOW_SECONDS
    fresh = receipt(room_id="fresh", planted_at=NOW - window)
    stale = receipt(room_id="stale", planted_at=NOW - window - 1)
    result = score([fresh, stale], window=window)
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"expired": 1}


def test_future_planted_at_is_refused(test_signer) -> None:
    assert score([receipt(planted_at=NOW + 3600)]).refused == {"future": 1}


def test_unregistered_hotkey_is_ignored_and_logged(test_signer) -> None:
    result = score([receipt(hotkey="5Nobody")])
    assert result.units_by_uid == ()
    assert result.refused == {"unregistered": 1}
    assert result.summary()["unregistered_hotkeys"] == ["5Nobody"]


def test_validator_cannot_pay_itself(test_signer) -> None:
    assert score([receipt(hotkey=base.VALIDATOR)]).refused == {"validator_self": 1}


# --- blending into the plan ------------------------------------------------


def test_valid_receipt_weights_the_breaker_uid(test_signer) -> None:
    planned = machine_plan()
    blended, summary = runtime.apply_escape_receipts(
        planned, config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    assert summary["status"] == "APPLIED"
    assert summary["accepted"] == 1
    weights = dict(zip(blended.wire_uids, blended.wire_weights, strict=True))
    assert set(weights) == {19, BREAKER_UID}
    assert sum(weights.values()) == W
    # 10% of 65535 is 6553.5; the remainder goes to the larger fractional part.
    assert weights[BREAKER_UID] in (6553, 6554)
    assert blended.identity()["escape"] == {
        "fraction": "1/10",
        "units_by_uid": [[BREAKER_UID, 1]],
        "uid_hotkeys": [[BREAKER_UID, BREAKER]],
    }
    assert blended.evidence_digest != planned.evidence_digest
    assert blended.expected_vector() == (blended.wire_uids, blended.wire_weights)


def test_blend_splits_the_share_by_break_count(test_signer, monkeypatch) -> None:
    planned = machine_plan()
    second = "5SecondBreaker"
    snap = replace(
        planned.snapshot,
        registered_hotkeys={**planned.snapshot.registered_hotkeys, second: 31},
    )
    planned = replace(planned, snapshot=snap)
    receipts = [
        receipt(room_id="a"),
        receipt(room_id="b"),
        receipt(room_id="c", hotkey=second),
    ]
    blended, _summary = runtime.apply_escape_receipts(
        planned, config("3/10"), now=NOW, load=lambda _source: receipts
    )
    weights = dict(zip(blended.wire_uids, blended.wire_weights, strict=True))
    assert sum(weights.values()) == W
    assert abs(weights[BREAKER_UID] - 2 * weights[31]) <= 1
    assert abs(weights[19] - round(W * 0.7)) <= 1


def test_no_breaks_or_unreadable_source_leave_the_plan_unchanged(test_signer) -> None:
    planned = machine_plan()
    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=lambda _source: []
    )
    assert same is planned and summary["status"] == "NO_BREAKS"

    def broken(_source: str) -> list[object]:
        raise OSError("feed down")

    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=broken
    )
    assert same is planned and summary["status"] == "SOURCE_UNAVAILABLE"


def test_off_by_default_changes_nothing(monkeypatch) -> None:
    for name in (
        escape_receipts.ESCAPE_RECEIPTS_SOURCE_ENV,
        escape_receipts.ESCAPE_WEIGHT_FRACTION_ENV,
        escape_receipts.ESCAPE_REWARD_WINDOW_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    assert escape_config_from_environment() is None
    # A source without a fraction, or a zero fraction, is still off.
    assert (
        escape_config_from_environment({"CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x"})
        is None
    )
    assert (
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0",
            }
        )
        is None
    )
    # The plan a validator builds today has no escape block and the same
    # identity as before this change.
    planned = base.plan()
    assert planned.escape_active is False
    assert "escape" not in planned.identity()
    assert planned.expected_vector() == (planned.wire_uids, planned.wire_weights)
    assert planned.snapshot.identity() == registered_snapshot().identity()


def test_malformed_config_refuses() -> None:
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "1",
            }
        )
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "http://insecure.example/feed",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.1",
            }
        )
    loaded = escape_config_from_environment(
        {
            "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
            "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.1",
            "CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS": "86400",
        }
    )
    assert loaded == EscapeReceiptConfig(
        source="https://api.example/escape/receipts",
        fraction=Fraction(1, 10),
        window_seconds=86400,
    )


def test_feed_file_accepts_list_or_object(tmp_path: Path, test_signer) -> None:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps({"receipts": [receipt()]}))
    assert len(escape_receipts.load_receipt_feed(str(path))) == 1
    path.write_text(json.dumps([receipt(), receipt(room_id="b")]))
    assert len(escape_receipts.load_receipt_feed(str(path))) == 2


# --- writer ----------------------------------------------------------------


class BreakerSubtensor(base.WriterSubtensor):
    """Chain double where the breaker is registered but serves no axon."""

    breaker_hotkey = BREAKER

    def metagraph(self, netuid: int, *, block: int):
        graph = super().metagraph(netuid, block=block)
        graph.uids.append(BREAKER_UID)
        graph.hotkeys.append(self.breaker_hotkey)
        graph.validator_permit.append(False)
        graph.axons.append(base.Axon("0.0.0.0", 0, serving=False))
        graph.last_update.append(0)
        graph.total_stake.append(SimpleNamespace(rao=0))
        return graph


def breaker_writer(tmp_path: Path, monkeypatch, planned):
    instance, _subtensor, _ = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor = BreakerSubtensor(miners=planned.snapshot.miners)
    subtensor.substrate.expected_uids = list(planned.wire_uids)
    subtensor.substrate.expected_weights = list(planned.wire_weights)
    instance.subtensor = subtensor
    return instance, subtensor


def test_writer_signs_and_confirms_a_blended_vector(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, blended)
    result = base.submit_before_deadline(instance, blended)
    assert result.status == STATUS_CONFIRMED
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["intent"]["kwargs"]["dests"] == [19, BREAKER_UID]
    assert state["last_attempt"]["identity"]["escape"]["units_by_uid"] == [
        [BREAKER_UID, 1]
    ]
    assert subtensor.substrate.submit_calls == 1


def test_writer_refuses_a_recycled_breaker_uid(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, blended)
    subtensor.breaker_hotkey = "5NewHolder"
    with pytest.raises(DirectValidatorError, match="escape receipt UID changed"):
        base.submit_before_deadline(instance, blended)
    assert subtensor.substrate.submit_calls == 0


def test_writer_refuses_a_vector_that_does_not_match_its_escape_inputs(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    inflated = replace(blended, escape_fraction="1/2")
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, inflated)
    with pytest.raises(DirectValidatorError):
        base.submit_before_deadline(instance, inflated)
    assert subtensor.substrate.submit_calls == 0
