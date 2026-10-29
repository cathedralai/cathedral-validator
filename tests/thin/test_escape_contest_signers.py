"""Pinned contest signer key rotation (SN94 escape receipts)."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_direct_validator as base
from cathedral_thin.independent_runtime.escape_receipts import (
    CONTEST_SIGNER_SET_SCHEMA,
    DEFAULT_REWARD_WINDOW_SECONDS,
    LEGACY_SINGLE_KEY_ID,
    PINNED_CONTEST_PUBKEY_B64,
    PINNED_CONTEST_SIGNERS,
    PINNED_CONTEST_SIGNERS_SHA256,
    EscapeReceiptError,
    load_contest_signers,
    parse_contest_signers,
    parse_contest_signers_bytes,
    score_escape_receipts,
    verify_escape_receipt,
)
from test_escape_receipt_weights import (
    BREAKER,
    BREAKER_UID,
    NOW,
    REPO,
    receipt,
)

OLD_KEY = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
NEW_KEY = Ed25519PrivateKey.from_private_bytes(b"\x12" * 32)
OVERLAP_START = NOW - 100
OLD_NOT_AFTER = NOW + 100


def _pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


def _row(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    not_before: float = 0,
    not_after: float | None = None,
    revoked: bool = False,
) -> dict[str, object]:
    row: dict[str, object] = {
        "id": key_id,
        "not_before": not_before,
        "pubkey_b64": _pub_b64(key),
    }
    if not_after is not None:
        row["not_after"] = not_after
    if revoked:
        row["revoked"] = True
    return row


def make_signers(*rows: dict[str, object]):
    return parse_contest_signers(
        {"schema": CONTEST_SIGNER_SET_SCHEMA, "keys": list(rows)}
    )


def overlapping_signers(*, revoked_old: bool = False):
    return make_signers(
        _row(
            OLD_KEY,
            "old",
            not_before=0,
            not_after=OLD_NOT_AFTER,
            revoked=revoked_old,
        ),
        _row(NEW_KEY, "new", not_before=OVERLAP_START),
    )


def score_with(receipts, signers, *, now: float = NOW):
    return score_escape_receipts(
        receipts,
        registered={BREAKER: BREAKER_UID, base.VALIDATOR: 7},
        validator_uid=7,
        now=now,
        window_seconds=DEFAULT_REWARD_WINDOW_SECONDS,
        signers=signers,
    )


def test_old_key_valid_then_expired() -> None:
    signers = overlapping_signers()
    still_valid = receipt(
        key=OLD_KEY, key_id="old", planted_at=OLD_NOT_AFTER, room_id="in-window"
    )
    expired = receipt(
        key=OLD_KEY, key_id="old", planted_at=OLD_NOT_AFTER + 1, room_id="late"
    )
    assert verify_escape_receipt(still_valid, signers=signers).key_id == "old"
    with pytest.raises(EscapeReceiptError, match="not valid at planted_at"):
        verify_escape_receipt(expired, signers=signers)
    result = score_with([still_valid, expired], signers)
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"invalid": 1}
    assert result.accepted_key_ids == ("old",)


def test_overlap_window_accepts_both_keys() -> None:
    signers = overlapping_signers()
    planted = OVERLAP_START + 1
    old_receipt = receipt(key=OLD_KEY, key_id="old", planted_at=planted, room_id="a")
    new_receipt = receipt(key=NEW_KEY, key_id="new", planted_at=planted, room_id="b")
    assert verify_escape_receipt(old_receipt, signers=signers).key_id == "old"
    assert verify_escape_receipt(new_receipt, signers=signers).key_id == "new"
    result = score_with([old_receipt, new_receipt], signers)
    assert result.units_by_uid == ((BREAKER_UID, 2),)
    assert set(result.accepted_key_ids) == {"old", "new"}


def test_revoked_key_is_refused() -> None:
    signers = overlapping_signers(revoked_old=True)
    planted = OVERLAP_START + 1
    revoked_receipt = receipt(key=OLD_KEY, key_id="old", planted_at=planted)
    with pytest.raises(EscapeReceiptError, match="revoked"):
        verify_escape_receipt(revoked_receipt, signers=signers)
    result = score_with([revoked_receipt], signers)
    assert result.units_by_uid == ()
    assert result.refused == {"invalid": 1}


def test_unknown_key_id_is_refused() -> None:
    signers = overlapping_signers()
    unknown = receipt(key=OLD_KEY, key_id="no-such", planted_at=OVERLAP_START + 1)
    with pytest.raises(EscapeReceiptError, match="unknown contest key id"):
        verify_escape_receipt(unknown, signers=signers)
    result = score_with([unknown], signers)
    assert result.units_by_uid == ()
    assert result.refused == {"invalid": 1}


def test_tampered_key_set_fails_the_pin() -> None:
    raw = (REPO / "config/escape/contest-signers.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_CONTEST_SIGNERS_SHA256
    load_contest_signers(raw, expected_sha256=PINNED_CONTEST_SIGNERS_SHA256)
    tampered = raw.replace(b"contest-2026-10", b"contest-2099-01", 1)
    assert tampered != raw
    with pytest.raises(EscapeReceiptError, match="does not match its sha256 pin"):
        load_contest_signers(tampered, expected_sha256=PINNED_CONTEST_SIGNERS_SHA256)


def test_legacy_single_key_config_is_still_accepted() -> None:
    pub_file = (REPO / "config/escape/contest-signer.ed25519.pub").read_bytes()
    legacy = parse_contest_signers_bytes(pub_file)
    assert len(legacy.keys) == 1
    assert legacy.keys[0].key_id == LEGACY_SINGLE_KEY_ID
    assert legacy.keys[0].pubkey_b64 == PINNED_CONTEST_PUBKEY_B64
    assert legacy.keys[0].not_after is None
    assert legacy.keys[0].revoked is False

    test_pub = (_pub_b64(OLD_KEY) + "\n").encode("ascii")
    test_legacy = parse_contest_signers_bytes(test_pub)
    unsigned_id = receipt(key=OLD_KEY, planted_at=NOW - 10)
    assert "key_id" not in unsigned_id
    verified = verify_escape_receipt(unsigned_id, signers=test_legacy)
    assert verified.key_id == LEGACY_SINGLE_KEY_ID
    result = score_with([unsigned_id], test_legacy)
    assert result.units_by_uid == ((BREAKER_UID, 1),)


def test_pinned_set_is_the_current_contest_key() -> None:
    assert len(PINNED_CONTEST_SIGNERS.keys) == 1
    key = PINNED_CONTEST_SIGNERS.keys[0]
    assert key.key_id == "contest-2026-10"
    assert key.pubkey_b64 == PINNED_CONTEST_PUBKEY_B64
    assert key.not_before == 0
    assert key.not_after is None
    assert key.revoked is False
    assert PINNED_CONTEST_SIGNERS.source_sha256 == PINNED_CONTEST_SIGNERS_SHA256
