"""The validator scores a receipt trimmed by the real Polaris signer (AB#687, AB#727).

Polaris signs only a claim's proof fields (polariscomputer #1742) and keeps the
rest private. The fixture is one receipt signed by polariscomputer's own
``sign_contest_receipt`` with a throwaway key, from a claim that carried notes,
command text, stdout and an extra proof_token field. If a later validator
change starts to need a claim field Polaris no longer publishes, this fails
before a real break is refused.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from cathedral_thin.independent_runtime.escape_receipts import (
    CONTEST_SIGNER_SET_SCHEMA,
    DEFAULT_REWARD_WINDOW_SECONDS,
    EscapeReceiptError,
    parse_contest_signers,
    score_escape_receipts,
    verify_escape_receipt,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "escape_trimmed_receipt_polaris.json"
    ).read_text("utf-8")
)
RECEIPT = FIXTURE["receipt"]
PUBLIC_CLAIM_KEYS = {
    "schema",
    "target",
    "window_id",
    "room_id",
    "commands",
    "proof_token",
    "breaker_hotkey",
}
BREAKER_UID = 23
NOW = RECEIPT["planted_at"] + 60


def _signers(key_id: str = RECEIPT["key_id"]):
    return parse_contest_signers(
        {
            "schema": CONTEST_SIGNER_SET_SCHEMA,
            "keys": [
                {"id": key_id, "not_before": 0, "pubkey_b64": FIXTURE["pubkey_b64"]}
            ],
        }
    )


def test_fixture_is_trimmed_to_the_proof_fields():
    claim = RECEIPT["claim"]
    assert set(claim) == PUBLIC_CLAIM_KEYS
    assert all(set(command) == {"attested_room"} for command in claim["commands"])
    assert set(claim["proof_token"]) == {"kind", "window_id", "nonce"}
    text = json.dumps(RECEIPT)
    for marker in FIXTURE["trimmed_markers"]:
        assert marker not in text


def test_trimmed_receipt_verifies_and_scores_one_unit():
    verified = verify_escape_receipt(copy.deepcopy(RECEIPT), signers=_signers())
    assert verified.digest == FIXTURE["receipt_digest"]
    assert verified.breaker_hotkey == RECEIPT["claim"]["breaker_hotkey"]
    scored = score_escape_receipts(
        [copy.deepcopy(RECEIPT), copy.deepcopy(RECEIPT)],
        registered={RECEIPT["claim"]["breaker_hotkey"]: BREAKER_UID},
        validator_uid=7,
        now=NOW,
        window_seconds=DEFAULT_REWARD_WINDOW_SECONDS,
        signers=_signers(),
    )
    assert scored.units_by_uid == ((BREAKER_UID, 1),)
    assert scored.accepted_digests == (FIXTURE["receipt_digest"],)


@pytest.mark.parametrize(
    "edit",
    [
        lambda r: r["claim"].update(notes="added after signing"),
        lambda r: r["claim"]["commands"][0].update(cmd="cat /run/escape-room/nonce"),
        lambda r: r["claim"]["proof_token"].update(method="added after signing"),
    ],
)
def test_a_field_added_back_after_signing_fails_the_signature(edit):
    tampered = copy.deepcopy(RECEIPT)
    edit(tampered)
    with pytest.raises(EscapeReceiptError, match="signature"):
        verify_escape_receipt(tampered, signers=_signers())


def test_signer_set_must_hold_the_receipts_key_id():
    with pytest.raises(EscapeReceiptError, match="unknown contest key id"):
        verify_escape_receipt(copy.deepcopy(RECEIPT), signers=_signers("drill"))
