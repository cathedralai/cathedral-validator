"""Cathedral Ed25519 spot-check of the CyberGym attestation receipt (distill #115).

This is not Intel DCAP quote verification. The check verifies Cathedral's own
Ed25519 signature over a ``cathedral_customer_receipt_v1`` document. Offline
success proves Cathedral signed those assertions. It does not replay vendor
evidence and it does not prove an Intel TDX quote.

cathedral-validator #103 makes the validator carry the one representative receipt
the report attaches and ratchet its presence. This module checks that the
receipt verifies under the pinned Cathedral key, and that the committed
``(nonce, miner)`` is the one the chain named this epoch.

``CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT`` is off by default: a failed
or missing *carried* receipt is recorded and the lane still pays. After an
audience has adopted receipt carriage, ingest refuses a later report that
omits the field regardless of this flag. Real Intel DCAP quote verification
is separate work. Do not describe this module as DCAP.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TRUSTED_KEYS_ENV = "CATHEDRAL_RECEIPT_TRUSTED_KEYS"
REQUIRE_ATTESTATION_ENV = "CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT"

# Must match the producer's cybergym_score_report._SPOTCHECK_DOMAIN exactly, so the
# validator re-derives the identical chain-named miner.
_SPOTCHECK_DOMAIN = b"cathedral-cybergym-spotcheck-v1"
_REQUIRED_TEE = "intel_tdx"
_TRUTHY = {"1", "true", "yes", "on"}


def require_attestation() -> bool:
    """Whether an unverifiable/absent receipt should BURN the CyberGym lane.

    Off by default: the spot-check is advisory during rollout (the outcome is recorded
    but the lane still pays), so turning verification on cannot silently zero a healthy
    lane. Set the env to enforce.
    """
    return os.environ.get(REQUIRE_ATTESTATION_ENV, "").strip().lower() in _TRUTHY


def _load_trusted_keys() -> dict[str, Any] | None:
    path = os.environ.get(TRUSTED_KEYS_ENV, "").strip()
    if not path:
        return None
    try:
        keys = json.loads(Path(path).read_text())["keys"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return keys if isinstance(keys, dict) else None


def _cathedral_signed_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Cathedral signs the canonical JSON of every top-level receipt field except
    ``signature`` (cathedral-compute ``customer_receipt_signed_bytes``)."""
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _signature_verifies(receipt: Mapping[str, Any], keys: dict[str, Any]) -> bool:
    try:
        entry = keys[str(receipt["signing_key_id"])]
        if entry.get("status") != "active" or entry.get("algorithm") != "ed25519":
            return False
        issued = datetime.fromisoformat(str(receipt["issued_at"]).replace("Z", "+00:00"))
        valid_from = datetime.fromisoformat(str(entry["valid_from"]).replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(str(entry["valid_until"]).replace("Z", "+00:00"))
        if not (valid_from <= issued <= valid_until):
            return False
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(str(entry["public_key_base64"]), validate=True)
        )
        signature = base64.b64decode(str(receipt["signature"]["value_base64"]), validate=True)
    except (KeyError, TypeError, ValueError):
        return False
    try:
        public_key.verify(signature, _cathedral_signed_bytes(receipt))
    except InvalidSignature:
        return False
    return True


def chain_named_miner(creditable, *, nonce: str, source_epoch: int) -> str | None:
    """Re-derive the miner the chain named — the argmin the producer used to pick the
    receipt (cybergym_score_report._spotcheck_miner). Identical domain + digest, so a
    third party (this validator) computes the same answer from published data alone."""
    creditable = sorted(creditable)
    if not creditable:
        return None
    nonce_bytes = nonce.encode("utf-8")
    if not nonce_bytes:
        return None
    epoch_bytes = str(int(source_epoch)).encode("ascii")

    def _digest(hotkey: str) -> str:
        return hashlib.sha256(
            _SPOTCHECK_DOMAIN + b"\x00" + nonce_bytes + b"\x00"
            + epoch_bytes + b"\x00" + hotkey.encode("utf-8")
        ).hexdigest()

    return min(creditable, key=_digest)


def verify_attestation_receipt(
    attestation_receipt: Any, *, nonce: str, source_epoch: int, scored_hotkeys
) -> tuple[bool, str]:
    """``(ok, reason)``. Verifies the carried receipt end to end:

    1. Cathedral Ed25519 signature over the receipt (pinned trusted key, active, in window);
    2. Intel-TDX posture (``cpu_tee=intel_tdx`` + ``intel_verified`` + ``execution_binding_verified``);
    3. result binding — ``sha256(result_bytes) == receipt.result_sha256`` (the envelope IS
       what the receipt attested);
    4. commitment binding — the envelope commits to THIS epoch's ``nonce`` and to the miner
       the chain named (re-derived here), so the producer cannot show a receipt for a miner
       or an epoch it prefers.
    """
    if not isinstance(attestation_receipt, Mapping):
        return False, "malformed"
    receipt = attestation_receipt.get("receipt")
    result_b64 = attestation_receipt.get("result_b64")
    if not isinstance(receipt, Mapping) or not isinstance(result_b64, str):
        return False, "malformed"

    keys = _load_trusted_keys()
    if keys is None:
        return False, "no_trusted_keys"
    if not _signature_verifies(receipt, keys):
        return False, "bad_signature"

    if (
        receipt.get("cpu_tee") != _REQUIRED_TEE
        or receipt.get("intel_verified") is not True
        or receipt.get("execution_binding_verified") is not True
    ):
        return False, "posture"

    try:
        result_bytes = base64.b64decode(result_b64, validate=True)
    except (ValueError, TypeError):
        return False, "bad_result_b64"
    if hashlib.sha256(result_bytes).hexdigest() != str(receipt.get("result_sha256")):
        return False, "result_mismatch"

    try:
        commitment = json.loads(result_bytes).get("commitment")
    except (ValueError, TypeError, AttributeError):
        return False, "bad_envelope"
    if not isinstance(commitment, Mapping):
        return False, "bad_envelope"

    if str(commitment.get("nonce")) != str(nonce):
        return False, "nonce_mismatch"
    named = chain_named_miner(
        (h for h in scored_hotkeys), nonce=str(nonce), source_epoch=source_epoch
    )
    if named is None or str(commitment.get("miner_hotkey")) != named:
        return False, "miner_mismatch"

    return True, "ok"
