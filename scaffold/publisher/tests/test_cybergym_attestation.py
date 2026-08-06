"""Independent DCAP spot-check of the carried CyberGym attestation receipt.

Self-contained: it mints an Ed25519 "Cathedral" key, builds an internally consistent
receipt + result envelope, signs it, and points the module at a trusted-keys file for
that key — then breaks exactly one thing per test. No cathedral_distill fixture needed.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scaffold.publisher import cybergym_attestation as att

KEY_ID = "cathedral-customer-receipt-2026-07-31-01"
NONCE = "cgnonce-sha256:" + "ab" * 32
EPOCH = 42
MINERS = ("5Alice", "5Bob", "5Carol")


def _signed_bytes(receipt: dict) -> bytes:
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _named(miners=MINERS, nonce=NONCE, epoch=EPOCH) -> str:
    """Independently re-derive the chain-named miner (not via the production helper)."""
    dom = b"cathedral-cybergym-spotcheck-v1"

    def d(h):
        return hashlib.sha256(
            dom + b"\x00" + nonce.encode() + b"\x00" + str(epoch).encode() + b"\x00" + h.encode()
        ).hexdigest()

    return min(sorted(miners), key=d)


@pytest.fixture
def signer(tmp_path, monkeypatch):
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    keys = {"keys": {KEY_ID: {
        "algorithm": "ed25519", "status": "active",
        "public_key_base64": base64.b64encode(raw).decode(),
        "valid_from": "2026-07-31T00:00:00.000000Z",
        "valid_until": "2027-08-01T00:00:00.000000Z",
    }}}
    path = tmp_path / "trusted.json"
    path.write_text(json.dumps(keys))
    monkeypatch.setenv(att.TRUSTED_KEYS_ENV, str(path))
    return sk


def _build(sk, *, nonce=NONCE, miner=None, epoch=EPOCH, break_result=False,
           intel_verified=True, exec_binding=True, cpu_tee="intel_tdx",
           key_status="active"):
    miner = miner or _named(nonce=nonce, epoch=epoch)
    envelope = {
        "schema": "cathedral_cybergym_tdx_enclave_commitment_v1",
        "commitment": {"miner_hotkey": miner, "nonce": nonce,
                       "task_id": "arvo:1", "poc_sha256": "sha256:" + "a" * 64},
        "enclave_pubkey_b64": "", "signature_b64": "",
    }
    result_bytes = json.dumps(envelope).encode()
    result_sha = "0" * 64 if break_result else hashlib.sha256(result_bytes).hexdigest()
    receipt = {
        "schema": "cathedral_customer_receipt_v1", "cpu_tee": cpu_tee,
        "intel_verified": intel_verified, "execution_binding_verified": exec_binding,
        "signing_key_id": KEY_ID, "issued_at": "2026-08-05T12:00:00.000000Z",
        "result_sha256": result_sha, "workload_sha256": "w" * 8,
    }
    receipt["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(sk.sign(_signed_bytes(receipt))).decode(),
    }
    return {"receipt": receipt, "result_b64": base64.b64encode(result_bytes).decode()}


def _verify(ar, *, nonce=NONCE, epoch=EPOCH):
    return att.verify_attestation_receipt(
        ar, nonce=nonce, source_epoch=epoch, scored_hotkeys=MINERS
    )


def test_a_genuine_receipt_for_the_chain_named_miner_verifies(signer):
    assert _verify(_build(signer)) == (True, "ok")


def test_tampered_signature_is_refused(signer):
    ar = _build(signer)
    sig = bytearray(base64.b64decode(ar["receipt"]["signature"]["value_base64"]))
    sig[0] ^= 0x01
    ar["receipt"]["signature"]["value_base64"] = base64.b64encode(bytes(sig)).decode()
    assert _verify(ar) == (False, "bad_signature")


def test_a_different_epoch_nonce_is_refused(signer):
    # receipt commits to NONCE; verifying under a different nonce must fail.
    assert _verify(_build(signer), nonce="cgnonce-sha256:" + "cd" * 32)[1] == "nonce_mismatch"


def test_a_receipt_for_a_miner_the_chain_did_not_name_is_refused(signer):
    other = next(m for m in MINERS if m != _named())
    assert _verify(_build(signer, miner=other))[1] == "miner_mismatch"


def test_result_not_bound_to_the_receipt_is_refused(signer):
    assert _verify(_build(signer, break_result=True))[1] == "result_mismatch"


def test_non_tdx_or_unverified_posture_is_refused(signer):
    # signed with the flag off, so the signature is valid but posture fails.
    assert _verify(_build(signer, intel_verified=False))[1] == "posture"
    assert _verify(_build(signer, exec_binding=False))[1] == "posture"
    assert _verify(_build(signer, cpu_tee="amd_sev"))[1] == "posture"


def test_without_a_trusted_keys_file_it_fails_closed(signer, monkeypatch):
    monkeypatch.delenv(att.TRUSTED_KEYS_ENV, raising=False)
    assert _verify(_build(signer)) == (False, "no_trusted_keys")


def test_a_retired_key_is_not_trusted(signer, tmp_path, monkeypatch):
    ar = _build(signer)
    # rewrite the trust file with the key retired
    raw = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    path = tmp_path / "retired.json"
    path.write_text(json.dumps({"keys": {KEY_ID: {
        "algorithm": "ed25519", "status": "retired",
        "public_key_base64": base64.b64encode(raw).decode(),
        "valid_from": "2026-07-31T00:00:00.000000Z",
        "valid_until": "2027-08-01T00:00:00.000000Z"}}}))
    monkeypatch.setenv(att.TRUSTED_KEYS_ENV, str(path))
    assert _verify(ar) == (False, "bad_signature")


def test_a_malformed_receipt_is_refused(signer):
    assert _verify("notadict")[1] == "malformed"
    assert _verify({"result_b64": "eA=="})[1] == "malformed"


def test_a_genuine_cathedral_intel_tdx_receipt_verifies(monkeypatch):
    """The one that proves this reimplementation actually matches Cathedral: a REAL
    captured `attest.v1` receipt (Intel-TDX hardware, Cathedral-signed) verifies against
    the pinned published trusted-keys file — and its committed nonce/miner bind. If
    Cathedral ever changed the receipt or signed-bytes shape, this fails first."""
    fixtures = Path(__file__).parent / "fixtures"
    monkeypatch.setenv(att.TRUSTED_KEYS_ENV, str(fixtures / "cathedral-customer-receipt-trusted-keys.json"))
    fix = json.loads((fixtures / "cybergym-real-tdx-receipt.json").read_text())
    ar = {"receipt": fix["receipt"], "result_b64": fix["result_b64"]}
    commitment = json.loads(base64.b64decode(fix["result_b64"]))["commitment"]
    miner, nonce = commitment["miner_hotkey"], commitment["nonce"]

    assert att.verify_attestation_receipt(
        ar, nonce=nonce, source_epoch=21, scored_hotkeys={miner}) == (True, "ok")
    # the chain binding is real, not vacuous:
    assert att.verify_attestation_receipt(
        ar, nonce="cgnonce-other", source_epoch=21, scored_hotkeys={miner})[1] == "nonce_mismatch"
    assert att.verify_attestation_receipt(
        ar, nonce=nonce, source_epoch=21, scored_hotkeys={"5NotThisMiner"})[1] == "miner_mismatch"


def test_require_flag_reads_the_env(monkeypatch):
    monkeypatch.delenv(att.REQUIRE_ATTESTATION_ENV, raising=False)
    assert att.require_attestation() is False
    monkeypatch.setenv(att.REQUIRE_ATTESTATION_ENV, "1")
    assert att.require_attestation() is True
    monkeypatch.setenv(att.REQUIRE_ATTESTATION_ENV, "off")
    assert att.require_attestation() is False
