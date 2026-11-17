"""The literals `cathedral_thin.cybergym_epoch_proof` claims to mirror, actually pinned.

`cybergym_epoch_proof` duplicates cathedral's wire contract rather than importing it,
because no import spans the two repositories, and its docstring says a test pins the
shared literals "so drift fails a test here instead of silently failing to verify a real
producer document in production".

No such test existed. So the drift shipped: `scaffold/publisher/cybergym_contract` and
`scaffold/publisher/cybergym_ingest` gained `OPTIONAL_SEMANTIC_KEYS` (`nonce`,
`dispatched_units`, `attestation_receipt`) and the independent verifier did not. A
current producer emits `nonce` and `dispatched_units` whenever the epoch recorded a
frontier row, so its report was refused `invalid_document: unexpected fields
dispatched_units,nonce`, the epoch proof did not verify, and the lane's entire share
burned -- while this repo's own intake accepted the same body.

These tests are the guard that was promised. They compare the two implementations
directly, so adding a key to one and not the other fails here.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cathedral_thin import cybergym_epoch_proof as proof  # noqa: E402

contract = pytest.importorskip(
    "scaffold.publisher.cybergym_contract",
    reason="the publisher extra provides the contract this verifier mirrors",
)


def _document(**overrides):
    document = {
        "producer_hotkey": "5Producer",
        "network": "finney",
        "netuid": 94,
        "source_epoch": 11,
        "generated_at": "2026-11-17T12:00:00.000Z",
        "complete": True,
        "score_units": proof.EXPECTED_SCORE_UNITS,
        "scores": {"5Miner": 2.0},
        "evidence_sha256": "a" * 64,
    }
    document.update(overrides)
    return document


class TestTheMirroredLiteralsAgree:
    def test_the_required_key_set_matches_including_order(self):
        assert proof.SEMANTIC_KEYS == contract.SEMANTIC_KEYS

    def test_the_optional_key_set_matches_including_order(self):
        """The drift that actually shipped. Adding a key on one side now fails here."""
        assert proof.OPTIONAL_SEMANTIC_KEYS == contract.OPTIONAL_SEMANTIC_KEYS

    def test_the_hmac_secret_env_matches(self):
        assert proof.EPOCH_PROOF_SECRET_ENV == contract.HMAC_SECRET_ENV

    def test_the_canonical_bytes_agree_on_an_optional_bearing_document(self):
        """One serializer, or the HMAC is taken over two different bodies."""
        document = _document(nonce="0xabc", dispatched_units=100.0)
        assert proof.canonical_bytes(document) == contract.canonical_report_bytes(
            document
        )

    def test_both_normalizers_produce_the_same_semantic_form(self):
        document = _document(nonce="  0xabc  ", dispatched_units=100)
        assert proof.normalize(document) == contract.normalize_semantic_document(
            dict(document)
        )


class TestTheVerifierAcceptsWhatTheIntakeAccepts:
    def test_a_producer_frontier_report_is_no_longer_refused(self):
        """The exact body shape that burned the lane: nonce + dispatched_units."""
        normalized = proof.normalize(_document(nonce="0xabc", dispatched_units=100.0))
        assert normalized["nonce"] == "0xabc"
        assert normalized["dispatched_units"] == 100.0

    def test_an_attestation_receipt_sample_is_carried_verbatim(self):
        sample = {
            "receipt": {"schema": "cathedral_assurance_receipt_v2", "x": 1},
            "result_b64": base64.b64encode(b"result").decode("ascii"),
        }
        normalized = proof.normalize(_document(attestation_receipt=sample))
        assert normalized["attestation_receipt"] == sample

    def test_a_report_without_the_optional_keys_is_unchanged(self):
        """Back-compatibility is the point: no key appears that was not supplied."""
        normalized = proof.normalize(_document())
        assert set(normalized) == set(proof.SEMANTIC_KEYS)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"nonce": ""},
            {"nonce": "x" * 257},
            {"nonce": 1},
            {"dispatched_units": -1.0},
            {"dispatched_units": float("inf")},
            {"dispatched_units": True},
            {"dispatched_units": "100"},
            {"attestation_receipt": {"receipt": {}, "result_b64": "aa=="}},
            {"attestation_receipt": {"receipt": {"a": 1}, "result_b64": "not base64!"}},
            {"attestation_receipt": {"receipt": {"a": 1}}},
            {"attestation_receipt": "sample"},
        ],
    )
    def test_a_malformed_optional_field_still_fails_closed(self, overrides):
        """Widening the key set must not widen what counts as a valid value."""
        with pytest.raises(proof.EpochProofError):
            proof.normalize(_document(**overrides))

    def test_an_unrecognised_key_is_still_refused(self):
        """A CLOSED list, not 'ignore what you do not know': a derived column must
        not be able to ride into the signed material."""
        with pytest.raises(proof.EpochProofError) as excinfo:
            proof.normalize(_document(derived_bonus=1.0))
        assert "unexpected fields derived_bonus" in str(excinfo.value)
