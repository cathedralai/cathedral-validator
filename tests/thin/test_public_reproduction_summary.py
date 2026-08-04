"""The reproduction summary honors the signed release's evidence posture.

A relay release (schema v3, no evidence checkpoint captured at submission)
verifies as `frozen_evidence: NOT_CLAIMED` — there is nothing to replay, and
the summary must say so instead of demanding a checkpoint replay that the
release never claimed. A checkpoint release still requires every evidence
field to reproduce. The assertion previously required `evidence_checkpoint`
unconditionally, failing every relay release the finalizer had just signed.

These tests call the production function with injected release results.
"""

from __future__ import annotations

import pytest

from scaffold.sn39_public_reproduction import (
    ReproductionError,
    assert_public_reproduction,
)

REVISION = "0e84fb32c3bfb03da17fdc0c598a566c73ed619f"


def _relay_result(**overrides):
    result = {
        "release_attestation": "PASS",
        "historical_launch": "PASS",
        "frozen_evidence": "NOT_CLAIMED",
        "evidence_scope": "signed_feed_relay",
        "reproducer_revision": REVISION,
    }
    result.update(overrides)
    return result


def _checkpoint_result(**overrides):
    result = {
        "release_attestation": "PASS",
        "historical_launch": "PASS",
        "evidence_checkpoint": "PASS",
        "evidence_candidate_set": "PASS",
        "root_finalizer_tdx_replay": "PASS",
        "reproducer_revision": REVISION,
    }
    result.update(overrides)
    return result


# -- relay posture -----------------------------------------------------------


def test_relay_release_reproduces_without_a_checkpoint():
    summary = assert_public_reproduction(release_result=_relay_result())
    assert summary["release_attestation"] == "PASS"
    assert summary["historical_launch"] == "PASS"
    assert summary["frozen_evidence"] == "NOT_CLAIMED"
    assert summary["evidence_scope"] == "signed_feed_relay"
    assert summary["evidence_checkpoint"] == "NOT_CLAIMED"
    assert summary["evidence_candidate_set"] == "NOT_CLAIMED"
    assert summary["root_finalizer_tdx_replay"] == "NOT_CLAIMED"
    assert summary["chain_write"] is False
    assert summary["reproducer_revision"] == REVISION


def test_relay_posture_requires_the_relay_scope():
    result = _relay_result(evidence_scope="frozen_checkpoint")
    with pytest.raises(ReproductionError, match="relay scope"):
        assert_public_reproduction(release_result=result)


def test_relay_posture_rejects_a_conflicting_checkpoint_claim():
    result = _relay_result(evidence_checkpoint="PASS")
    with pytest.raises(ReproductionError, match="conflicts"):
        assert_public_reproduction(release_result=result)


def test_relay_posture_still_requires_the_attestation_and_launch():
    for field in ("release_attestation", "historical_launch"):
        result = _relay_result(**{field: "FAIL"})
        with pytest.raises(ReproductionError, match="did not reproduce"):
            assert_public_reproduction(release_result=result)


# -- checkpoint posture ------------------------------------------------------


def test_checkpoint_release_still_requires_every_evidence_field():
    summary = assert_public_reproduction(release_result=_checkpoint_result())
    assert summary["evidence_checkpoint"] == "PASS"
    assert summary["evidence_candidate_set"] == "PASS"
    assert summary["root_finalizer_tdx_replay"] == "PASS"
    for field in (
        "release_attestation",
        "historical_launch",
        "evidence_checkpoint",
        "evidence_candidate_set",
    ):
        result = _checkpoint_result(**{field: "FAIL"})
        with pytest.raises(ReproductionError, match="did not reproduce"):
            assert_public_reproduction(release_result=result)


def test_a_missing_evidence_field_is_not_treated_as_relay():
    # No NOT_CLAIMED stamp and no checkpoint result: fail closed, never
    # silently downgrade to the relay posture.
    result = _checkpoint_result()
    del result["evidence_checkpoint"]
    with pytest.raises(ReproductionError, match="did not reproduce"):
        assert_public_reproduction(release_result=result)
