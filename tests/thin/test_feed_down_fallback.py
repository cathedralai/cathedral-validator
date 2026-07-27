"""Thin degrades UP into FULL when the signed vector is unreachable.

Thin follows Cathedral's signed vector, so an unreachable publisher leaves it
with nothing to submit. FULL derives the same allocation from raw evidence and
never reads the vector, so a runtime that is provisioned for FULL should keep
validating rather than idle until the feed returns.

The direction matters and is the whole security argument. thin -> FULL replaces
a trusted assertion with an independent recomputation, so being forced into it
is a fail-safe. FULL -> thin would let anyone able to break the evidence path
push the validator back onto trusting the publisher, so that transition stays
refused and is asserted here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scaffold import validator_thin as vt

FINNEY = vt.FINNEY_GENESIS_HASH
HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"


def _state(**over):
    base = {
        "submission_validator_hotkey": HOTKEY,
        "submission_genesis_hash": FINNEY,
        "provenance_netuid": 39,
    }
    base.update(over)
    return base


def _identity(**over):
    base = {
        "network": "finney",
        "netuid": 39,
        "validator_hotkey": HOTKEY,
        "operator_declared_authority": True,
    }
    base.update(over)
    return base


# -- the lane transition ----------------------------------------------------


def test_operator_declared_authority_authorizes_the_thin_to_full_transition():
    assert vt._authority_lane_transition_authorized(_state(), _identity()) is True


def test_fallback_transition_is_bound_to_this_validator_hotkey():
    # A reservation minted for one hotkey must not authorize another's lane
    # change, or a captured state file would be portable between wallets.
    other = _identity(
        validator_hotkey="5G3qVaXzKMPDm5AJ3dpzbpUC27kpccBvDwzSWXrq8M6qMmbC"
    )
    assert vt._authority_lane_transition_authorized(_state(), other) is False


def test_fallback_transition_is_bound_to_the_finney_genesis():
    state = _state(submission_genesis_hash="0x" + "ab" * 32)
    assert vt._authority_lane_transition_authorized(state, _identity()) is False


def test_fallback_transition_is_bound_to_netuid_39():
    assert (
        vt._authority_lane_transition_authorized(_state(), _identity(netuid=7)) is False
    )
    assert (
        vt._authority_lane_transition_authorized(
            _state(provenance_netuid=7), _identity()
        )
        is False
    )


def test_without_the_marker_the_launch_journal_is_still_required():
    # Absent the fallback marker this falls through to the ContinuousAuthorization
    # branch, which a beta runtime cannot satisfy. The waiver must not leak into
    # ordinary ticks.
    identity = _identity()
    identity.pop("operator_declared_authority")
    assert vt._authority_lane_transition_authorized(_state(), identity) is False


def test_a_falsey_marker_does_not_authorize():
    for value in (False, "true", 1, None):
        identity = _identity(operator_declared_authority=value)
        assert vt._authority_lane_transition_authorized(_state(), identity) is False


# -- provisioning gate ------------------------------------------------------


def test_full_is_not_considered_provisioned_without_controlled_evidence(tmp_path):
    verifier = tmp_path / "verifier"
    verifier.write_text("#!/bin/sh\n")
    args = SimpleNamespace(
        provenance_controlled_dir=None, provenance_verifier_binary=str(verifier)
    )
    assert vt._full_path_provisioned(args) is False


def test_full_is_not_considered_provisioned_without_a_present_verifier(tmp_path):
    args = SimpleNamespace(
        provenance_controlled_dir=str(tmp_path),
        provenance_verifier_binary=str(tmp_path / "absent"),
    )
    assert vt._full_path_provisioned(args) is False


def test_full_is_provisioned_when_both_inputs_exist(tmp_path):
    verifier = tmp_path / "verifier"
    verifier.write_text("#!/bin/sh\n")
    args = SimpleNamespace(
        provenance_controlled_dir=str(tmp_path),
        provenance_verifier_binary=str(verifier),
    )
    assert vt._full_path_provisioned(args) is True


# -- the classified failure -------------------------------------------------


def test_an_unreachable_publisher_is_classified_not_swallowed(monkeypatch):
    def boom(_url):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(vt, "fetch_vector", boom)
    args = SimpleNamespace(publisher_url="https://example.invalid")
    with pytest.raises(vt._FeedUnavailableForThin) as caught:
        vt._thin_tick_locked(args)
    # The type is what routes the fallback, and the cause is retained so the
    # operator log can still name the underlying transport failure.
    assert "ConnectionError" in str(caught.value)
    assert isinstance(caught.value.__cause__, ConnectionError)


def test_the_classified_failure_is_still_a_vector_error():
    # Callers that only know about VectorError must keep failing closed rather
    # than seeing an unfamiliar exception escape the tick.
    assert issubclass(vt._FeedUnavailableForThin, vt.wire.VectorError)


# -- who may declare authority ---------------------------------------------


def test_configuring_full_mode_counts_as_the_operators_declaration():
    # The fence exists to stop the lane changing SILENTLY. A config change is
    # not silent, so it is the explicit reconciliation the fence asks for.
    args = SimpleNamespace(beta_skip_launch_ceremony=True, provenance="authority")
    assert vt._operator_declared_authority(args) is True


def test_a_thin_runtime_does_not_declare_authority():
    args = SimpleNamespace(beta_skip_launch_ceremony=True, provenance="shadow")
    assert vt._operator_declared_authority(args) is False


def test_a_thin_runtime_that_lost_its_feed_does_declare_authority():
    args = SimpleNamespace(
        beta_skip_launch_ceremony=True,
        provenance="shadow",
        _feed_down_fallback_active=True,
    )
    assert vt._operator_declared_authority(args) is True


def test_without_the_beta_waiver_the_signed_authorization_is_still_required():
    # The reviewed production path is unchanged: no waiver, no shortcut.
    for mode in ("authority", "shadow"):
        args = SimpleNamespace(
            beta_skip_launch_ceremony=False,
            provenance=mode,
            _feed_down_fallback_active=True,
        )
        assert vt._operator_declared_authority(args) is False
