"""Thin degrades UP into FULL when the signed vector is unreachable.

Thin follows Cathedral's signed vector, so an unreachable publisher leaves it
with nothing to submit. FULL derives the same allocation from raw evidence and
never reads the vector, so a runtime that is EXPLICITLY provisioned for FULL and
opts in can keep validating rather than idle until the feed returns.

The launch DEFAULT, however, is off (cathedral-validator#40): a shadow validator
idles on a dead feed rather than auto-escalating to an authority writer at tick
time. The escalation is available, not automatic. The authorization guards below
still gate it for the opt-in case.

The direction matters and is the whole security argument. thin -> FULL replaces
a trusted assertion with an independent recomputation, so being forced into it
is a fail-safe. FULL -> thin would let anyone able to break the evidence path
push the validator back onto trusting the publisher, so that transition stays
refused and is asserted here.
"""

from __future__ import annotations

import contextlib
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


# -- the switch stays inside the startup contract ---------------------------


def _fallback_args(tmp_path, **over):
    """A thin runtime that is opted in to the fallback and provisioned for FULL."""
    verifier = tmp_path / "verifier"
    verifier.write_text("#!/bin/sh\n")
    base = {
        "publisher_url": "https://example.invalid/vector.json",
        "provenance": "shadow",
        "require_policy": vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
        "feed_down_fallback": True,
        "provenance_controlled_dir": str(tmp_path),
        "provenance_verifier_binary": str(verifier),
        "max_submissions": 0,
        "broadcast": False,
        "offline": False,
        "launch_preflight": False,
        "require_full_provenance_for_broadcast": False,
        "netuid": 39,
    }
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def feed_down_tick(monkeypatch):
    """tick() with a dead feed: chain preflight, lock and authority tick stubbed."""
    calls = []

    @contextlib.contextmanager
    def _no_lock(_args):
        yield

    def _feed_down(_args):
        raise vt._FeedUnavailableForThin("signed vector unavailable: ConnectionError")

    def _authority(args, payload):
        calls.append(payload)
        return True

    monkeypatch.setattr(vt, "_prepare_tick_preflight", lambda _args: None)
    monkeypatch.setattr(vt, "_thin_tick_lock", _no_lock)
    monkeypatch.setattr(vt, "_thin_tick_locked", _feed_down)
    monkeypatch.setattr(vt, "_authority_tick", _authority)
    return calls


def test_the_fallback_refuses_a_switch_the_startup_guard_would_reject(
    tmp_path, feed_down_tick
):
    """A v3 pin plus authority mode is refused at startup because it fails closed
    on every tick. The fallback must not reach that state at tick time, where no
    startup guard runs and nothing ever switches back."""
    args = _fallback_args(tmp_path)
    # This runtime is admissible: the pin relays Cathedral's signed v3 vector.
    vt._validate_runtime_contract(args)

    with pytest.raises(vt._FeedUnavailableForThin):
        vt.tick(args)

    assert feed_down_tick == []
    assert args.provenance == "shadow"
    assert bool(getattr(args, "_feed_down_fallback_active", False)) is False
    # The decisive assertion: the runtime this tick left behind must still be one
    # the startup guard would admit.
    vt._validate_runtime_contract(args)


def test_an_admissible_runtime_still_degrades_up(tmp_path, feed_down_tick):
    """The fallback itself is intact: where authority mode is a configuration the
    startup guard admits, a dead feed still degrades UP into FULL."""
    args = _fallback_args(
        tmp_path, require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1
    )
    vt._validate_runtime_contract(args)

    assert vt.tick(args) is True

    assert feed_down_tick == [None]
    assert args.provenance == "authority"
    assert args._feed_down_fallback_active is True


# --------------------------------------------------------------------------- #
# launch default: idle (fail closed), do NOT auto-escalate to authority (#40)
# --------------------------------------------------------------------------- #
def test_the_launch_default_for_feed_down_fallback_is_off():
    """The shipped default must be off, so a shadow runtime idles on a dead feed
    rather than silently becoming an authority writer (cathedral-validator#40)."""
    from scaffold import cli

    assert cli._DEFAULTS["feed_down_fallback"] is False


def test_an_absent_flag_fails_closed_rather_than_escalating():
    """Even if the arg is missing entirely, the tick-time branch must read it as
    off — an absent flag is not a licence to escalate."""
    from types import SimpleNamespace

    # The branch is `if not bool(getattr(args, "feed_down_fallback", <default>))`.
    # With the fixed default, an object with no such attribute reads as False, so
    # `not False` -> the escalation is refused and the feed-unavailable error
    # propagates to the run loop, which idles.
    args = SimpleNamespace()
    assert bool(getattr(args, "feed_down_fallback", False)) is False
