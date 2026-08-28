"""Internal authority-labelled journal helpers remain bounded to launch recovery."""

from __future__ import annotations

from types import SimpleNamespace

from scaffold import validator_thin as vt


FINNEY = vt.FINNEY_GENESIS_HASH
HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"


def _state(**over):
    state = {
        "submission_validator_hotkey": HOTKEY,
        "submission_genesis_hash": FINNEY,
        "provenance_netuid": 39,
    }
    state.update(over)
    return state


def _identity(**over):
    identity = {
        "network": "finney",
        "netuid": 39,
        "validator_hotkey": HOTKEY,
        "operator_declared_authority": True,
    }
    identity.update(over)
    return identity


def test_launch_lane_transition_is_bound_to_signer_chain_and_netuid() -> None:
    assert vt._authority_lane_transition_authorized(_state(), _identity()) is True
    assert (
        vt._authority_lane_transition_authorized(
            _state(),
            _identity(
                validator_hotkey="5G3qVaXzKMPDm5AJ3dpzbpUC27kpccBvDwzSWXrq8M6qMmbC"
            ),
        )
        is False
    )
    assert (
        vt._authority_lane_transition_authorized(
            _state(submission_genesis_hash="0x" + "ab" * 32), _identity()
        )
        is False
    )
    assert (
        vt._authority_lane_transition_authorized(_state(), _identity(netuid=7)) is False
    )


def test_launch_lane_transition_requires_the_exact_boolean_marker() -> None:
    for value in (False, "true", 1, None):
        assert (
            vt._authority_lane_transition_authorized(
                _state(), _identity(operator_declared_authority=value)
            )
            is False
        )


def test_internal_authority_declaration_requires_the_launch_waiver() -> None:
    assert (
        vt._operator_declared_authority(
            SimpleNamespace(beta_skip_launch_ceremony=True, provenance="authority")
        )
        is True
    )
    assert (
        vt._operator_declared_authority(
            SimpleNamespace(beta_skip_launch_ceremony=False, provenance="authority")
        )
        is False
    )
    assert (
        vt._operator_declared_authority(
            SimpleNamespace(beta_skip_launch_ceremony=True, provenance="shadow")
        )
        is False
    )
