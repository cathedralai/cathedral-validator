"""The SN39 immutable trust profile admits exactly two weight policies.

The profile is what stops a tampered config from redirecting mainnet weights:
every field is compared to one pinned literal, so a config that differs anywhere
cannot broadcast. Rolling SN39 from the launch contract (90% validated supply /
10% burn) to v3 (70% Intel TDX / 30% CyberGym / 0% fixed burn) needs exactly one
of those fields to admit a second value, and nothing else.

These tests hold that line from both directions. The widened field must accept
validated_supply_v3 and refuse anything that is not one of the two named
contracts — including confidential_primary_v1, which is a legitimate CLI pin on
other subnets but is not an SN39 mainnet posture. Every other field must still
be refused the moment it is altered by a single character.

They also cover the two places the same contract is re-asked, because widening
the startup profile alone would have been worse than not widening it at all:

  * the resolved-chain contract, which re-checks the pin against the connected
    chain rather than the config's label. Left strict, a v3 config would clear
    startup and then die at chain preflight on every tick — a validator that
    starts cleanly and never writes.

  * the continuous-authorization obligation, which asks "is this an SN39
    mainnet posture?" and answered it by testing for the v1 pin. Left strict, a
    re-pin to v3 would have SILENTLY DROPPED the obligation: a real weakening
    bought with a one-word config change.

Finally, the guard refusing require_policy=validated_supply_v3 together with
provenance=authority is re-proven here. It already had a test, but that test
lives in the advisory publisher suite, which does not gate CI; the guard is what
keeps a v3 operator from configuring a validator that starts, fails closed on
every tick, and goes dark with no single loud reason.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as vt


def _profile_args(**over):
    """A config that satisfies the SN39 mainnet trust profile exactly."""
    base = {
        "max_submissions": 0,
        "broadcast": True,
        "offline": False,
        "netuid": 39,
        "network": "finney",
        "publisher_url": vt.SN39_PUBLISHER_URL,
        "public_key_hex": vt.DEFAULT_PUBLIC_KEY_HEX,
        "key_id": vt.SN39_WEIGHT_POLICY_KEY_ID,
        "require_policy": vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        "evidence_url": vt.SN39_EVIDENCE_URL,
        "provenance_registry_keys_digest": vt.SN39_REGISTRY_KEYS_DIGEST,
        "provenance_report_keys_digest": vt.SN39_REPORT_KEYS_DIGEST,
        "provenance_index_keys_digest": vt.SN39_INDEX_KEYS_DIGEST,
        "provenance_verifier_digest": vt.SN39_VERIFIER_DIGEST,
        "provenance_source_revision": vt.SN39_PRODUCER_REVISION,
        "provenance_mechanism": vt.MECHANISM_DEFAULT,
        "provenance_burn_hotkey": vt.SN39_BURN_HOTKEY,
        "state_file": str(vt.SN39_STATE_FILE),
        "provenance": "shadow",
        "runtime_root": None,
        "launch_preflight": False,
        "require_full_provenance_for_broadcast": False,
        # Satisfies the completed-launch gate without touching any pinned
        # field, so a mismatch reported below is always the field under test.
        "require_completed_launch_for_broadcast": True,
        "beta_skip_launch_ceremony": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _preflight(**over):
    base = {
        "wallet": object(),
        "subtensor": object(),
        "hotkey_to_uid": {vt.SN39_BURN_HOTKEY: 0, "validator-hotkey": 1},
        "validator_hotkey": "validator-hotkey",
        "validator_uid": 1,
        "block": 5_000_000,
        "min_allowed_weights": 1,
        "max_weight_limit": 1.0,
        "commit_reveal_enabled": False,
        "genesis_hash": vt.FINNEY_GENESIS_HASH,
        "subnet_owner_hotkey": vt.SN39_BURN_HOTKEY,
    }
    base.update(over)
    return vt.ChainPreflight(**base)


@pytest.fixture
def no_launch_material(monkeypatch, tmp_path):
    """Point the launch-material probes at paths that do not exist.

    `_sn39_launch_obligation` returns True for any host holding launch
    material, which short-circuits `_continuous_transition_required` before it
    ever consults the policy pin. Redirecting the probes keeps the pin-fallback
    branch reachable and keeps the result independent of the host running the
    suite.
    """
    for name in (
        "SN39_LAUNCH_CONTROLLED_DIR",
        "SN39_LAUNCH_VERIFIER_BINARY",
        "SN39_LAUNCH_APPROVAL_FILE",
    ):
        monkeypatch.setattr(vt, name, tmp_path / "absent" / name.lower())


# --------------------------------------------------------------------------
# The widened field
# --------------------------------------------------------------------------


def test_v1_pin_still_satisfies_the_trust_profile() -> None:
    """The launch pin is untouched: it passes exactly as it did before."""
    vt._validate_runtime_contract(_profile_args())


def test_v3_pin_satisfies_the_trust_profile() -> None:
    """A v3 re-pin is now a broadcastable SN39 posture."""
    vt._validate_runtime_contract(
        _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3)
    )


@pytest.mark.parametrize(
    "policy",
    [
        # A plausible-looking third economy.
        "validated_supply_v2",
        # A real REQUIRE_POLICY_CHOICES value that is not an SN39 posture.
        vt.REQUIRE_POLICY_CONFIDENTIAL_PRIMARY_V1,
        # Case and whitespace are not normalised for this field.
        "VALIDATED_SUPPLY_V3",
        " validated_supply_v3",
        "validated_supply_v3 ",
        "",
        None,
    ],
)
def test_third_policy_value_is_still_refused(policy) -> None:
    """Membership is a CLOSED set of two, not "any validated_supply"."""
    with pytest.raises(vt.wire.VectorError, match="require_policy"):
        vt._validate_runtime_contract(_profile_args(require_policy=policy))


def test_admitted_policy_set_is_exactly_the_two_named_contracts() -> None:
    """A third entry here is a change to the mainnet economy, not a refactor."""
    assert vt.SN39_PINNED_REQUIRE_POLICIES == (
        "validated_supply_v1",
        "validated_supply_v3",
    )


# --------------------------------------------------------------------------
# Everything else in the profile stays single-equality strict
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("network", "test"),
        ("publisher_url", "https://api.cathedral.computer.evil.test"),
        ("public_key_hex", "0" * 64),
        ("key_id", "cathedral-weight-policy-2"),
        ("evidence_url", "https://api.cathedral.computer/v1/evidence2"),
        ("provenance_registry_keys_digest", "sha256:" + "0" * 64),
        ("provenance_report_keys_digest", "sha256:" + "0" * 64),
        ("provenance_index_keys_digest", "sha256:" + "0" * 64),
        ("provenance_verifier_digest", "sha256:" + "0" * 64),
        ("provenance_source_revision", "0" * 40),
        ("provenance_mechanism", "validated_supply_v3"),
        ("provenance_burn_hotkey", "5" + "H" * 47),
        ("state_file", "/tmp/thin-state.json"),
        ("provenance", "audit"),
    ],
)
@pytest.mark.parametrize(
    "policy",
    [
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
    ],
)
def test_every_other_pinned_field_is_still_refused_when_altered(
    field, tampered, policy
) -> None:
    """Widening one field must not have loosened its neighbours, under EITHER pin."""
    with pytest.raises(vt.wire.VectorError, match=field):
        vt._validate_runtime_contract(
            _profile_args(require_policy=policy, **{field: tampered})
        )


def test_provenance_mechanism_stays_pinned_to_v1_under_a_v3_policy() -> None:
    """The mechanism selects the BURN contract, so it is not part of this roll.

    `MECHANISM_ACCEPTED` already admits v2/v3 evidence under a v1 mechanism pin,
    and `MECHANISM_BURN_FRACTION` is looked up by the operator's own pin rather
    than by the id a manifest claims. Widening evidence admission therefore
    cannot move the burn — and widening the mechanism pin here would have.
    """
    assert vt.MECHANISM_DEFAULT == "validated_supply_v1"
    assert "validated_supply_v3" not in vt.MECHANISM_BURN_FRACTION
    vt._validate_runtime_contract(
        _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3)
    )


def test_non_canonical_runtime_root_is_still_refused_under_a_v3_pin() -> None:
    with pytest.raises(vt.wire.VectorError, match="canonical owner-only"):
        vt._validate_runtime_contract(
            _profile_args(
                require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
                runtime_root="/tmp/cathedral-validator",
            )
        )


# --------------------------------------------------------------------------
# The PR #45 guard: v3 + authority is still refused
# --------------------------------------------------------------------------


def test_v3_pin_with_authority_provenance_is_still_refused_at_startup() -> None:
    """A v3 pin is a RELAY posture; authority mode never applies the signed v3
    vector, so every tick fails closed and the validator goes dark silently.

    This guard predates the widening and must survive it. It fires before any
    profile check, so it applies to an offline or non-SN39 runtime too.
    """
    with pytest.raises(
        vt.wire.VectorError, match="incompatible with provenance=authority"
    ):
        vt._validate_runtime_contract(
            _profile_args(
                require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
                provenance="authority",
            )
        )


def test_v3_authority_guard_fires_even_off_the_sn39_profile() -> None:
    with pytest.raises(
        vt.wire.VectorError, match="incompatible with provenance=authority"
    ):
        vt._validate_runtime_contract(
            SimpleNamespace(
                require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
                provenance="authority",
                max_submissions=0,
                broadcast=False,
                offline=True,
                netuid=39,
            )
        )


def test_v1_pin_with_authority_provenance_is_unaffected() -> None:
    """authority is a valid v1 posture; the widening must not have changed that."""
    vt._validate_runtime_contract(_profile_args(provenance="authority"))


# --------------------------------------------------------------------------
# The same contract, re-asked before the feed-down switch
# --------------------------------------------------------------------------


def test_the_feed_down_switch_is_held_to_this_profile() -> None:
    """A dead publisher must not buy a runtime the posture its config was refused.

    The switch is one-way and happens after startup, so without this the guard
    above only covers configs an operator wrote down, not the one the process
    ends up running.
    """
    args = _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3)
    vt._validate_runtime_contract(args)
    refusal = vt._feed_down_switch_refusal(args)
    assert refusal is not None
    assert "incompatible with provenance=authority" in refusal


def test_the_feed_down_switch_still_serves_a_gated_v1_runtime() -> None:
    """The fallback stays available where authority is an admissible posture."""
    assert vt._feed_down_switch_refusal(_profile_args()) is None


def test_the_feed_down_switch_does_not_hand_out_the_completed_launch_gate(
    no_launch_material,
) -> None:
    """Escalating makes the runtime originate weights, which is the capability
    the completed-launch gate protects. An ungated relay stays thin."""
    args = _profile_args(require_completed_launch_for_broadcast=False)
    vt._validate_runtime_contract(args)
    assert "completed-launch gate" in str(vt._feed_down_switch_refusal(args))


# --------------------------------------------------------------------------
# The same contract, re-asked against the resolved chain
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy",
    [
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
    ],
)
def test_resolved_chain_contract_accepts_both_admitted_pins(policy) -> None:
    """Both pins must clear chain preflight, or a v3 validator never writes."""
    vt._validate_resolved_chain_contract(
        _profile_args(require_policy=policy), _preflight()
    )


@pytest.mark.parametrize("policy", ["validated_supply_v2", "confidential_primary_v1"])
def test_resolved_chain_contract_still_refuses_a_third_pin(policy) -> None:
    with pytest.raises(vt.wire.VectorError, match="validated_supply_v1 or"):
        vt._validate_resolved_chain_contract(
            _profile_args(require_policy=policy), _preflight()
        )


def test_resolved_chain_contract_still_refuses_a_foreign_genesis_under_v3() -> None:
    """The other resolved-chain invariants are untouched by the widening."""
    with pytest.raises(vt.wire.VectorError, match="pinned Finney genesis"):
        vt._validate_resolved_chain_contract(
            _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3),
            _preflight(genesis_hash="0x" + "b" * 64),
        )


def test_resolved_chain_contract_still_requires_the_pinned_burn_owner_under_v3() -> (
    None
):
    with pytest.raises(vt.wire.VectorError, match="pinned burn hotkey"):
        vt._validate_resolved_chain_contract(
            _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3),
            _preflight(subnet_owner_hotkey="5" + "H" * 47),
        )


def test_resolved_chain_contract_still_refuses_commit_reveal_under_v3() -> None:
    with pytest.raises(vt.wire.VectorError, match="commit-reveal disabled"):
        vt._validate_resolved_chain_contract(
            _profile_args(require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3),
            _preflight(commit_reveal_enabled=True),
        )


# --------------------------------------------------------------------------
# The continuous-authorization obligation survives the re-pin
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy",
    [
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
    ],
)
def test_continuous_transition_is_required_under_both_admitted_pins(
    policy, no_launch_material
) -> None:
    """The obligation follows the SN39 posture, not the launch contract.

    Both admitted pins are that posture. Left as an equality test on v1, a
    one-word config change to v3 would have dropped the obligation with nothing
    reporting it.
    """
    args = _profile_args(
        require_policy=policy, require_completed_launch_for_broadcast=None
    )
    assert vt._sn39_launch_obligation(args) is False
    assert vt._continuous_transition_required(args) is True


def test_continuous_transition_not_required_for_a_non_sn39_pin(
    no_launch_material,
) -> None:
    """The fallback still says "no" for a posture that is not SN39 mainnet."""
    args = _profile_args(
        require_policy=vt.REQUIRE_POLICY_CONFIDENTIAL_PRIMARY_V1,
        require_completed_launch_for_broadcast=None,
    )
    assert vt._continuous_transition_required(args) is False


def test_explicit_operator_choice_still_wins_over_the_pin(no_launch_material) -> None:
    args = _profile_args(
        require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
        require_completed_launch_for_broadcast=False,
    )
    assert vt._continuous_transition_required(args) is False


def test_launch_material_still_forces_the_obligation_under_v3(monkeypatch) -> None:
    """Branch 1 is unreachable from config, under either pin."""
    monkeypatch.setattr(vt, "_sn39_launch_obligation", lambda _args: True)
    args = _profile_args(
        require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
        require_completed_launch_for_broadcast=False,
    )
    assert vt._continuous_transition_required(args) is True


# --------------------------------------------------------------------------
# The allocation gate itself stays strict
# --------------------------------------------------------------------------


def test_v1_pin_still_rejects_a_v3_contract_vector() -> None:
    """The roll stays a deliberate, coordinated re-pin.

    Widening the trust profile lets an operator CHOOSE v3. It must not let a
    publisher flip the allocation under a validator that is still pinned to v1
    — that refusal is the whole reason the pin exists.
    """
    payload = {
        "burn_snapshot": {"burn_hotkey": "burn-hotkey", "forced_burn_percentage": 0.0},
        "policy_metadata": {
            "validated_supply": {
                "contract_version": "v3",
                "intel_tdx_allocation": 0.70,
                "cybergym_allocation": 0.30,
                "fixed_burn_allocation": 0.0,
                "burn_hotkey": "burn-hotkey",
            }
        },
    }
    with pytest.raises(vt.wire.VectorError, match="rejects contract_version 'v3'"):
        vt.vector_to_uid_weights(
            payload,
            {"burn-hotkey": 0},
            require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        )


def test_state_file_pin_is_compared_as_a_path_not_a_string() -> None:
    """A trailing-slash or dot-segment spelling of the pinned path still passes."""
    vt._validate_runtime_contract(
        _profile_args(
            require_policy=vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
            state_file=str(Path(vt.SN39_STATE_FILE.parent) / "." / "thin-state.json"),
        )
    )
