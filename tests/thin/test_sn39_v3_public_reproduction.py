"""A v3 SN39 run reproduces, and the pin now picks the lane it must match.

Two mechanical spots in the public reproducer were written against the launch
contract alone: the startup `policy_pin` was compared to one literal, and the
signed release's `reward_mechanism` was compared to one inline dict. Either one
turns a v3 (70% Intel TDX / 30% CyberGym / 0% fixed burn) run into an
unreproducible run — the worst possible outcome for a subnet whose whole claim
is that anyone can check the payout.

Widening them must not weaken a v1 reproduction, so the pin/lane relationship is
now a CROSS-CHECK rather than two independent facts. Before, the dry-run lane was
selected by the result's own `contract_version` stamp while the pin was compared
to a literal, so a v1-pinned run that emitted a v3 vector reproduced happily
under the v3 assertions. Now the pin selects the lane and the result's stamp has
to agree with it — strictly stricter than what it replaces, in both directions.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scaffold import sn39_public_reproduction as pr


# -- the resolved startup pin ------------------------------------------------


def _startup(**over):
    event = {
        "event": "STARTUP",
        "status": "INFO",
        "detail": "submission_authority=thin provenance=shadow",
        "policy_pin": "validated_supply_v1",
        **pr.EXPECTED_STARTUP,
    }
    event.update(over)
    return event


def _v2_dry_run(**over):
    burn_uid = 0
    event = {
        "event": "WEIGHTS_DRY_RUN",
        "status": "PASS",
        "authority": "thin",
        "uid_count": 2,
        "burn_uid": burn_uid,
        "burn_share": 0.1,
        "uid_weights": {"0": 0.1, "12": 0.9},
        "wire_uids": [0, 12],
        "wire_weights": [pr.WIRE_BURN_U16, pr.WIRE_VALIDATED_SUPPLY_U16],
        "version_key": pr.EXPECTED_VERSION_KEY,
        "mapping_block": 5_000_000,
        "validator_uid": 7,
        "validator_hotkey": "5Validator",
    }
    event.update(over)
    return event


def _v3_dry_run(**over):
    event = {
        "event": "WEIGHTS_DRY_RUN",
        "status": "PASS",
        "authority": "thin",
        "contract_version": "validated_supply_v3",
        "burn_share": 0.0,
        "intel_tdx_share": 0.70,
        "cybergym_share": 0.30,
        "uid_weights": {"12": 0.42, "13": 0.28, "50": 0.20, "51": 0.10},
        "mapping_block": 5_000_000,
        "validator_uid": 7,
        "validator_hotkey": "5Validator",
    }
    event.update(over)
    return event


def _stream(tmp_path, startup, dry_run):
    events = [
        startup,
        dry_run,
        {"event": "PROVENANCE_AUDIT_PASS", "status": "PASS", "vector_agrees": True},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    return path


def test_v1_pinned_run_still_reproduces_the_launch_lane(tmp_path):
    summary = pr.assert_current_dry_run(
        _stream(tmp_path, _startup(), _v2_dry_run()),
    )
    assert summary["burn_share"] == "0.10"
    assert summary["current_dry_run"] == "PASS"


def test_v3_pinned_run_reproduces_the_70_30_0_lane(tmp_path):
    summary = pr.assert_current_dry_run(
        _stream(
            tmp_path,
            _startup(policy_pin="validated_supply_v3"),
            _v3_dry_run(),
        ),
    )
    assert summary["burn_share"] == "0.00"
    assert summary["current_dry_run"] == "PASS"


@pytest.mark.parametrize(
    "pin",
    ["validated_supply_v2", "confidential_primary_v1", "", None, "VALIDATED_SUPPLY_V3"],
)
def test_a_third_policy_pin_still_does_not_reproduce(tmp_path, pin):
    """Membership is a CLOSED set of two, not "anything validated_supply"."""
    with pytest.raises(pr.ReproductionError, match="policy_pin"):
        pr.assert_current_dry_run(
            _stream(tmp_path, _startup(policy_pin=pin), _v3_dry_run()),
        )


def test_v1_pin_with_a_v3_result_is_now_refused(tmp_path):
    """The cross-check that is STRICTER than the code it replaces.

    Previously the lane was chosen by the result's own stamp, so this stream
    reproduced under the v3 assertions while claiming the v1 pin. A run whose
    pin and payout disagree is exactly the thing a reproducer exists to catch.
    """
    with pytest.raises(pr.ReproductionError, match="does not match the resolved"):
        pr.assert_current_dry_run(
            _stream(tmp_path, _startup(), _v3_dry_run()),
        )


def test_v3_pin_with_the_launch_result_is_refused(tmp_path):
    with pytest.raises(pr.ReproductionError, match="does not match the resolved"):
        pr.assert_current_dry_run(
            _stream(
                tmp_path,
                _startup(policy_pin="validated_supply_v3"),
                _v2_dry_run(),
            ),
        )


def test_v3_lane_shares_are_still_checked(tmp_path):
    """Admitting the pin does not admit a different split under it."""
    with pytest.raises(pr.ReproductionError, match="70/30/0"):
        pr.assert_current_dry_run(
            _stream(
                tmp_path,
                _startup(policy_pin="validated_supply_v3"),
                _v3_dry_run(intel_tdx_share=0.90, cybergym_share=0.10),
            ),
        )


def test_v3_lane_still_refuses_a_nonzero_burn(tmp_path):
    with pytest.raises(pr.ReproductionError, match="70/30/0"):
        pr.assert_current_dry_run(
            _stream(
                tmp_path,
                _startup(policy_pin="validated_supply_v3"),
                _v3_dry_run(burn_share=0.10),
            ),
        )


def test_every_other_startup_pin_is_still_flat_equality(tmp_path):
    """Only `policy_pin` is exempt from flat equality — and it is still listed.

    It stays in EXPECTED_STARTUP so the table remains a complete description of
    a valid STARTUP event (anything building a fixture from it gets the launch
    pin); what changed is only that its comparison is the closed membership in
    EXPECTED_STARTUP_POLICY_PINS rather than one literal.
    """
    assert pr.EXPECTED_STARTUP["policy_pin"] == "validated_supply_v1"
    assert pr.EXPECTED_STARTUP["policy_pin"] in pr.EXPECTED_STARTUP_POLICY_PINS
    with pytest.raises(pr.ReproductionError, match="provenance_mechanism"):
        pr.assert_current_dry_run(
            _stream(
                tmp_path,
                _startup(
                    policy_pin="validated_supply_v3",
                    provenance_mechanism="validated_supply_v3",
                ),
                _v3_dry_run(),
            ),
        )


def test_admitted_startup_pins_are_exactly_the_two_named_contracts():
    assert pr.EXPECTED_STARTUP_POLICY_PINS == (
        "validated_supply_v1",
        "validated_supply_v3",
    )


# -- the signed release's reward mechanism ------------------------------------


def _sign(release: dict) -> tuple[bytes, bytes, dict[str, str]]:
    release_bytes = json.dumps(release, sort_keys=True, separators=(",", ":")).encode()
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key().public_bytes_raw()
    signature = {
        "algorithm": "Ed25519",
        "key_id": pr.RELEASE_KEY_ID,
        "payload": "release.json exact bytes",
        "payload_sha256": "sha256:" + hashlib.sha256(release_bytes).hexdigest(),
        "signature": base64.b64encode(private.sign(release_bytes)).decode(),
    }
    signature_bytes = json.dumps(
        signature, sort_keys=True, separators=(",", ":")
    ).encode()
    return (
        release_bytes,
        signature_bytes,
        {pr.RELEASE_KEY_ID: base64.b64encode(public).decode()},
    )


REVISION = "0" * 40


def _release(mechanism: dict) -> dict:
    return {
        "schema": pr.RELEASE_SCHEMA,
        "network": "finney",
        "netuid": 39,
        "validated_capability": "intel_tdx_cpu",
        "submission_authority_default": "thin",
        "full_provenance_mode": "concurrent_shadow",
        "claim": "SN39 mainnet: validated Intel TDX CPU compute.",
        "reproducer_revision": REVISION,
        "release_attestation": {"key_id": pr.RELEASE_KEY_ID},
        "reward_mechanism": mechanism,
        "source_revisions": {"producer": "deliberately-wrong"},
        "pins": {},
        "attested_submission": {},
    }


def _verify(mechanism: dict):
    release_bytes, signature_bytes, public_keys = _sign(_release(mechanism))
    return pr.verify_release_bytes(
        release_bytes,
        signature_bytes,
        public_keys=public_keys,
        repo_revision=REVISION,
    )


@pytest.mark.parametrize("mechanism_id", ["validated_supply_v1", "validated_supply_v3"])
def test_both_admitted_mechanisms_clear_the_reward_mechanism_check(mechanism_id):
    """Getting past the mechanism check is the whole assertion here.

    The release then fails on `source_revisions`, which is deliberate: these
    fixtures are not real signed releases, and the attested_submission block is
    still bound to the immutable 2-UID 90/10 launch extrinsic (out of scope for
    this change). What matters is WHICH refusal fires.
    """
    with pytest.raises(pr.ReproductionError, match="source revisions") as raised:
        _verify(dict(pr.EXPECTED_RELEASE_REWARD_MECHANISMS[mechanism_id]))
    assert "reward mechanism" not in str(raised.value)


def test_the_v1_mechanism_literal_is_unchanged():
    """A v1 release is held to precisely the same object as before."""
    assert pr.EXPECTED_RELEASE_REWARD_MECHANISMS["validated_supply_v1"] == {
        "id": "validated_supply_v1",
        "revision": 1,
        "validated_supply_share": 0.9,
        "burn_share": 0.1,
        "wire_quantization": {
            "weights_u16": [pr.WIRE_VALIDATED_SUPPLY_U16, pr.WIRE_BURN_U16],
            "effective_validated_supply_share": pr.WIRE_VALIDATED_SUPPLY_SHARE,
            "effective_burn_share": pr.WIRE_BURN_SHARE,
        },
    }


def test_the_v3_mechanism_is_the_70_30_0_split():
    assert pr.EXPECTED_RELEASE_REWARD_MECHANISMS["validated_supply_v3"] == {
        "id": "validated_supply_v3",
        "revision": 1,
        "intel_tdx_share": 0.70,
        "cybergym_share": 0.30,
        "burn_share": 0.0,
    }


@pytest.mark.parametrize(
    "mechanism",
    [
        # An unknown id has no expected shape at all.
        {"id": "validated_supply_v2", "revision": 1, "burn_share": 0.1},
        # A v3 id may not borrow the v1 shape...
        {
            "id": "validated_supply_v3",
            "revision": 1,
            "validated_supply_share": 0.9,
            "burn_share": 0.1,
        },
        # ...nor may a v1 id claim the v3 split.
        {
            "id": "validated_supply_v1",
            "revision": 1,
            "intel_tdx_share": 0.70,
            "cybergym_share": 0.30,
            "burn_share": 0.0,
        },
        # A single moved share is still a different economy.
        {
            "id": "validated_supply_v3",
            "revision": 1,
            "intel_tdx_share": 0.80,
            "cybergym_share": 0.20,
            "burn_share": 0.0,
        },
        # A v3 release may not quietly reintroduce a fixed burn.
        {
            "id": "validated_supply_v3",
            "revision": 1,
            "intel_tdx_share": 0.70,
            "cybergym_share": 0.30,
            "burn_share": 0.05,
        },
        # A revision bump is a new contract, not a compatible one.
        {
            "id": "validated_supply_v3",
            "revision": 2,
            "intel_tdx_share": 0.70,
            "cybergym_share": 0.30,
            "burn_share": 0.0,
        },
        # Extra keys are not tolerated: equality is whole-object.
        {
            "id": "validated_supply_v3",
            "revision": 1,
            "intel_tdx_share": 0.70,
            "cybergym_share": 0.30,
            "burn_share": 0.0,
            "gpu_share": 0.0,
        },
        # A malformed id must refuse rather than raise on an unhashable key.
        {"id": {"nested": "object"}, "revision": 1},
        {"id": None},
    ],
)
def test_a_mechanism_outside_the_table_does_not_reproduce(mechanism):
    with pytest.raises(pr.ReproductionError, match="reward mechanism differs"):
        _verify(mechanism)


def test_the_pin_set_is_derived_from_the_lane_table_so_they_cannot_drift():
    """One closed set, not two.

    A pin admitted by the membership check but missing from the lane table
    would raise an uncaught KeyError out of the public reproducer instead of a
    ReproductionError, so the tuple is derived from the table's keys rather
    than maintained beside it.
    """
    assert pr.EXPECTED_STARTUP_POLICY_PINS == tuple(
        pr._PIN_TO_DRY_RUN_CONTRACT_VERSION
    )
    for pin in pr.EXPECTED_STARTUP_POLICY_PINS:
        assert pin in pr._PIN_TO_DRY_RUN_CONTRACT_VERSION
