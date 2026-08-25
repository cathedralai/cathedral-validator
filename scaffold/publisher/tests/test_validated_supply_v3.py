"""Validator-side contract tests for the v3 (70/30/0) allocation policy.

Covers:
  * ``_validated_supply_meta`` acceptance of contract_version v3 and rejection of
    drift (wrong shares, wrong fixed-burn percentage, missing fields);
  * ``vector_to_uid_weights`` v3 routing (unpinned + v3-pinned), the 70% Intel
    TDX / 30% CyberGym split, forfeited/ineligible lane mass sinking to burn, and
    the sum-to-1.0 invariant;
  * fail-closed behavior: a v1-pinned validator REJECTS a v3 vector, v2 still
    requires 10% fixed burn, and authority/FULL mode refuses v3;
  * provenance acceptance-set widening (MECHANISM_ACCEPTED);
  * the sn39 public-reproduction v3 dry-run acceptance helper;
  * a cross-repo round trip: the vendored publisher composes a real signed v3
    vector and the validator independently maps it to UID weights.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pytest

from scaffold import provenance_audit, validator_thin
from scaffold import sn39_public_reproduction as repro

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
V3_PIN = validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V3
V1_PIN = validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V1


def _cp_block(*, mass: float) -> dict:
    positive = mass == 1.0
    return {
        "contract_version": "v1",
        "mode": "confidential_primary",
        "source": "cathedral_confidential_tdx",
        "base_mass": 0.0,
        "confidential_mass": mass,
        "complete": positive,
        "fresh": positive,
        "confirmed": True,
    }


def _tdx_rows(rows: list[tuple[str, float]]) -> list[dict]:
    return [
        {
            "miner_hotkey": hk,
            "weight": w,
            "base_component": 0.0,
            "external_component": w,
        }
        for hk, w in rows
    ]


def v3_payload(
    *,
    tdx_rows: list[tuple[str, float]] | None = None,
    tdx_mass: float = 1.0,
    lane_weights: dict[int, float] | None = None,
    forfeited: float = 0.0,
    lane_burn_uid: int | None = None,
    burn_hotkey: str = "burn-hotkey",
    fixed_burn_pct: float = 0.0,
) -> dict:
    tdx_rows = tdx_rows if tdx_rows is not None else [("tdx-a", 0.6), ("tdx-b", 0.4)]
    lane_weights = lane_weights if lane_weights is not None else {50: 0.18, 51: 0.12}
    lane_hotkeys = {uid: f"cyber-{uid}" for uid in lane_weights}
    lane_hotkeys.update({50: "cyber-a", 51: "cyber-b"})
    if 0 in lane_weights:
        lane_hotkeys[0] = burn_hotkey
    return {
        "weights": _tdx_rows(tdx_rows),
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": burn_hotkey,
            "forced_burn_percentage": fixed_burn_pct,
        },
        "policy_metadata": {
            "confidential_primary": _cp_block(mass=tdx_mass),
            "validated_supply": {
                "contract_version": "v3",
                "intel_tdx_allocation": 0.70,
                "cybergym_allocation": 0.30,
                "fixed_burn_allocation": 0.0,
                "burn_hotkey": burn_hotkey,
            },
            "cybergym_lane": {
                "fraction": 0.30,
                "weights": {str(u): w for u, w in lane_weights.items()},
                "contributing_fraction": 0.30 - forfeited,
                "forfeited_fraction": forfeited,
                "burn_uid": lane_burn_uid,
                "uid_hotkeys": {str(uid): lane_hotkeys[uid] for uid in lane_weights},
                "cybergym": {"reason": "ok"},
            },
        },
    }


# ---- metadata contract -------------------------------------------------------


def test_v3_metadata_accepted() -> None:
    policy = validator_thin._validated_supply_meta(v3_payload())
    assert policy["contract_version"] == "v3"
    assert policy["intel_tdx_allocation"] == 0.70
    assert policy["cybergym_allocation"] == 0.30
    assert policy["fixed_burn_allocation"] == 0.0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("intel_tdx_allocation", 0.69, "allocation must be 0.70/0.30"),
        ("cybergym_allocation", 0.31, "allocation must be 0.70/0.30"),
        ("fixed_burn_allocation", 0.10, "fixed burn allocation must equal 0.0"),
    ],
)
def test_v3_metadata_share_drift_fails_closed(field, value, message) -> None:
    doc = v3_payload()
    doc["policy_metadata"]["validated_supply"][field] = value
    with pytest.raises(validator_thin.wire.VectorError, match=message):
        validator_thin._validated_supply_meta(doc)


def test_v3_requires_zero_fixed_burn() -> None:
    doc = v3_payload(fixed_burn_pct=10.0)
    with pytest.raises(validator_thin.wire.VectorError, match="must burn 0%"):
        validator_thin._validated_supply_meta(doc)


def test_v3_metadata_field_set_is_exact() -> None:
    doc = v3_payload()
    doc["policy_metadata"]["validated_supply"]["extra"] = 1
    with pytest.raises(validator_thin.wire.VectorError, match="fields mismatch"):
        validator_thin._validated_supply_meta(doc)


def test_v2_still_requires_ten_percent_burn() -> None:
    # A v2 contract with 0% fixed burn must still be rejected (v2 unchanged).
    doc = {
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": "burn-hotkey",
            "forced_burn_percentage": 0.0,
        },
        "policy_metadata": {
            "validated_supply": {
                "contract_version": "v2",
                "intel_tdx_allocation": 0.90,
                "fixed_burn_allocation": 0.10,
                "burn_hotkey": "burn-hotkey",
            }
        },
    }
    with pytest.raises(validator_thin.wire.VectorError, match="must burn 10%"):
        validator_thin._validated_supply_meta(doc)


# ---- uid-weight mapping ------------------------------------------------------

H2U = {"burn-hotkey": 0, "tdx-a": 10, "tdx-b": 11, "cyber-a": 50, "cyber-b": 51}


def test_v3_maps_70_30_split() -> None:
    out = validator_thin.vector_to_uid_weights(v3_payload(), H2U, require_policy=V3_PIN)
    assert out[10] == pytest.approx(0.42)  # 0.6 * 0.70
    assert out[11] == pytest.approx(0.28)  # 0.4 * 0.70
    assert out[50] == pytest.approx(0.18)  # cybergym lane
    assert out[51] == pytest.approx(0.12)
    assert 0 not in out  # no forfeited mass -> burn receives nothing
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


def test_v3_cybergym_forfeit_sinks_to_burn() -> None:
    doc = v3_payload(lane_weights={0: 0.30}, forfeited=0.30, lane_burn_uid=0)
    out = validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)
    assert out[10] == pytest.approx(0.42)
    assert out[11] == pytest.approx(0.28)
    assert out[0] == pytest.approx(0.30)  # whole CyberGym lane forfeited to burn
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


def test_v3_tdx_degraded_sinks_seventy_to_burn() -> None:
    doc = v3_payload(tdx_rows=[], tdx_mass=0.0)
    out = validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)
    assert out[50] == pytest.approx(0.18)
    assert out[51] == pytest.approx(0.12)
    assert out[0] == pytest.approx(0.70)  # revoked TDX lane sinks to burn
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


# ---- v3 CyberGym-idle redirect (N=0 -> compute) ------------------------------


def _v3_idle_payload() -> dict:
    """A v3 vector for a tick where CyberGym has no winners: the honest 100/0 split
    with an EMPTY cybergym_lane (same wire fields, all zero)."""
    doc = v3_payload()
    doc["policy_metadata"]["validated_supply"]["intel_tdx_allocation"] = 1.0
    doc["policy_metadata"]["validated_supply"]["cybergym_allocation"] = 0.0
    doc["policy_metadata"]["cybergym_lane"] = {
        "fraction": 0.0,
        "weights": {},
        "contributing_fraction": 0.0,
        "forfeited_fraction": 0.0,
        "burn_uid": None,
        "uid_hotkeys": {},
        "cybergym": {"reason": "no_contribution"},
    }
    return doc


def test_v3_idle_metadata_accepted() -> None:
    policy = validator_thin._validated_supply_meta(_v3_idle_payload())
    assert policy["intel_tdx_allocation"] == 1.0
    assert policy["cybergym_allocation"] == 0.0


def test_v3_idle_cybergym_redirects_the_whole_lane_to_compute() -> None:
    out = validator_thin.vector_to_uid_weights(
        _v3_idle_payload(), H2U, require_policy=V3_PIN
    )
    assert out[10] == pytest.approx(0.6)  # 0.6 * 1.0 — TDX takes the whole vector
    assert out[11] == pytest.approx(0.4)  # 0.4 * 1.0
    assert 50 not in out and 51 not in out  # CyberGym paid nobody
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


def test_v3_idle_shape_rejects_a_paying_cybergym_lane() -> None:
    # 1.0/0.0 must FORCE an empty lane: a publisher cannot claim idle while paying
    # CyberGym miners. The full lane's fraction (0.30) no longer matches cyber_alloc.
    doc = v3_payload()
    doc["policy_metadata"]["validated_supply"]["intel_tdx_allocation"] = 1.0
    doc["policy_metadata"]["validated_supply"]["cybergym_allocation"] = 0.0
    with pytest.raises(validator_thin.wire.VectorError):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_active_shape_rejects_an_empty_cybergym_lane() -> None:
    # 0.70/0.30 must FORCE a full lane: the empty lane no longer matches cyber_alloc.
    doc = _v3_idle_payload()
    doc["policy_metadata"]["validated_supply"]["intel_tdx_allocation"] = 0.70
    doc["policy_metadata"]["validated_supply"]["cybergym_allocation"] = 0.30
    with pytest.raises(validator_thin.wire.VectorError):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_publisher_composes_an_empty_lane_when_cybergym_is_idle(monkeypatch) -> None:
    # Publisher side: no_contribution -> an EMPTY lane (fraction 0.0), same wire
    # fields; build_signed_vector then signs the 100/0 split. It does NOT raise.
    from scaffold.publisher import cybergym_bridge
    from scaffold.publisher import weights as pub

    monkeypatch.setenv("CATHEDRAL_CYBERGYM_MECHANISM_ENABLED", "1")
    monkeypatch.setenv("CATHEDRAL_CYBERGYM_WEIGHT_FRACTION", "0.30")
    monkeypatch.setattr(
        cybergym_bridge,
        "cybergym_allocation",
        lambda store, **kw: {
            "status": "no_contribution",
            "cybergym": {"reason": "no_contribution"},
        },
    )
    lane = pub._compose_cybergym_lane_v3(store=None, now=NOW)
    assert lane["fraction"] == 0.0
    assert lane["weights"] == {}
    assert lane["forfeited_fraction"] == 0.0
    assert lane["burn_uid"] is None
    assert set(lane) == pub.V3_CYBERGYM_LANE_FIELDS  # same wire shape as a full lane


def test_v3_lane_mass_drift_fails_closed() -> None:
    doc = v3_payload(lane_weights={50: 0.18, 51: 0.20})  # sums to 0.38 != 0.30
    with pytest.raises(validator_thin.wire.VectorError, match="cybergym_lane mass"):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_forfeit_burn_uid_mismatch_fails_closed() -> None:
    # forfeited mass resolved to a stale burn uid (99) that is not the current
    # burn hotkey's uid (0) must fail closed.
    doc = v3_payload(lane_weights={99: 0.30}, forfeited=0.30, lane_burn_uid=99)
    with pytest.raises(validator_thin.wire.VectorError, match="does not match"):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_rejects_a_recycled_cybergym_uid() -> None:
    doc = v3_payload()
    current = {**H2U, "cyber-a": 52, "replacement": 50}
    with pytest.raises(validator_thin.wire.VectorError, match="does not match"):
        validator_thin.vector_to_uid_weights(doc, current, require_policy=V3_PIN)


def test_v3_tdx_hotkey_on_burn_uid_fails_closed() -> None:
    doc = v3_payload(tdx_rows=[("burn-hotkey", 1.0)])
    with pytest.raises(validator_thin.wire.VectorError, match="resolves to burn UID"):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_missing_burn_hotkey_fails_closed() -> None:
    with pytest.raises(
        validator_thin.wire.VectorError, match="no current metagraph UID"
    ):
        validator_thin.vector_to_uid_weights(
            v3_payload(), {"tdx-a": 10, "tdx-b": 11}, require_policy=V3_PIN
        )


# ---- routing / fail-closed ---------------------------------------------------


def test_v1_pin_rejects_v3_contract() -> None:
    with pytest.raises(
        validator_thin.wire.VectorError, match="rejects contract_version 'v3'"
    ):
        validator_thin.vector_to_uid_weights(v3_payload(), H2U, require_policy=V1_PIN)


def test_v3_pin_rejects_non_v3() -> None:
    # A valid v2 (90/10) vector presented to a v3-pinned validator is refused.
    doc = v3_payload()
    doc["policy_metadata"]["validated_supply"] = {
        "contract_version": "v2",
        "intel_tdx_allocation": 0.90,
        "fixed_burn_allocation": 0.10,
        "burn_hotkey": "burn-hotkey",
    }
    doc["policy_metadata"].pop("cybergym_lane")
    doc["burn_snapshot"]["forced_burn_percentage"] = 10.0
    with pytest.raises(validator_thin.wire.VectorError, match="no v3"):
        validator_thin.vector_to_uid_weights(doc, H2U, require_policy=V3_PIN)


def test_v3_applies_unpinned() -> None:
    out = validator_thin.vector_to_uid_weights(v3_payload(), H2U)
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)
    assert out[10] == pytest.approx(0.42)


def test_authority_full_mode_refuses_v3() -> None:
    with pytest.raises(
        validator_thin.wire.VectorError, match="not\n?.*supported|not supported"
    ):
        validator_thin._provenance_uid_weights(
            {"tdx-a": 1.0},
            mechanism="validated_supply_v3",
            burn_hotkey="burn-hotkey",
            hotkey_to_uid=H2U,
        )


# ---- provenance acceptance set -----------------------------------------------


def test_provenance_accepts_v3_in_rollout_set() -> None:
    accepted = provenance_audit.MECHANISM_ACCEPTED
    assert "validated_supply_v3" in accepted["validated_supply_v1"]
    assert "validated_supply_v3" in accepted["validated_supply_v2"]
    assert accepted["validated_supply_v3"] == ("validated_supply_v3",)
    # A v3-pinned validator refuses a downgrade to v1/v2.
    assert "validated_supply_v1" not in accepted["validated_supply_v3"]


# ---- sn39 public-reproduction dry-run ----------------------------------------


def _v3_submission() -> dict:
    return {
        "status": "PASS",
        "authority": "thin",
        "contract_version": "validated_supply_v3",
        "burn_share": 0.0,
        "intel_tdx_share": 0.70,
        "cybergym_share": 0.30,
        "uid_weights": {"10": 0.42, "11": 0.28, "50": 0.18, "51": 0.12},
        "mapping_block": 8680424,
        "validator_uid": 30,
        "validator_hotkey": "validator-hotkey",
    }


def test_sn39_v3_dry_run_accepts_zero_burn_split() -> None:
    assert repro._assert_current_dry_run_v3(_v3_submission()) == "0.00"


def test_sn39_v3_dry_run_rejects_nonzero_burn() -> None:
    doc = _v3_submission()
    doc["burn_share"] = 0.1
    with pytest.raises(repro.ReproductionError, match="70/30/0"):
        repro._assert_current_dry_run_v3(doc)


def test_sn39_v3_dry_run_rejects_share_drift() -> None:
    doc = _v3_submission()
    doc["intel_tdx_share"] = 0.90
    with pytest.raises(repro.ReproductionError, match="70/30/0"):
        repro._assert_current_dry_run_v3(doc)


def test_sn39_v2_dry_run_helper_unchanged() -> None:
    # The v2 90/10 helper still enforces the 2-uid boundary.
    submission = {
        "status": "PASS",
        "authority": "thin",
        "uid_count": 2,
        "burn_share": 0.1,
        "burn_uid": 0,
        "uid_weights": {"0": 0.1, "163": 0.9},
        "wire_uids": [0, 163],
        "wire_weights": [repro.WIRE_VALIDATED_SUPPLY_U16, repro.WIRE_BURN_U16],
        "version_key": repro.EXPECTED_VERSION_KEY,
        "mapping_block": 8680424,
        "validator_uid": 30,
        "validator_hotkey": "validator-hotkey",
    }
    # wire_weights order follows sorted uids: uid 0 is burn -> WIRE_BURN_U16 first.
    submission["wire_weights"] = [repro.WIRE_BURN_U16, repro.WIRE_VALIDATED_SUPPLY_U16]
    assert repro._assert_current_dry_run_v2(submission) == "0.10"


# ---- cross-repo round trip (vendored publisher -> validator) -----------------


def test_cross_repo_v3_publisher_to_validator(monkeypatch) -> None:
    from scaffold.publisher import cybergym_bridge
    from scaffold.publisher import weights as pub

    monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "1")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MODE", "confidential_primary")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_SOURCE", "cathedral_confidential_tdx")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY", "burn-hotkey")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_BURN_UID", "")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2", "0")
    monkeypatch.setenv("CATHEDRAL_ALLOCATION_CONTRACT", "v3")
    monkeypatch.setenv("CATHEDRAL_CYBERGYM_MECHANISM_ENABLED", "1")
    monkeypatch.setenv("CATHEDRAL_CYBERGYM_WEIGHT_FRACTION", "0.30")

    def fake_compose(store, *, now=None, coldkey_of=None, blend_meta_out=None):
        if blend_meta_out is not None:
            blend_meta_out.update(
                {
                    "base_mass": 0.0,
                    "external_mass": 1.0,
                    "blended": False,
                    "confidential_primary": _cp_block(mass=1.0),
                }
            )
        return {"tdx-a": 0.6, "tdx-b": 0.4}

    monkeypatch.setattr(pub, "compose_scores", fake_compose)
    monkeypatch.setattr(pub, "_load_scoring_coldkey_map", lambda store: {})
    monkeypatch.setattr(
        pub,
        "_apply_payable_hotkey_policy",
        lambda store, scores, *, now: (scores, {"mode": "off"}),
    )
    monkeypatch.setattr(pub, "next_policy_version", lambda store: 1_700_000_000_000)
    monkeypatch.setattr(pub, "_effective_mode", lambda store, since: "flat_recent")
    monkeypatch.setattr(
        pub,
        "_perminer_policy_status",
        lambda store, *, now, coldkey_of: {
            "score_source": None,
            "scoring_mode": "disabled",
            "perminer_enabled": False,
            "perminer_shadow": False,
            "perminer_live_requested": False,
            "perminer_bonus_live": False,
            "perminer_primary_live": False,
            "perminer_epoch": None,
            "perminer_has_scores": False,
            "bonus_multiplier": 1.0,
            "history_floor": 0,
            "public_baseline": 0.0,
            "coldkey_required": False,
            "identity_ready": False,
            "degraded_reason": None,
        },
    )
    monkeypatch.setattr(
        pub,
        "_external_scores_policy_status",
        lambda store, *, now: {
            "enabled": True,
            "has_scores": True,
            "source": "cathedral_confidential_tdx",
        },
    )
    monkeypatch.setattr(
        cybergym_bridge,
        "cybergym_allocation",
        lambda store, *, now=None: {
            "status": "ok",
            "weights": {50: 0.18, 51: 0.12},
            "forfeited_fraction": 0.0,
            "contributing_fraction": 0.30,
            "burn_uid": None,
            "uid_hotkeys": {50: "cyber-a", 51: "cyber-b"},
            "cybergym": {"reason": "ok", "report_sha256": "sha256:" + "a" * 64},
        },
    )

    payload = pub.build_signed_vector(object(), signing_key_hex="11" * 32, now=NOW)

    vs = payload["policy_metadata"]["validated_supply"]
    assert vs["contract_version"] == "v3"
    assert vs["intel_tdx_allocation"] == 0.70 and vs["cybergym_allocation"] == 0.30
    lane = payload["policy_metadata"]["cybergym_lane"]
    assert math.isclose(math.fsum(lane["weights"].values()), 0.30, abs_tol=1e-12)
    assert payload["burn_snapshot"]["forced_burn_percentage"] == 0.0
    # Signed TDX rows stay confidential-primary rows (mass 1.0), byte-identical to v2.
    assert math.isclose(
        math.fsum(row["weight"] for row in payload["weights"]), 1.0, abs_tol=1e-12
    )

    out = validator_thin.vector_to_uid_weights(payload, H2U, require_policy=V3_PIN)
    assert out[10] == pytest.approx(0.42)
    assert out[11] == pytest.approx(0.28)
    assert out[50] == pytest.approx(0.18)
    assert out[51] == pytest.approx(0.12)
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


def _v3_publisher_env_and_stubs(monkeypatch, *, cybergym_allocation):
    """Shared publisher-compose setup for a v3 round-trip, parameterized by the
    CyberGym lane the bridge returns. Mirrors test_cross_repo_v3_publisher_to_validator."""
    from scaffold.publisher import cybergym_bridge
    from scaffold.publisher import weights as pub

    for k, v in {
        "CATHEDRAL_VALIDATED_SUPPLY_ENABLED": "1",
        "CATHEDRAL_EXTERNAL_SCORES_MODE": "confidential_primary",
        "CATHEDRAL_EXTERNAL_SCORES_SOURCE": "cathedral_confidential_tdx",
        "CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY": "burn-hotkey",
        "CATHEDRAL_WEIGHT_POLICY_BURN_UID": "",
        "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2": "0",
        "CATHEDRAL_ALLOCATION_CONTRACT": "v3",
        "CATHEDRAL_CYBERGYM_MECHANISM_ENABLED": "1",
        "CATHEDRAL_CYBERGYM_WEIGHT_FRACTION": "0.30",
    }.items():
        monkeypatch.setenv(k, v)

    def fake_compose(store, *, now=None, coldkey_of=None, blend_meta_out=None):
        if blend_meta_out is not None:
            blend_meta_out.update({"base_mass": 0.0, "external_mass": 1.0,
                                   "blended": False, "confidential_primary": _cp_block(mass=1.0)})
        return {"tdx-a": 0.6, "tdx-b": 0.4}

    monkeypatch.setattr(pub, "compose_scores", fake_compose)
    monkeypatch.setattr(pub, "_load_scoring_coldkey_map", lambda store: {})
    monkeypatch.setattr(pub, "_apply_payable_hotkey_policy",
                        lambda store, scores, *, now: (scores, {"mode": "off"}))
    monkeypatch.setattr(pub, "next_policy_version", lambda store: 1_700_000_000_000)
    monkeypatch.setattr(pub, "_effective_mode", lambda store, since: "flat_recent")
    monkeypatch.setattr(pub, "_perminer_policy_status", lambda store, *, now, coldkey_of: {
        "score_source": None, "scoring_mode": "disabled", "perminer_enabled": False,
        "perminer_shadow": False, "perminer_live_requested": False, "perminer_bonus_live": False,
        "perminer_primary_live": False, "perminer_epoch": None, "perminer_has_scores": False,
        "bonus_multiplier": 1.0, "history_floor": 0, "public_baseline": 0.0,
        "coldkey_required": False, "identity_ready": False, "degraded_reason": None})
    monkeypatch.setattr(pub, "_external_scores_policy_status", lambda store, *, now: {
        "enabled": True, "has_scores": True, "source": "cathedral_confidential_tdx"})
    monkeypatch.setattr(cybergym_bridge, "cybergym_allocation",
                        lambda store, *, now=None: cybergym_allocation)
    return pub


def test_cross_repo_v3_forfeit_round_trip_burn_uid_stable(monkeypatch) -> None:
    """forfeited_fraction > 0, burn UID stable between compose and validate:
    the forfeited mass sinks to the burn UID and the vector normalizes to 1.0.

    Closes the #35 gap: the publisher-composed forfeiture path was only ever
    exercised with forfeited_fraction == 0. Here build_signed_vector emits a lane
    whose 0.06 forfeited share is bound to the burn UID (0), and the validator's
    own mapper accepts it end to end."""
    # 0.24 contributed by miners + 0.06 forfeited to the burn UID = 0.30 lane.
    lane = {"status": "ok", "weights": {50: 0.14, 51: 0.10, 0: 0.06},
            "forfeited_fraction": 0.06, "contributing_fraction": 0.24, "burn_uid": 0,
            "uid_hotkeys": {50: "cyber-a", 51: "cyber-b", 0: "burn-hotkey"},
            "cybergym": {"reason": "ok", "report_sha256": "sha256:" + "a" * 64}}
    pub = _v3_publisher_env_and_stubs(monkeypatch, cybergym_allocation=lane)

    payload = pub.build_signed_vector(object(), signing_key_hex="11" * 32, now=NOW)
    cyber_lane = payload["policy_metadata"]["cybergym_lane"]
    assert cyber_lane["forfeited_fraction"] == pytest.approx(0.06)
    assert cyber_lane["burn_uid"] == 0
    assert math.isclose(math.fsum(cyber_lane["weights"].values()), 0.30, abs_tol=1e-9)

    out = validator_thin.vector_to_uid_weights(payload, H2U, require_policy=V3_PIN)
    # burn UID (0) receives exactly the forfeited 0.06; the whole vector sums to 1.0.
    assert out[0] == pytest.approx(0.06)
    assert out[50] == pytest.approx(0.14) and out[51] == pytest.approx(0.10)
    assert out[10] == pytest.approx(0.42) and out[11] == pytest.approx(0.28)
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-9)


def test_cross_repo_v3_forfeit_round_trip_burn_uid_moved_is_rejected(monkeypatch) -> None:
    """forfeited_fraction > 0, burn hotkey's UID MOVED between compose and validate:
    the whole v3 vector is rejected (fail-closed), no partial or misdirected write.

    This is the burn-UID-churn liveness cliff #35 names: fund-safe (nothing is
    misdirected) but it drops that tick's write, so it is a Phase-5 liveness watch
    item, documented in THIN_SUBNET_RUNBOOK.md."""
    lane = {"status": "ok", "weights": {50: 0.14, 51: 0.10, 0: 0.06},
            "forfeited_fraction": 0.06, "contributing_fraction": 0.24, "burn_uid": 0,
            "uid_hotkeys": {50: "cyber-a", 51: "cyber-b", 0: "burn-hotkey"},
            "cybergym": {"reason": "ok", "report_sha256": "sha256:" + "a" * 64}}
    pub = _v3_publisher_env_and_stubs(monkeypatch, cybergym_allocation=lane)
    payload = pub.build_signed_vector(object(), signing_key_hex="11" * 32, now=NOW)

    # The burn hotkey now resolves to a DIFFERENT uid than the lane's baked burn_uid.
    moved = dict(H2U)
    moved["burn-hotkey"] = 7
    with pytest.raises(validator_thin.wire.VectorError, match="recipient UID does not match"):
        validator_thin.vector_to_uid_weights(payload, moved, require_policy=V3_PIN)


def test_v3_pin_with_authority_provenance_is_refused_at_startup() -> None:
    """require_policy=validated_supply_v3 + provenance=authority fails closed every
    tick and the validator goes dark silently; refuse it loudly at startup (#35)."""
    from types import SimpleNamespace

    args = SimpleNamespace(
        require_policy=validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
        provenance="authority")
    with pytest.raises(validator_thin.wire.VectorError,
                       match="incompatible with provenance=authority"):
        validator_thin._validate_runtime_contract(args)


def test_v3_pin_with_shadow_provenance_does_not_trip_the_guard() -> None:
    """shadow (relay + concurrent audit) is the correct posture for a v3 pin, so the
    v3/authority guard must NOT fire."""
    from types import SimpleNamespace

    args = SimpleNamespace(
        require_policy=validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
        provenance="shadow", max_submissions=0, broadcast=False, offline=True, netuid=39)
    try:
        validator_thin._validate_runtime_contract(args)
    except validator_thin.wire.VectorError as exc:
        assert "incompatible with provenance=authority" not in str(exc)
