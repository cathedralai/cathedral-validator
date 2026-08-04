"""Attestation-verified (thin/shadow) is the principal default.

Locks the consolidation's behavioral core: the console CLI defaults, the
module-path assurance fallback, the launch fail-closed default, and the new
config/validator-selfcompose-sn39.toml profile. Authority must stay reachable
(opt-in) but must NOT be the default that loses the chain-finality race.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace

from scaffold import cli
from scaffold import provenance_audit as pa
from scaffold import validator_thin as vt


ROOT = pathlib.Path(__file__).resolve().parents[2]


# -- console CLI defaults ---------------------------------------------------


def test_cli_defaults_are_attestation_verified() -> None:
    # The load-bearing change: provenance defaults to shadow (attestation-
    # verified/thin), the mode that wins the chain-finality race.
    assert cli._DEFAULTS["provenance"] == "shadow"


def test_min_assurance_default_is_unchanged() -> None:
    # min_assurance is deliberately NOT lowered: it gates the shadow verifier's
    # PROVEN labeling and the opt-in authority path, never the thin write path.
    # Lowering it would only change shadow persistence semantics (Round-six S3),
    # not help attestation-verified win the race.
    assert cli._DEFAULTS["min_assurance"] == "rewarded_set_proven"


def test_cli_launch_gate_stays_fail_closed_by_default() -> None:
    # Fail-closed in code; only the relay/self-compose TOMLs opt out (they
    # perform no launch of their own). Authority cannot be weakened by this.
    assert cli._DEFAULTS["require_completed_launch_for_broadcast"] is True


def test_authority_is_still_reachable_as_an_opt_in_alias() -> None:
    # `--mode full` and `mode = "authority"` both still resolve to authority;
    # the default flip did not remove the fallback.
    assert cli._MODE_ALIASES["full"] == "authority"
    assert cli._MODE_ALIASES["authority"] == "authority"
    assert cli._MODE_ALIASES["thin"] == "shadow"
    assert cli._MODE_ALIASES["shadow"] == "shadow"


# -- module path (python -m scaffold.validator_thin) ------------------------


def test_module_path_assurance_fallback_is_unchanged() -> None:
    # No min_assurance attribute set -> the fallback stays rewarded_set_proven
    # (rank 1). This is the shadow verifier / authority bar, not the thin gate.
    assert vt._minimum_assurance_rank(SimpleNamespace()) == pa.ASSURANCE_RANKS[
        "rewarded_set_proven"
    ]
    assert vt._minimum_assurance_rank(SimpleNamespace()) == 1


def test_module_parser_provenance_default_is_shadow() -> None:
    parser = vt.build_parser()
    ns = parser.parse_args([])
    assert ns.provenance == "shadow"
    # min_assurance flag exists for opt-in parity; default is unchanged.
    assert ns.min_assurance == "rewarded_set_proven"


def test_module_parser_still_accepts_the_authority_assurance_levels() -> None:
    parser = vt.build_parser()
    for level in ("receipts_only", "rewarded_set_proven", "full_over_epoch"):
        ns = parser.parse_args(["--min-assurance", level])
        assert ns.min_assurance == level


# -- the new consolidated self-compose profile ------------------------------


def _selfcompose_cfg() -> dict:
    return cli._load_config_file(
        str(ROOT / "config" / "validator-selfcompose-sn39.toml")
    )


def test_selfcompose_config_is_attestation_verified_thin() -> None:
    cfg = _selfcompose_cfg()
    assert cfg["provenance"] == "shadow"
    assert cfg["require_completed_launch_for_broadcast"] is False
    # v2 stays the byte-identical default; v3 is a Phase 5 flip.
    assert cfg["require_policy"] == "validated_supply_v1"
    # min_assurance is intentionally not pinned in this profile (inherits the
    # rewarded_set_proven default), so it never appears in the loaded config.
    assert "min_assurance" not in cfg


def test_selfcompose_config_points_publisher_at_the_local_role() -> None:
    cfg = _selfcompose_cfg()
    # The one line that makes the validator self-composing: fetch the signed
    # vector from the LOCAL publisher role, not a remote origin.
    assert cfg["publisher_url"].startswith("http://127.0.0.1:")


def test_relay_profile_stays_shadow() -> None:
    cfg = cli._load_config_file(
        str(ROOT / "config" / "validator-thin-sn39-relay.toml")
    )
    assert cfg["provenance"] == "shadow"


def test_authority_fallback_config_is_left_byte_identical() -> None:
    # The mainnet authority profile is the reachable fallback and must NOT have
    # been flipped to shadow by this consolidation.
    cfg = cli._load_config_file(
        str(ROOT / "config" / "validator-mainnet-sn39.toml")
    )
    assert cfg["provenance"] == "authority"
    assert cfg["min_assurance"] == "rewarded_set_proven"
