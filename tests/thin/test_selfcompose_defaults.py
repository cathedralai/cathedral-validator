"""Attestation-verified (thin/shadow) is the principal default.

Locks the consolidation's behavioral core: the console CLI defaults, the
module-path assurance fallback, the launch fail-closed default, and the new
config/validator-selfcompose-sn39.toml profile. Authority must stay reachable
(opt-in) but must NOT be the default that loses the chain-finality race.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

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
    assert (
        vt._minimum_assurance_rank(SimpleNamespace())
        == pa.ASSURANCE_RANKS["rewarded_set_proven"]
    )
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


def _relay_cfg() -> dict:
    return cli._load_config_file(
        str(ROOT / "config" / "validator-thin-sn39-relay.toml")
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


def test_selfcompose_config_carries_the_launch_ceremony_waiver() -> None:
    cfg = _selfcompose_cfg()
    # The two opt-outs pinned above are only HONORED for a runtime with no
    # launch of its own. The consolidated host has the release-installed launch
    # material, so it reads as launch-capable no matter what it declares, and
    # the runtime contract refuses the opt-outs without this waiver. Omitting it
    # makes the profile unable to start on the one host it is written for.
    assert cfg["beta_skip_launch_ceremony"] is True


def test_selfcompose_config_points_publisher_at_the_local_role() -> None:
    cfg = _selfcompose_cfg()
    # The one line that makes the validator self-composing: fetch the signed
    # vector from the LOCAL publisher role, not a remote origin.
    assert cfg["publisher_url"].startswith("http://127.0.0.1:")


def test_relay_profile_stays_shadow() -> None:
    assert _relay_cfg()["provenance"] == "shadow"


def test_the_only_deltas_from_the_relay_profile_are_the_documented_two() -> None:
    """The self-compose header states its deltas; hold it to that claim.

    The profile's whole safety story is "same trust-bearing numbers as the
    relay, one publisher origin apart". A value that quietly drifts apart —
    or a key present in one profile and missing from the other, which is how
    the launch waiver went absent here in the first place — falsifies the
    header without touching it. Compare the LOADED configs so a delta cannot
    hide behind formatting or section ordering.
    """
    absent = object()
    selfcompose, relay = _selfcompose_cfg(), _relay_cfg()
    deltas = {
        key
        for key in set(selfcompose) | set(relay)
        if selfcompose.get(key, absent) != relay.get(key, absent)
    }
    assert deltas == {"publisher_url", "status_jsonl"}


# -- the self-compose profile on the host it is written for -----------------


def _selfcompose_broadcast_args() -> SimpleNamespace:
    """The self-compose profile as `serve --broadcast` would resolve it.

    `publisher_url` is overridden to the release origin because it is the one
    delta the immutable trust profile also pins, and it raises first — the
    local-publisher URL is refused independently of anything launch-related
    (a separate, known limitation of this profile). Overriding it here is what
    lets these tests reach the launch-gate branch they are about; it is a
    no-op for every other pinned value.
    """
    cfg = dict(cli._DEFAULTS)
    cfg.update(_selfcompose_cfg())
    cfg["publisher_url"] = vt.SN39_PUBLISHER_URL
    cfg["broadcast"] = True
    cfg["offline"] = False
    return SimpleNamespace(**cfg)


def _relocate_launch_material(monkeypatch, root: pathlib.Path) -> pathlib.Path:
    """Point the three release-pinned launch paths inside `root`.

    `_sn39_launch_obligation` answers from code constants and this runtime's
    own journal, never from config, so the only honest way to test the profile
    on its own host is to move what those constants address. Relocating all
    three (rather than one) keeps the test machine's real filesystem from
    deciding which branch fires.
    """
    monkeypatch.setattr(vt, "SN39_LAUNCH_CONTROLLED_DIR", root / "controlled")
    monkeypatch.setattr(vt, "SN39_LAUNCH_APPROVAL_FILE", root / "approval.json")
    verifier = root / "cathedral-tdx-verifier"
    monkeypatch.setattr(vt, "SN39_LAUNCH_VERIFIER_BINARY", verifier)
    return verifier


@pytest.fixture()
def launch_capable_host(monkeypatch, tmp_path) -> None:
    # A release install puts the verifier binary on the consolidated host; that
    # possession alone is what makes the runtime launch-capable.
    _relocate_launch_material(monkeypatch, tmp_path).write_bytes(b"")


@pytest.fixture()
def bare_relay_host(monkeypatch, tmp_path) -> None:
    # A third-party relay never receives the launch material, so none of the
    # pinned paths resolve.
    _relocate_launch_material(monkeypatch, tmp_path)


def test_selfcompose_profile_starts_on_a_launch_capable_host(
    launch_capable_host,
) -> None:
    # The consolidated host holds launch material, so it owes SN39 a launch it
    # cannot perform — and the profile still has to be able to broadcast there.
    args = _selfcompose_broadcast_args()
    assert vt._sn39_launch_obligation(args) is True
    vt._validate_runtime_contract(args)


def test_without_the_waiver_that_host_could_not_broadcast_at_all(
    launch_capable_host,
) -> None:
    # The gate is unchanged and still bites: this is what the shipped profile
    # did before it carried the waiver, and what it will do again if the waiver
    # is dropped. Pinning the failure keeps the waiver from reading as noise.
    args = _selfcompose_broadcast_args()
    args.beta_skip_launch_ceremony = False
    with pytest.raises(vt.wire.VectorError, match="completed-launch gate"):
        vt._validate_runtime_contract(args)


def test_a_host_without_launch_material_never_needed_the_waiver(
    bare_relay_host,
) -> None:
    # Why the omission went unnoticed: with no launch material there is no
    # obligation, so the gate never fires and the missing waiver costs nothing.
    # It is the launch-capable host, and only that host, that the waiver saves.
    args = _selfcompose_broadcast_args()
    args.beta_skip_launch_ceremony = False
    assert vt._sn39_launch_obligation(args) is False
    vt._validate_runtime_contract(args)


def test_an_authority_profile_carries_everything_authority_requires() -> None:
    # This replaces test_no_authority_config_profile_ships, which asserted that no
    # config may select "the deleted mode". The mode was never deleted: only its
    # profiles were, in the shadow-only cleanup, and the code path stayed intact
    # and runnable the whole time.
    #
    # So the useful invariant is not "never ship authority", it is "never ship a
    # BROKEN authority profile". Each of these is mandatory at runtime and the
    # failure arrives as a refused tick, which on a live validator reads as an
    # outage rather than a missing config line:
    #
    #   controlled_dir         the evidence to replay
    #   verifier_binary        the pinned TDX verifier
    #   max_anchor_lag_blocks  without it the producer chooses the block every
    #                          independent chain check is evaluated at
    required = (
        "provenance_controlled_dir",
        "provenance_verifier_binary",
        "provenance_max_anchor_lag_blocks",
    )
    for cfg_path in sorted((ROOT / "config").glob("*.toml")):
        cfg = cli._load_config_file(str(cfg_path))
        if cfg.get("provenance") != "authority":
            continue
        for key in required:
            assert cfg.get(key), f"{cfg_path.name} selects authority without {key}"


def test_the_controlled_dir_tracks_the_rotating_symlink() -> None:
    # Controlled evidence is exported one directory per epoch and `current` is
    # repointed after each export. A profile pinned to an epoch directory replays
    # stale evidence and then refuses on an epoch mismatch minutes later, which
    # looks like a validator fault instead of a stale path.
    for cfg_path in sorted((ROOT / "config").glob("*.toml")):
        cfg = cli._load_config_file(str(cfg_path))
        controlled = cfg.get("provenance_controlled_dir")
        if not controlled:
            continue
        assert "epoch-" not in controlled, (
            f"{cfg_path.name} pins an epoch directory; point at the rotating "
            "`current` symlink instead"
        )
