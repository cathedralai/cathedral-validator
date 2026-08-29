from __future__ import annotations

import contextlib
import copy
import hashlib
import inspect
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin import uid30_fleet_preview as preview
from cathedral_thin import uid30_fleet_submit as submit
from cathedral_thin import uid30_launch as launch
from cathedral_thin import uid30_state
from cathedral_thin.independent.constants import (
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from scaffold import validator_thin as canonical

ROOT = "https://1.1.1.1:8081"
SECOND = "https://8.8.8.8:8081"
EVIDENCE_BLOCK = canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK + 40
RECHECK_BLOCK = EVIDENCE_BLOCK + 1
EVIDENCE_HASH = "0x" + "a" * 64
RECHECK_HASH = "0x" + "b" * 64


def _machine(endpoint: str, marker: str) -> dict:
    stable = "tdx-platform-sha256:" + marker * 64
    return {
        "endpoint": endpoint,
        "channel_id": hashlib.sha256(("channel:" + marker).encode()).hexdigest(),
        "stable_platform_id": stable,
        "machine_id": hashlib.sha256(stable.encode("ascii")).hexdigest(),
        "quote_sha256": hashlib.sha256(("quote:" + marker).encode()).hexdigest(),
        "report_data_sha256": hashlib.sha256(("report:" + marker).encode()).hexdigest(),
        "sat_rule": SAT_WORK_UNIT_RULE,
        "verified_work_units": 20,
    }


def _preview() -> dict:
    return {
        "schema": preview.SCHEMA,
        "status": preview.STATUS,
        "network": "finney",
        "netuid": 39,
        "mechanism_id": 0,
        "evidence_anchor": {
            "block_number": EVIDENCE_BLOCK,
            "block_hash": EVIDENCE_HASH,
        },
        "finalized_recheck": {
            "block_number": RECHECK_BLOCK,
            "block_hash": RECHECK_HASH,
        },
        "validator": {"uid": 30, "hotkey": submit.UID30_HOTKEY},
        "score_contract": {
            "formula": "sum independently re-derived verified work_units across unique physical identities",
            "declared_machine_count_bonus_units": 0,
            "attestation_only_bonus_units": 0,
            "per_machine_unit_cap": 20,
            "fleet_cap_per_uid": 32,
        },
        "current": {
            "uid30_storage": [[8, W], [124, W]],
            "burn_destination_uid": 136,
            "burn_weight": 0,
            "weighted_serving_uids": [
                {
                    "uid": 8,
                    "hotkey": submit.PREDECESSOR_HOTKEY,
                    "endpoint": SECOND,
                    "stored_weight": W,
                    "verified_work_units": 0,
                },
                {
                    "uid": 124,
                    "hotkey": submit.MINER_HOTKEY,
                    "endpoint": ROOT,
                    "stored_weight": W,
                    "verified_work_units": 40,
                },
            ],
            "verified_units_by_hotkey": {submit.MINER_HOTKEY: 40},
            "fleet_discovery": [],
            "machine_observations": [],
            "exclusions": [],
            "blockers": [],
        },
        "consolidation_target": {
            "hotkey": submit.MINER_HOTKEY,
            "uid": 124,
            "root_axon": ROOT,
            "fleet_endpoints": [ROOT, SECOND],
            "machines": [_machine(ROOT, "1"), _machine(SECOND, "2")],
            "raw_uid_units": 40,
            "required_raw_uid_units": 40,
            "proof_complete": True,
            "not_proven_reasons": [],
            "non_authorizing_target_wire_row": [[124, W]],
        },
        "qvl_digest": submit.LAUNCH_QVL_DIGEST,
        "burn_destination": None,
        "burn_weight": 0,
        "changes_current_chain_row": True,
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
        "weight_signed": False,
        "weight_submitted": False,
        "proof_boundary": (
            "PROVEN means the pinned UID owns two independently verified TDX "
            "platforms with 20 SAT units each and its signed fleet survived a "
            "finalized recheck. The singleton row remains a no-write target. "
            "This artifact does not authorize weights, prove subnet emission, "
            "or prove TAO earnings. AMD SEV-SNP fleet identity remains "
            "NOT_PROVEN and disabled."
        ),
    }


def _written_preview(tmp_path: Path) -> tuple[Path, str, dict]:
    document = _preview()
    target = tmp_path / "fleet.json"
    raw = preview._canonical_bytes(document)
    digest = hashlib.sha256(raw).hexdigest()
    target.write_bytes(raw)
    target.chmod(0o600)
    digest_path = Path(str(target) + ".sha256")
    digest_path.write_text(f"{digest}  {target.name}\n", encoding="ascii")
    digest_path.chmod(0o600)
    return target, digest, document


def _uid_safety(*, uid124_safe: bool = True) -> dict:
    return {
        "schema": "cathedral_sn39_uid_safety_v2",
        "rotation": {
            "status": canonical.PASS,
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "targets": [
                {
                    "uid": 8,
                    "hotkey": submit.PREDECESSOR_HOTKEY,
                    "registration_replacement_safe": True,
                },
                {
                    "uid": 124,
                    "hotkey": submit.MINER_HOTKEY,
                    "registration_replacement_safe": uid124_safe,
                },
            ],
        },
        "excluded_hotkeys": [] if uid124_safe else [submit.MINER_HOTKEY],
    }


def _fleet_state() -> submit.UID30FleetState:
    block = RECHECK_BLOCK + 2
    base = SimpleNamespace(
        block_number=block,
        block_hash="0x" + "c" * 64,
        next_epoch_start_block=block + 200,
        subnet_owner_hotkey=canonical.SN39_BURN_HOTKEY,
        validator_permit=True,
        validator_stake_rao=2_000,
        stake_threshold_rao=1_000,
        last_update=canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK,
        blocks_since_last_update=(block - canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK),
        weights_rate_limit=10,
        commit_reveal_enabled=False,
        mechanism_count=1,
        weights_version_key=VERSION_KEY,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        preflight=SimpleNamespace(name="preflight"),
    )
    return submit.UID30FleetState(
        base=base,
        current_weights=((8, W), (124, W)),
        current_axons=(),
        uid_safety=_uid_safety(),
    )


@pytest.mark.parametrize(
    "uid124_safe", [True, False], ids=["both-safe", "uid124-unsafe"]
)
def test_read_fleet_state_binds_real_read_shape_to_full_write_safety(
    monkeypatch: pytest.MonkeyPatch, uid124_safe: bool
) -> None:
    monkeypatch.setenv(
        "CATHEDRAL_CHAIN_ENDPOINT", "wss://entrypoint-finney.opentensor.ai:443"
    )
    block = RECHECK_BLOCK + 2
    block_hash = "0x" + "c" * 64
    owner_hotkey = canonical.SN39_BURN_HOTKEY
    uid_map = {
        submit.UID30_HOTKEY: 30,
        submit.PREDECESSOR_HOTKEY: 8,
        submit.MINER_HOTKEY: 124,
        owner_hotkey: 136,
    }
    reverse_map = {uid: hotkey for hotkey, uid in uid_map.items()}
    wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address=submit.UID30_HOTKEY))

    class Substrate:
        def get_block_hash(self, observed_block: int) -> str:
            if observed_block == 0:
                return submit.FINNEY_GENESIS_HASH
            assert observed_block == block
            return block_hash

        def get_constant(
            self,
            *,
            module_name: str,
            constant_name: str,
            block_hash: str,
        ) -> int:
            assert module_name == "SubtensorModule"
            assert constant_name == "HotkeySwapOnSubnetInterval"
            assert block_hash == "0x" + "c" * 64
            return 100

    class Subtensor:
        substrate = Substrate()

        def query_subtensor(
            self, *, name: str, params: list[object], block: int
        ) -> object:
            assert block == RECHECK_BLOCK + 2
            if name == "Owner":
                return "coldkey:" + str(params[0])
            if name == "LastHotkeySwapOnNetuid":
                return 0
            if name == "ColdkeySwapAnnouncements":
                return None
            if name == "ColdkeySwapAnnouncementDelay":
                return 100
            raise AssertionError(name)

    subtensor = Subtensor()
    read_preflight = uid30_state.UID30ReadPreflight(
        wallet=wallet,
        subtensor=subtensor,
        hotkey_to_uid=dict(uid_map),
        uid_to_hotkey=dict(reverse_map),
        validator_hotkey=submit.UID30_HOTKEY,
        validator_uid=30,
        block=block,
        finalized_hash=block_hash,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        commit_reveal_enabled=False,
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        subnet_owner_hotkey=owner_hotkey,
        blocks_until_next_epoch=200,
        next_epoch_start_block=block + 200,
        weights_rate_limit=10,
        validator_blocks_since_last_update=(
            block - canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
        ),
        connection_target=submit.ARCHIVE_CHAIN_ENDPOINT,
    )
    root_axon = submit.ServingAxon(
        uid=124,
        hotkey=submit.MINER_HOTKEY,
        ip="1.1.1.1",
        port=8081,
    )
    predecessor_axon = submit.ServingAxon(
        uid=8,
        hotkey=submit.PREDECESSOR_HOTKEY,
        ip="8.8.8.8",
        port=8081,
    )
    read_base = uid30_state.UID30ChainState(
        preflight=read_preflight,
        block_number=block,
        block_hash=block_hash,
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        subnet_owner_hotkey=owner_hotkey,
        validator_hotkey=submit.UID30_HOTKEY,
        validator_uid=30,
        validator_permit=True,
        validator_stake_rao=2_000,
        stake_threshold_rao=1_000,
        last_update=canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK,
        blocks_since_last_update=(block - canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK),
        weights_rate_limit=10,
        mechanism_count=1,
        weights_version_key=VERSION_KEY,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        commit_reveal_enabled=False,
        miner_hotkey=submit.MINER_HOTKEY,
        miner_uid=124,
        serving_axon=root_axon,
        next_epoch_start_block=block + 200,
        blocks_until_next_epoch=200,
        uid_safety={
            "status": "read_only_current_mapping_only",
            "authorized_for_chain_write": False,
        },
    )
    write_preflight = canonical.ChainPreflight(
        wallet=wallet,
        subtensor=subtensor,
        hotkey_to_uid=dict(uid_map),
        validator_hotkey=submit.UID30_HOTKEY,
        validator_uid=30,
        block=block,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        commit_reveal_enabled=False,
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        subnet_owner_hotkey=owner_hotkey,
        blocks_until_next_epoch=200,
        next_epoch_start_block=block + 200,
        weights_rate_limit=10,
        validator_blocks_since_last_update=(
            block - canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
        ),
        uid_mapping_stable_until_block=block + 4,
        replacement_safe_hotkeys=frozenset(
            {submit.PREDECESSOR_HOTKEY}
            | ({submit.MINER_HOTKEY} if uid124_safe else set())
        ),
        subnet_free_uid_slots=0,
        subnet_max_regs_per_block=1,
        subnet_min_nonimmune_uids=1,
        subnet_immunity_period=100,
        subnet_temporally_immune_uids=2,
        subnet_owner_coldkey="subnet-owner-coldkey",
        subnet_immune_owner_uids_limit=1,
        subnet_owner_immortal_hotkeys=frozenset(),
        subnet_max_uids=256,
        subnet_registration_blocks=(
            (8, submit.PREDECESSOR_HOTKEY, block - 100),
            (124, submit.MINER_HOTKEY, block - 100),
        ),
        subnet_owned_hotkeys=(),
        subnet_prune_metrics=(
            (8, submit.PREDECESSOR_HOTKEY, 0.0, 0.0, 0.0),
            (124, submit.MINER_HOTKEY, 0.0, 0.0, 0.0),
        ),
        subnet_worst_case_evictions=0,
        subnet_eviction_depth=(
            (submit.PREDECESSOR_HOTKEY, 1),
            (submit.MINER_HOTKEY, 1),
        ),
        finalized_hash=block_hash,
        connection_target=submit.ARCHIVE_CHAIN_ENDPOINT,
    )
    calls: list[dict[str, object]] = []

    def full_preflight(**kwargs: object) -> canonical.ChainPreflight:
        calls.append(kwargs)
        return write_preflight

    def read_state(**kwargs: object) -> uid30_state.UID30ChainState:
        prepared = kwargs.get("preflight")
        assert isinstance(prepared, uid30_state.UID30ReadPreflight)
        assert prepared.subtensor is write_preflight.subtensor
        assert prepared.wallet is write_preflight.wallet
        assert prepared.block == write_preflight.block
        assert prepared.finalized_hash == write_preflight.finalized_hash
        assert prepared.connection_target == submit.ARCHIVE_CHAIN_ENDPOINT
        return read_base

    monkeypatch.setattr(submit, "read_uid30_chain_state", read_state)
    monkeypatch.setattr(canonical, "chain_preflight", full_preflight)
    monkeypatch.setattr(
        preview,
        "read_current_uid30_weights",
        lambda _state: ((8, W), (124, W)),
    )
    monkeypatch.setattr(
        preview,
        "read_weighted_serving_axons",
        lambda _state, _weights: (predecessor_axon, root_axon),
    )

    if not uid124_safe:
        document = _preview()
        reached: list[str] = []
        monkeypatch.setattr(
            submit,
            "load_reviewed_preview",
            lambda *_args, **_kwargs: (document, "d" * 64),
        )
        monkeypatch.setattr(
            canonical,
            "_submission_tick_lock",
            lambda _args, *, lane: contextlib.nullcontext(),
        )
        monkeypatch.setattr(submit, "_assert_pristine_predecessor", lambda _args: None)
        monkeypatch.setattr(
            canonical,
            "_reserve_common_submission",
            lambda *_args, **_kwargs: reached.append("reserve"),
        )
        monkeypatch.setattr(
            canonical,
            "_submit_exact_sn39_extrinsic",
            lambda *_args, **_kwargs: reached.append("sign"),
        )

        with pytest.raises(
            launch.UID30LaunchError,
            match="both fixed UID mappings replacement-safe",
        ):
            submit.submit_reviewed_fleet(
                preview_path="/reviewed.json",
                reviewed_sha256="d" * 64,
                qvl_path="/pinned/qvl",
                confirm=True,
                exclusive_writer_asserted=True,
            )

        assert reached == []
        return

    state = submit.read_fleet_state()

    assert not hasattr(read_preflight, "replacement_safe_hotkeys")
    assert state.base.preflight is write_preflight
    assert state.uid_safety["schema"] == "cathedral_sn39_uid_safety_v2"
    assert state.uid_safety["excluded_hotkeys"] == []
    assert {row["uid"] for row in state.uid_safety["rotation"]["targets"]} == {8, 124}
    assert calls == [
        {
            "network": "finney",
            "netuid": 39,
            "wallet_name": "cathedral",
            "wallet_hotkey": "default",
            "connection_endpoint": submit.ARCHIVE_CHAIN_ENDPOINT,
        }
    ]


def test_owner_only_canonical_digest_binds_exact_preview(tmp_path: Path) -> None:
    path, digest, document = _written_preview(tmp_path)

    loaded, loaded_digest = submit.load_reviewed_preview(path, reviewed_sha256=digest)

    assert loaded == document
    assert loaded_digest == digest
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    Path(str(path) + ".sha256").write_text(
        f"{digest}  another.json\n", encoding="ascii"
    )
    with pytest.raises(launch.UID30LaunchError, match="filename differs"):
        submit.load_reviewed_preview(path, reviewed_sha256=digest)


@pytest.mark.parametrize(
    "mutation,message",
    [
        (lambda row: row.update(burn_weight=1), "no-write gates"),
        (
            lambda row: row["consolidation_target"].update(
                non_authorizing_target_wire_row=[[8, W], [124, W]]
            ),
            "target or predecessor",
        ),
        (
            lambda row: row["consolidation_target"]["machines"][1].update(
                stable_platform_id=row["consolidation_target"]["machines"][0][
                    "stable_platform_id"
                ]
            ),
            "machine proof is invalid",
        ),
    ],
)
def test_preview_mutations_never_authorize(mutation, message: str) -> None:
    document = _preview()
    mutation(document)
    with pytest.raises(launch.UID30LaunchError, match=message):
        submit.validate_reviewed_preview(document)


def test_root_endpoint_does_not_have_to_sort_before_second_machine() -> None:
    document = _preview()
    document["consolidation_target"].update(
        root_axon=SECOND,
        fleet_endpoints=[SECOND, ROOT],
        machines=[_machine(ROOT, "1"), _machine(SECOND, "2")],
    )
    document["current"]["weighted_serving_uids"][0]["endpoint"] = ROOT
    document["current"]["weighted_serving_uids"][1]["endpoint"] = SECOND

    assert submit.validate_reviewed_preview(document) == document


def test_identity_is_exact_uid124_zero_burn_and_two_distinct_machines() -> None:
    document = submit.validate_reviewed_preview(_preview())
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256="d" * 64,
        fresh=document,
        state=_fleet_state(),
    )

    submit._validate_attempt_identity(
        identity, reviewed=document, preview_sha256="d" * 64
    )
    contract = canonical._strict_zero_burn_uid30_fleet_contract(
        identity, lane="authority"
    )
    assert contract["uid_weights"] == ((124, 1.0),)
    assert identity["burn_destination"] is None
    assert identity["burn_share"] == 0.0
    assert len(identity["fresh_miner_evidence"]) == 2

    changed = copy.deepcopy(identity)
    changed["uid_weights"] = [[8, 1.0], [124, 1.0]]
    with pytest.raises(Exception, match="rows are not exact"):
        canonical._strict_zero_burn_uid30_fleet_contract(changed, lane="authority")


def test_unsigned_reservation_restores_exact_predecessor_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    state_path = runtime / canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
    predecessor = {
        "submission_pending_id": None,
        "submission_active_lane": "authority",
        "submission_attempt_ids": [
            canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
            canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        ],
        "submission_attempt_count": 2,
        "submission_finalized_count": 2,
        "submission_highest_source_epoch": (
            canonical.SN39_UID30_FLEET_PREDECESSOR_SOURCE_EPOCH
        ),
        "submission_finalized_id": canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        "submission_attempt_budgets": {
            "launch_full_gate": {
                "limit": 1,
                "ids": [canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
            },
            "authority_bounded": {
                "limit": 1,
                "ids": [canonical.SN39_UID30_FLEET_PREDECESSOR_ID],
            },
        },
        "submission_genesis_hash": submit.FINNEY_GENESIS_HASH,
        "provenance_netuid": 39,
        "submission_validator_hotkey": submit.UID30_HOTKEY,
    }
    predecessor_bytes = canonical._canonical_json_bytes(predecessor)
    state_path.write_bytes(predecessor_bytes)
    state_path.chmod(0o600)
    predecessor_digest = hashlib.sha256(predecessor_bytes).hexdigest()
    monkeypatch.setattr(submit, "DEFAULT_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(canonical, "_VALIDATOR_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(
        canonical,
        "SN39_UID30_FLEET_PREDECESSOR_JOURNAL_SHA256",
        predecessor_digest,
    )
    document = submit.validate_reviewed_preview(_preview())
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256="d" * 64,
        fresh=document,
        state=_fleet_state(),
    )
    attempt_id = launch._attempt_id(identity)
    args = submit._submission_contract(preview_sha256="d" * 64)

    canonical._reserve_common_submission(
        args,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )

    reserved = canonical._read_state(state_path)
    assert reserved["submission_pending_reviewed_uid30_contract"] == (
        "same_uid_fleet_consolidation"
    )
    assert reserved["submission_pending_budget_scope"] == (
        canonical.SN39_UID30_FLEET_BUDGET_SCOPE
    )
    assert canonical._abort_unsigned_common_submission(args, attempt_id=attempt_id)
    assert state_path.read_bytes() == predecessor_bytes

    canonical._reserve_common_submission(
        args,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )
    canonical._commit_pending_signed_attempt(
        args,
        attempt_id=attempt_id,
        intent={
            "extrinsic_hash": "0x" + "f" * 64,
            "nonce": 7,
            "era_reference_block": identity["mapping_block"],
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "version_key": VERSION_KEY,
            "wire_uids": [124],
            "wire_weights": [W],
        },
    )

    signed = canonical._read_state(state_path)
    assert signed["submission_pending_phase"] == "signed_intent"
    assert signed["submission_attempt_budgets"][
        canonical.SN39_UID30_FLEET_BUDGET_SCOPE
    ] == {"limit": 1, "ids": [attempt_id]}
    assert attempt_id in signed["submission_attempt_ids"]
    assert "submission_pending_predecessor_journal_zlib_b64" not in signed
    assert not canonical._abort_unsigned_common_submission(args, attempt_id=attempt_id)


def test_canonical_presign_reproves_exact_predecessor_and_singleton(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    state_path = runtime / canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
    predecessor_identity = {
        "subnet_owner_hotkey": canonical.SN39_BURN_HOTKEY,
        "next_epoch_start_block": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK + 200,
        "inclusion_policy": {
            "valid_from_block": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK - 2,
            "valid_until_block": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK + 100,
            "valid_from_time": "2026-08-28T00:00:00.000Z",
            "valid_until_time": "2026-08-30T00:00:00.000Z",
            "require_commit_reveal_disabled": True,
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "expected_next_epoch_start_block": (
                canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK + 200
            ),
        },
    }
    predecessor_intent = {"fixture": "two-uid-intent"}
    predecessor_receipt = {"fixture": "two-uid-receipt"}
    monkeypatch.setattr(
        canonical,
        "SN39_UID30_FLEET_PREDECESSOR_IDENTITY_SHA256",
        canonical._sha256_document(predecessor_identity).removeprefix("sha256:"),
    )
    monkeypatch.setattr(
        canonical,
        "SN39_UID30_FLEET_PREDECESSOR_INTENT_SHA256",
        canonical._sha256_document(predecessor_intent).removeprefix("sha256:"),
    )
    monkeypatch.setattr(
        canonical,
        "SN39_UID30_FLEET_PREDECESSOR_RECEIPT_SHA256",
        canonical._sha256_document(predecessor_receipt).removeprefix("sha256:"),
    )
    predecessor = {
        "submission_pending_id": None,
        "submission_active_lane": "authority",
        "submission_attempt_ids": [
            canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
            canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        ],
        "submission_attempt_count": 2,
        "submission_finalized_count": 2,
        "submission_highest_source_epoch": (
            canonical.SN39_UID30_FLEET_PREDECESSOR_SOURCE_EPOCH
        ),
        "submission_finalized_id": canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        "submission_finalized_lane": "authority",
        "submission_finalized_reviewed_uid30_contract": "two_miner_successor",
        "submission_finalized_identity": predecessor_identity,
        "submission_finalized_broadcast_intent": predecessor_intent,
        "submission_finalized_receipt": predecessor_receipt,
        "submission_attempt_budgets": {
            "launch_full_gate": {
                "limit": 1,
                "ids": [canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
            },
            "authority_bounded": {
                "limit": 1,
                "ids": [canonical.SN39_UID30_FLEET_PREDECESSOR_ID],
            },
        },
        "submission_genesis_hash": submit.FINNEY_GENESIS_HASH,
        "provenance_netuid": 39,
        "submission_validator_hotkey": submit.UID30_HOTKEY,
    }
    predecessor_bytes = canonical._canonical_json_bytes(predecessor)
    state_path.write_bytes(predecessor_bytes)
    state_path.chmod(0o600)
    predecessor_digest = hashlib.sha256(predecessor_bytes).hexdigest()
    monkeypatch.setattr(submit, "DEFAULT_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(canonical, "_VALIDATOR_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(
        canonical,
        "SN39_UID30_FLEET_PREDECESSOR_JOURNAL_SHA256",
        predecessor_digest,
    )

    document = submit.validate_reviewed_preview(_preview())
    fleet_state = _fleet_state()
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256="d" * 64,
        fresh=document,
        state=fleet_state,
    )
    attempt_id = launch._attempt_id(identity)
    args = submit._submission_contract(preview_sha256="d" * 64)
    canonical._reserve_common_submission(
        args,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )

    class Substrate:
        def get_block_hash(self, block: int) -> str:
            return {
                EVIDENCE_BLOCK: EVIDENCE_HASH,
                RECHECK_BLOCK: RECHECK_HASH,
                fleet_state.base.block_number: fleet_state.base.block_hash,
                canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK: (
                    canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH
                ),
            }[block]

        def query(
            self,
            *,
            module: str,
            storage_function: str,
            params: list[int],
            block_hash: str,
        ) -> SimpleNamespace:
            assert module == "SubtensorModule"
            if storage_function == "WeightsVersionKey":
                return SimpleNamespace(value=0)
            assert storage_function == "Weights"
            assert params[1] == 30
            assert block_hash in {
                fleet_state.base.block_hash,
                canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH,
            }
            return SimpleNamespace(value=[[8, W], [124, W]])

    substrate = Substrate()
    preflight = SimpleNamespace(
        subtensor=SimpleNamespace(substrate=substrate),
        wallet=SimpleNamespace(
            hotkey=SimpleNamespace(ss58_address=submit.UID30_HOTKEY)
        ),
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        validator_uid=30,
        validator_hotkey=submit.UID30_HOTKEY,
        subnet_owner_hotkey=canonical.SN39_BURN_HOTKEY,
        block=fleet_state.base.block_number,
        finalized_hash=fleet_state.base.block_hash,
        next_epoch_start_block=fleet_state.base.next_epoch_start_block,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        validator_blocks_since_last_update=(
            fleet_state.base.block_number - canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
        ),
    )
    monkeypatch.setattr(
        canonical, "_require_inclusion_policy_ready", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        canonical,
        "_require_uid_mapping_stability",
        lambda *_a, **_k: identity["uid_safety"],
    )
    monkeypatch.setattr(
        canonical,
        "_classify_finalized_receipt",
        lambda *_a, **_k: canonical.PASS,
    )

    canonical._authorize_reviewed_uid30_submission(
        args,
        preflight=preflight,
        attempt_id=attempt_id,
        version_key=VERSION_KEY,
        wire_uids=[124],
        wire_weights=[W],
    )

    reached: list[str] = []
    monkeypatch.setattr(
        canonical,
        "_require_uid_mapping_stability",
        lambda *_a, **_k: _uid_safety(uid124_safe=False),
    )

    def authorize_then_sign() -> None:
        canonical._authorize_reviewed_uid30_submission(
            args,
            preflight=preflight,
            attempt_id=attempt_id,
            version_key=VERSION_KEY,
            wire_uids=[124],
            wire_weights=[W],
        )
        reached.append("sign")

    with pytest.raises(
        Exception,
        match="both fixed UID mappings replacement-safe",
    ):
        authorize_then_sign()
    assert reached == []

    monkeypatch.setattr(
        canonical,
        "_require_uid_mapping_stability",
        lambda *_a, **_k: identity["uid_safety"],
    )

    with pytest.raises(Exception, match="exact reservation or predecessor"):
        canonical._authorize_reviewed_uid30_submission(
            args,
            preflight=preflight,
            attempt_id=attempt_id,
            version_key=VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[W, W],
        )


def test_cli_exposes_no_arbitrary_weight_retry_or_broadcast_flags() -> None:
    help_text = submit._parser().format_help()
    source = inspect.getsource(submit._parser)

    assert "--retry" not in source
    assert "--broadcast" not in source
    assert "--uid" not in source
    assert "--weight" not in source
    assert "--burn" not in source
    assert "--endpoint" not in source
    assert "submit" in help_text
    assert "recover" in help_text


def test_archive_predecessor_gate_requires_exact_historical_call_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = canonical.SN39_BURN_HOTKEY
    policy = SimpleNamespace(name="pinned-predecessor-policy")
    verdict = [canonical.PASS]
    observed: dict[str, object] = {}

    class ArchiveSubstrate:
        def get_block_hash(self, block: int) -> str:
            if block == 0:
                return submit.FINNEY_GENESIS_HASH
            assert block == canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
            return canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH

        def get_block_number(self, block_hash: str) -> int:
            assert block_hash == canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH
            return canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK

        def query(self, **kwargs: object) -> SimpleNamespace:
            observed["query"] = kwargs
            return SimpleNamespace(value=[[8, W], [124, W]])

    subtensor = SimpleNamespace(substrate=ArchiveSubstrate())
    preflight = canonical.ChainPreflight(
        wallet=SimpleNamespace(
            hotkey=SimpleNamespace(ss58_address=submit.UID30_HOTKEY)
        ),
        subtensor=subtensor,
        hotkey_to_uid={submit.UID30_HOTKEY: 30},
        validator_hotkey=submit.UID30_HOTKEY,
        validator_uid=30,
        block=RECHECK_BLOCK,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        connection_target=submit.ARCHIVE_CHAIN_ENDPOINT,
    )
    predecessor_identity = {"subnet_owner_hotkey": owner}
    journal = {
        "submission_pending_id": None,
        "submission_finalized_id": canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        "submission_finalized_identity": predecessor_identity,
    }
    monkeypatch.setattr(submit, "_assert_pristine_predecessor", lambda _args: None)
    monkeypatch.setattr(
        canonical, "_submission_state_path", lambda _args: Path("/fixed/journal.json")
    )
    monkeypatch.setattr(canonical, "_read_state", lambda _path: journal)
    monkeypatch.setattr(
        canonical,
        "_policy_from_submission_identity",
        lambda identity: policy if identity == predecessor_identity else pytest.fail(),
    )

    def classify(observed_subtensor: object, **kwargs: object) -> str:
        assert observed_subtensor is subtensor
        observed["classify"] = kwargs
        if verdict[0] != canonical.PASS:
            reason_out = kwargs["reason_out"]
            assert isinstance(reason_out, list)
            reason_out.append("historical state unavailable")
        return verdict[0]

    monkeypatch.setattr(canonical, "_classify_finalized_receipt", classify)

    submit._require_archive_predecessor(SimpleNamespace(), preflight)

    assert observed["query"] == {
        "module": "SubtensorModule",
        "storage_function": "Weights",
        "params": [canonical.get_mechid_storage_index(39, 0), 30],
        "block_hash": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH,
    }
    classify_args = observed["classify"]
    assert isinstance(classify_args, dict)
    assert classify_args["wire_uids"] == [8, 124]
    assert classify_args["wire_weights"] == [W, W]
    assert classify_args["inclusion_policy"] is policy

    verdict[0] = canonical.NOT_PROVEN
    with pytest.raises(launch.UID30LaunchError, match="historical state unavailable"):
        submit._require_archive_predecessor(SimpleNamespace(), preflight)


def test_fixed_archive_route_bypasses_pruned_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CATHEDRAL_CHAIN_ENDPOINT", "wss://entrypoint-finney.opentensor.ai:443"
    )

    assert (
        canonical._chain_preflight_connection_target(
            "finney", submit.ARCHIVE_CHAIN_ENDPOINT
        )
        == submit.ARCHIVE_CHAIN_ENDPOINT
    )


def test_later_heads_reject_inconsistent_finalized_hash_number_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finalized_hash = "0x" + "a" * 64
    different_hash = "0x" + "b" * 64

    class InconsistentFinalityRPC:
        def get_chain_finalised_head(self) -> str:
            return finalized_hash

        def get_block_number(self, observed_hash: str) -> int:
            assert observed_hash == finalized_hash
            return 200

        def get_block_hash(self, block_number: int) -> str:
            assert block_number == 200
            return different_hash

    state = SimpleNamespace(
        preflight=SimpleNamespace(
            subtensor=SimpleNamespace(substrate=InconsistentFinalityRPC())
        ),
        genesis_hash=submit.FINNEY_GENESIS_HASH,
    )
    monkeypatch.setattr(
        submit.second_miner_plan,
        "read_snapshot_at",
        lambda **_kwargs: pytest.fail(
            "an inconsistent finalized head must be rejected before snapshot reads"
        ),
    )

    with pytest.raises(
        launch.UID30LaunchAmbiguous,
        match="head number and hash do not match",
    ):
        submit._verify_later_finalized_heads(
            state=state,
            submission=SimpleNamespace(block_number=198),
            wait_seconds=0,
        )


def _prepare_submit_harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    submit_error: Exception | None = None,
    abort_result: bool = False,
) -> tuple[list[str], dict[str, object]]:
    document = _preview()
    state = _fleet_state()
    identity = {"fixed": "identity"}
    observed: dict[str, object] = {}
    sequence: list[str] = []
    monkeypatch.setattr(
        submit, "load_reviewed_preview", lambda *_args, **_kwargs: (document, "d" * 64)
    )
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: (
            contextlib.nullcontext() if lane == "authority" else pytest.fail(lane)
        ),
    )
    monkeypatch.setattr(submit, "read_fleet_state", lambda: state)
    monkeypatch.setattr(
        submit,
        "_require_archive_predecessor",
        lambda _args, _preflight: sequence.append("historical"),
    )
    monkeypatch.setattr(submit, "_state_matches_document", lambda *_a, **_k: None)

    def collect_fresh(path: str, *, chain_endpoint: str | None = None) -> dict:
        assert path == "/pinned/qvl"
        assert chain_endpoint == submit.ARCHIVE_CHAIN_ENDPOINT
        sequence.append("qvl")
        return document

    monkeypatch.setattr(preview, "collect_preview", collect_fresh)
    monkeypatch.setattr(submit, "validate_reviewed_preview", lambda row: row)
    monkeypatch.setattr(submit, "_same_fleet_identity", lambda *_a, **_k: None)
    monkeypatch.setattr(submit, "_attempt_identity", lambda **_kwargs: identity)
    monkeypatch.setattr(submit, "_validate_attempt_identity", lambda *_a, **_k: None)
    monkeypatch.setattr(launch, "_attempt_id", lambda _row: "sha256:" + "e" * 64)
    monkeypatch.setattr(
        canonical,
        "_reserve_common_submission",
        lambda *_a, **_k: sequence.append("reserve"),
    )

    def chain_submit(preflight, **kwargs):
        sequence.append("submit")
        observed.update(kwargs)
        assert preflight is state.base.preflight
        if submit_error is not None:
            raise submit_error
        return SimpleNamespace(receipt="receipt")

    monkeypatch.setattr(canonical, "_submit_exact_sn39_extrinsic", chain_submit)
    submission = canonical.ChainSubmission(
        success=True,
        extrinsic_hash="0x" + "1" * 64,
        block_hash="0x" + "2" * 64,
        block_number=state.base.block_number + 1,
        finalized=False,
    )
    monkeypatch.setattr(launch, "_receipt_submission", lambda *_a, **_k: submission)
    monkeypatch.setattr(
        canonical,
        "_record_pending_submission_receipt",
        lambda *_a, **_k: sequence.append("receipt"),
    )
    monkeypatch.setattr(
        launch,
        "_finalized_readback",
        lambda **_k: (
            sequence.append("readback") or {"dests": [124], "weights_u16": [W]}
        ),
    )
    monkeypatch.setattr(
        submit,
        "_verification_state",
        lambda *_a, **_k: SimpleNamespace(name="verification"),
    )
    later = (
        (submission.block_number + 1, "0x" + "3" * 64),
        (submission.block_number + 2, "0x" + "4" * 64),
    )
    monkeypatch.setattr(
        submit,
        "_verify_later_finalized_heads",
        lambda **_k: sequence.append("later") or later,
    )
    monkeypatch.setattr(
        canonical,
        "_record_pending_proof_status",
        lambda *_a, **_k: sequence.append("proof"),
    )
    monkeypatch.setattr(
        canonical,
        "_finalize_common_submission",
        lambda *_a, **_k: sequence.append("finalize"),
    )
    monkeypatch.setattr(
        canonical,
        "_abort_unsigned_common_submission",
        lambda *_a, **_k: sequence.append("abort") or abort_result,
    )
    return sequence, observed


def test_submit_calls_exact_singleton_once_and_requires_exact_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sequence, observed = _prepare_submit_harness(monkeypatch)

    result = submit.submit_reviewed_fleet(
        preview_path="/reviewed.json",
        reviewed_sha256="d" * 64,
        qvl_path="/pinned/qvl",
        confirm=True,
        exclusive_writer_asserted=True,
    )

    assert sequence == [
        "historical",
        "qvl",
        "reserve",
        "submit",
        "receipt",
        "readback",
        "later",
        "proof",
        "finalize",
    ]
    assert observed["wire_uids"] == [124]
    assert observed["wire_weights"] == [W]
    assert observed["allow_reviewed_uid30_finalized_descendant"] is False
    assert result.wire_uids == (124,)
    assert result.wire_weights == (W,)


def test_archive_predecessor_refusal_happens_before_qvl_and_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sequence, _observed = _prepare_submit_harness(monkeypatch)

    def refuse(_args: object, _preflight: object) -> None:
        sequence.append("archive-refused")
        raise launch.UID30LaunchError("archive history unavailable")

    monkeypatch.setattr(submit, "_require_archive_predecessor", refuse)

    with pytest.raises(launch.UID30LaunchError, match="archive history unavailable"):
        submit.submit_reviewed_fleet(
            preview_path="/reviewed.json",
            reviewed_sha256="d" * 64,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
        )

    assert sequence == ["archive-refused"]


def test_signed_uncertainty_is_one_attempt_and_never_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sequence, _observed = _prepare_submit_harness(
        monkeypatch,
        submit_error=TimeoutError("receipt unavailable after signed intent"),
        abort_result=False,
    )

    with pytest.raises(launch.UID30LaunchAmbiguous, match="do not retry"):
        submit.submit_reviewed_fleet(
            preview_path="/reviewed.json",
            reviewed_sha256="d" * 64,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
        )

    assert sequence == ["historical", "qvl", "reserve", "submit", "abort"]


def test_recovery_source_has_no_submission_call() -> None:
    source = inspect.getsource(submit.recover_reviewed_fleet)

    assert "_submit_exact_sn39_extrinsic" not in source
    assert "wallet" not in source


def test_recovery_preflight_uses_fixed_archive_not_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CATHEDRAL_CHAIN_ENDPOINT", "wss://entrypoint-finney.opentensor.ai:443"
    )
    preflight = canonical.ChainPreflight(
        wallet=SimpleNamespace(
            hotkey=SimpleNamespace(ss58_address=submit.UID30_HOTKEY)
        ),
        subtensor=SimpleNamespace(),
        hotkey_to_uid={submit.UID30_HOTKEY: 30},
        validator_hotkey=submit.UID30_HOTKEY,
        validator_uid=30,
        block=RECHECK_BLOCK,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        genesis_hash=submit.FINNEY_GENESIS_HASH,
        connection_target=submit.ARCHIVE_CHAIN_ENDPOINT,
    )
    observed: dict[str, object] = {}

    def chain_preflight(**kwargs: object) -> canonical.ChainPreflight:
        observed.update(kwargs)
        return preflight

    monkeypatch.setattr(canonical, "chain_preflight", chain_preflight)

    assert submit._archive_recovery_preflight() is preflight
    assert observed["network"] == "finney"
    assert observed["connection_endpoint"] == submit.ARCHIVE_CHAIN_ENDPOINT


def test_signed_journal_identity_mismatch_is_ambiguous_not_no_write() -> None:
    document = submit.validate_reviewed_preview(_preview())
    digest = "d" * 64
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256=digest,
        fresh=document,
        state=_fleet_state(),
    )
    attempt_id = launch._attempt_id(identity)
    identity["uid_weights"] = [[8, 1.0], [124, 1.0]]
    journal = {
        "submission_pending_id": attempt_id,
        "submission_pending_lane": "authority",
        "submission_pending_reviewed_uid30_contract": ("same_uid_fleet_consolidation"),
        "submission_pending_identity": identity,
        "submission_pending_broadcast_intent": {
            "extrinsic_hash": "0x" + "1" * 64,
            "nonce": 9,
            "era_reference_block": identity["mapping_block"],
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "version_key": VERSION_KEY,
            "wire_uids": [124],
            "wire_weights": [W],
        },
    }

    with pytest.raises(launch.UID30LaunchContradiction, match="reviewed proof"):
        submit._signed_record(
            journal,
            prefix="pending",
            reviewed=document,
            preview_sha256=digest,
        )


def test_finalized_recovery_is_chain_read_only_and_proves_same_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = submit.validate_reviewed_preview(_preview())
    digest = "d" * 64
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256=digest,
        fresh=document,
        state=_fleet_state(),
    )
    attempt_id = launch._attempt_id(identity)
    intent = {
        "extrinsic_hash": "0x" + "1" * 64,
        "nonce": 9,
        "era_reference_block": identity["mapping_block"],
        "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": VERSION_KEY,
        "wire_uids": [124],
        "wire_weights": [W],
    }
    receipt = {
        "extrinsic_hash": intent["extrinsic_hash"],
        "block_hash": "0x" + "2" * 64,
        "block_number": identity["mapping_block"] + 1,
        "version_key": VERSION_KEY,
        "wire_uids": [124],
        "wire_weights": [W],
    }
    journal = {
        "submission_pending_id": None,
        "submission_pending_proof_status": canonical.PASS,
        "submission_finalized_id": attempt_id,
        "submission_finalized_lane": "authority",
        "submission_finalized_identity": identity,
        "submission_finalized_broadcast_intent": intent,
        "submission_finalized_receipt": receipt,
        "submission_finalized_reviewed_uid30_contract": (
            "same_uid_fleet_consolidation"
        ),
    }
    preflight = SimpleNamespace(name="read-only-preflight")
    later = (
        (receipt["block_number"] + 1, "0x" + "3" * 64),
        (receipt["block_number"] + 2, "0x" + "4" * 64),
    )
    monkeypatch.setattr(
        submit,
        "load_reviewed_preview",
        lambda *_a, **_k: (document, digest),
    )
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: contextlib.nullcontext(),
    )
    monkeypatch.setattr(canonical, "_read_state", lambda _path: journal)
    monkeypatch.setattr(canonical, "_private_state_sha256", lambda _path: "0" * 64)
    monkeypatch.setattr(submit, "_archive_recovery_preflight", lambda: preflight)
    monkeypatch.setattr(
        submit,
        "_verification_state",
        lambda observed, _reviewed: SimpleNamespace(preflight=observed),
    )
    monkeypatch.setattr(launch, "_finalized_readback", lambda **_k: {"ok": True})
    monkeypatch.setattr(submit, "_verify_later_finalized_heads", lambda **_k: later)
    monkeypatch.setattr(
        canonical,
        "_submit_exact_sn39_extrinsic",
        lambda *_a, **_k: pytest.fail("recovery must never submit"),
    )
    monkeypatch.setattr(
        canonical,
        "_finalize_common_submission",
        lambda *_a, **_k: pytest.fail("already-finalized recovery must not mutate"),
    )

    result = submit.recover_reviewed_fleet(
        preview_path="/reviewed.json",
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
    )

    assert result.status == "ALREADY_FINALIZED"
    assert result.attempt_id == attempt_id
    assert result.wire_uids == (124,)
    assert result.wire_weights == (W,)
    assert result.later_finalized_heads == later


def test_repeated_recovery_reports_consumed_expired_attempt_without_chain_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = submit.validate_reviewed_preview(_preview())
    digest = "d" * 64
    identity = submit._attempt_identity(
        reviewed=document,
        preview_sha256=digest,
        fresh=document,
        state=_fleet_state(),
    )
    attempt_id = launch._attempt_id(identity)
    intent = {
        "extrinsic_hash": "0x" + "1" * 64,
        "nonce": 9,
        "era_reference_block": identity["mapping_block"],
        "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": VERSION_KEY,
        "wire_uids": [124],
        "wire_weights": [W],
    }
    journal = {
        "submission_pending_id": None,
        "submission_expired_status": canonical.EXPIRED_WITHOUT_INCLUSION,
        "submission_expired_id": attempt_id,
        "submission_expired_lane": "authority",
        "submission_expired_identity": identity,
        "submission_expired_broadcast_intent": intent,
        "submission_attempt_ids": [attempt_id],
        "submission_attempt_budgets": {
            canonical.SN39_UID30_FLEET_BUDGET_SCOPE: {
                "limit": 1,
                "ids": [attempt_id],
            }
        },
    }
    monkeypatch.setattr(
        submit,
        "load_reviewed_preview",
        lambda *_a, **_k: (document, digest),
    )
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: contextlib.nullcontext(),
    )
    monkeypatch.setattr(canonical, "_read_state", lambda _path: journal)
    monkeypatch.setattr(canonical, "_private_state_sha256", lambda _path: "0" * 64)
    monkeypatch.setattr(
        submit,
        "_archive_recovery_preflight",
        lambda: pytest.fail("terminal expiry needs no further chain access"),
    )

    result = submit.recover_reviewed_fleet(
        preview_path="/reviewed.json",
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
    )

    assert result.status == canonical.EXPIRED_WITHOUT_INCLUSION
    assert result.attempt_id == attempt_id
    assert result.extrinsic_hash == intent["extrinsic_hash"]
    assert result.wire_weights is None


def test_preview_module_stays_writer_free_after_submit_command_exists() -> None:
    source = inspect.getsource(preview)

    assert "uid30_fleet_submit" not in source
    assert "_submit_exact_sn39_extrinsic" not in source
    assert "_reserve_common_submission" not in source
