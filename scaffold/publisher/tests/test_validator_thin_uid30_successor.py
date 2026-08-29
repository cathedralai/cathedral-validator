from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as validator


MAPPING_BLOCK = validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK + 200
FINALIZED_HASH = "0x" + "f" * 64
SUCCESSOR_ATTEMPT_ID = "sha256:" + "e" * 64
SUCCESSOR_EXTRINSIC_HASH = "0x" + "d" * 64
SUCCESSOR_BLOCK_HASH = "0x" + "c" * 64


def _inclusion_policy(*, block: int = MAPPING_BLOCK) -> dict[str, object]:
    return {
        "valid_from_block": block - 2,
        "valid_until_block": block + 64,
        "valid_from_time": "2026-08-28T00:00:00.000Z",
        "valid_until_time": "2026-09-01T00:00:00.000Z",
        "require_commit_reveal_disabled": True,
        "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
        "expected_next_epoch_start_block": block + 200,
    }


def _predecessor() -> dict[str, object]:
    body: dict[str, object] = {
        "attempt_id": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
        "identity_sha256": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256
        ),
        "intent_sha256": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256,
        "receipt_sha256": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256
        ),
        "uid_safety_sha256": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256
        ),
        "canonical_journal_filename": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        ),
        "journal_identity_sha256": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_IDENTITY
        ),
        "original_journal_sha256": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
        ),
        "extrinsic_hash": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        ),
        "block_hash": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        "block_number": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "wire": [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]],
    }
    return {**body, "sha256": validator._sha256_document(body)}


def _proof(
    *,
    hotkey: str,
    uid: int,
    ip: str,
    spki: str,
    anchor_number: int,
    anchor_hash: str,
) -> dict[str, object]:
    return {
        "hotkey": hotkey,
        "uid": uid,
        "ip": ip,
        "port": 8081,
        "qvl_status": validator.PASS,
        "qvl_digest": validator.SN39_UID30_SUCCESSOR_QVL_SHA256,
        "quote_sha256": hashlib.sha256(f"quote:{hotkey}".encode()).hexdigest(),
        "report_data_sha256": hashlib.sha256(
            f"report:{hotkey}".encode()
        ).hexdigest(),
        "tls_spki_sha256": spki,
        "sat_units": 20,
        "sat_rule": validator.SN39_UID30_SUCCESSOR_SAT_RULE,
        "anchor_number": anchor_number,
        "anchor_hash": anchor_hash,
    }


def _successor_identity() -> dict[str, object]:
    proofs = [
        _proof(
            hotkey=validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
            uid=8,
            ip="34.46.19.69",
            spki="2" * 64,
            anchor_number=MAPPING_BLOCK - 2,
            anchor_hash="0x" + "a" * 64,
        ),
        _proof(
            hotkey=validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
            uid=124,
            ip="35.222.166.235",
            spki="3" * 64,
            anchor_number=MAPPING_BLOCK - 1,
            anchor_hash="0x" + "b" * 64,
        ),
    ]
    safety = {
        "schema": "cathedral_sn39_uid_safety_v2",
        "targets": [
            [8, validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY],
            [124, validator.SN39_UID30_LAUNCH_MINER_HOTKEY],
        ],
    }
    predecessor = _predecessor()
    preview_digest = "sha256:" + "1" * 64
    reviewed = {
        "valid_from_block": MAPPING_BLOCK - 2,
        "valid_until_block": MAPPING_BLOCK + 64,
        "miners": copy.deepcopy(proofs),
        "vector": {
            "dests": [8, 124],
            "weights_u16": [65535, 65535],
            "normalized": [[8, "1.0"], [124, "1.0"]],
            "expected_storage": [[8, 65535], [124, 65535]],
            "burn_destination": None,
            "burn_weight_u16": 0,
        },
        "predecessor": predecessor,
    }
    return {
        "network": "finney",
        "netuid": 39,
        "mapping_block": MAPPING_BLOCK,
        "validator_hotkey": validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
        "validator_uid": validator.SN39_UID30_LAUNCH_VALIDATOR_UID,
        "source_epoch": MAPPING_BLOCK,
        "uid_weights": [[8, 1.0], [124, 1.0]],
        "uid_hotkeys": [
            [8, validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY],
            [124, validator.SN39_UID30_LAUNCH_MINER_HOTKEY],
        ],
        "allocation_contract": validator.SN39_UID30_SUCCESSOR_POLICY,
        "burn_destination": None,
        "burn_share": 0.0,
        "subnet_owner_hotkey": validator.SN39_BURN_HOTKEY,
        "uid_safety": safety,
        "uid_safety_sha256": validator._sha256_document(safety).removeprefix(
            "sha256:"
        ),
        "next_epoch_start_block": MAPPING_BLOCK + 200,
        "inclusion_policy": _inclusion_policy(),
        "successor_schema": validator.SN39_UID30_SUCCESSOR_SCHEMA,
        "successor_contract": validator.SN39_UID30_SUCCESSOR_POLICY,
        "successor_preview_sha256": preview_digest,
        "report_id": preview_digest,
        "operator_declared_authority": True,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "predecessor": predecessor,
        "reviewed_preview": reviewed,
        "fresh_miner_evidence": proofs,
        "fresh_evidence_sha256": validator._sha256_document(
            {"proofs": proofs}
        ).removeprefix("sha256:"),
    }


def test_strict_successor_contract_uses_dynamic_uids_and_zero_burn() -> None:
    contract = validator._strict_zero_burn_uid30_successor_contract(
        _successor_identity(), lane="authority"
    )

    assert contract == {
        "kind": "two_miner_successor",
        "owner": validator.SN39_BURN_HOTKEY,
        "uid_weights": ((8, 1.0), (124, 1.0)),
        "uid_hotkeys": (
            (8, validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY),
            (124, validator.SN39_UID30_LAUNCH_MINER_HOTKEY),
        ),
    }
    assert validator.SN39_UID30_LAUNCH_VALIDATOR_UID not in dict(
        contract["uid_weights"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_spki",
        "duplicate_endpoint",
        "private_ip",
        "qvl_not_pass",
        "wrong_qvl_digest",
        "zero_sat",
        "bool_sat",
        "missing_quote",
        "missing_report_data",
        "future_anchor",
    ],
)
def test_strict_successor_contract_rejects_incomplete_or_shared_machine_proof(
    mutation: str,
) -> None:
    identity = _successor_identity()
    fresh = identity["fresh_miner_evidence"]
    assert isinstance(fresh, list)
    first, second = fresh
    if mutation == "duplicate_spki":
        second["tls_spki_sha256"] = first["tls_spki_sha256"]
    elif mutation == "duplicate_endpoint":
        second["ip"] = first["ip"]
    elif mutation == "private_ip":
        second["ip"] = "10.0.0.8"
    elif mutation == "qvl_not_pass":
        second["qvl_status"] = validator.FAIL
    elif mutation == "wrong_qvl_digest":
        second["qvl_digest"] = "0" * 64
    elif mutation == "zero_sat":
        second["sat_units"] = 0
    elif mutation == "bool_sat":
        second["sat_units"] = True
    elif mutation == "missing_quote":
        second.pop("quote_sha256")
    elif mutation == "missing_report_data":
        second.pop("report_data_sha256")
    elif mutation == "future_anchor":
        second["anchor_number"] = MAPPING_BLOCK + 1
    identity["fresh_evidence_sha256"] = validator._sha256_document(
        {"proofs": fresh}
    ).removeprefix("sha256:")

    with pytest.raises(validator.wire.VectorError):
        validator._strict_zero_burn_uid30_successor_contract(
            identity, lane="authority"
        )


@pytest.mark.parametrize("bad_uid", [True, "8"])
def test_strict_successor_contract_rejects_non_integer_uid(bad_uid: object) -> None:
    identity = _successor_identity()
    identity["uid_weights"][0][0] = bad_uid

    with pytest.raises(validator.wire.VectorError, match="two-row identity"):
        validator._strict_zero_burn_uid30_successor_contract(
            identity, lane="authority"
        )


def _patch_synthetic_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    predecessor_identity = {
        "subnet_owner_hotkey": validator.SN39_BURN_HOTKEY,
        "next_epoch_start_block": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK + 200
        ),
        "inclusion_policy": _inclusion_policy(
            block=validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        ),
    }
    predecessor_identity["inclusion_policy"]["expected_next_epoch_start_block"] = (
        predecessor_identity["next_epoch_start_block"]
    )
    predecessor_intent = {
        "extrinsic_hash": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH,
        "nonce": 7,
        "era_reference_block": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH
        ),
        "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "wire_uids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID],
        "wire_weights": [65535],
    }
    predecessor_receipt = {
        "extrinsic_hash": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH,
        "block_hash": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        "block_number": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "wire_uids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID],
        "wire_weights": [65535],
    }
    predecessor_safety = {"schema": "synthetic-predecessor-safety"}
    for name, document in (
        ("SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256", predecessor_identity),
        ("SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256", predecessor_intent),
        ("SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256", predecessor_receipt),
        ("SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256", predecessor_safety),
    ):
        monkeypatch.setattr(
            validator,
            name,
            validator._sha256_document(document).removeprefix("sha256:"),
        )
    return (
        predecessor_identity,
        predecessor_intent,
        predecessor_receipt,
        predecessor_safety,
    )


def _predecessor_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    identity, intent, receipt, safety = _patch_synthetic_predecessor(monkeypatch)
    attempt_id = validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    return {
        "submission_genesis_hash": validator.FINNEY_GENESIS_HASH,
        "provenance_netuid": 39,
        "submission_validator_hotkey": (
            validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        ),
        "submission_active_lane": "authority",
        "submission_attempt_ids": [attempt_id],
        "submission_attempt_count": 1,
        "submission_attempt_budgets": {
            "launch_full_gate": {"limit": 1, "ids": [attempt_id]}
        },
        "submission_highest_source_epoch": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH
        ),
        "submission_finalized_count": 1,
        "submission_finalized_id": attempt_id,
        "submission_finalized_lane": "authority",
        "submission_finalized_identity": identity,
        "submission_finalized_broadcast_intent": intent,
        "submission_finalized_receipt": receipt,
        "submission_extrinsic_hash": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        ),
        "submission_block_hash": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        ),
        "submission_block_number": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        "submission_version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "submission_launch_status": "finalized",
        "submission_launch_attempt_id": attempt_id,
        "submission_launch_attempt_ids": [attempt_id],
        "submission_launch_budget_limit": 1,
        "submission_launch_identity": identity,
        "submission_launch_broadcast_intent": intent,
        "submission_launch_extrinsic_hash": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        ),
        "submission_launch_block_hash": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        ),
        "submission_launch_block_number": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        ),
        "submission_launch_version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "submission_launch_uid_safety": safety,
        "submission_continuous_enabled": False,
    }


def _runtime(root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        broadcast=True,
        offline=False,
        network="finney",
        netuid=39,
        wallet_name="cathedral",
        wallet_hotkey="default",
        runtime_root=root,
        state_file=root / "authority-lane.json",
        max_submissions=1,
        require_full_provenance_for_broadcast=False,
        _continuous_submission_authorization=None,
        _submission_genesis_hash=validator.FINNEY_GENESIS_HASH,
        _submission_validator_hotkey=(
            validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        ),
        _uid30_two_miner_successor_preview_sha256="1" * 64,
    )


def _write_predecessor_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, SimpleNamespace]:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    runtime_root.chmod(0o700)
    state_path = runtime_root / validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
    state = _predecessor_state(monkeypatch)
    body = validator._canonical_json_bytes(state)
    state_path.write_bytes(body)
    state_path.chmod(0o600)
    monkeypatch.setattr(
        validator,
        "SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256",
        hashlib.sha256(body).hexdigest(),
    )
    monkeypatch.setattr(validator, "_VALIDATOR_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(validator, "_submission_state_path", lambda _args: state_path)
    return state_path, _runtime(runtime_root)


def test_successor_reservation_preserves_predecessor_and_commits_one_new_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity()

    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    reserved = validator._read_state(state_path)
    assert reserved["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    ]
    assert reserved["submission_attempt_budgets"] == {
        "launch_full_gate": {
            "limit": 1,
            "ids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
        }
    }
    assert reserved["submission_pending_budget_scope"] == "authority_bounded"
    assert reserved["submission_pending_budget_limit"] == 1
    assert reserved["submission_pending_reviewed_uid30_contract"] == (
        "two_miner_successor"
    )

    intent = {
        "extrinsic_hash": SUCCESSOR_EXTRINSIC_HASH,
        "nonce": 11,
        "era_reference_block": MAPPING_BLOCK,
        "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "wire_uids": [8, 124],
        "wire_weights": [65535, 65535],
    }
    validator._commit_pending_signed_attempt(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        intent=intent,
    )
    signed = validator._read_state(state_path)
    assert signed["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
        SUCCESSOR_ATTEMPT_ID,
    ]
    assert signed["submission_attempt_budgets"] == {
        "launch_full_gate": {
            "limit": 1,
            "ids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
        },
        "authority_bounded": {"limit": 1, "ids": [SUCCESSOR_ATTEMPT_ID]},
    }
    assert signed["submission_launch_attempt_id"] == (
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    )


def test_unsigned_successor_abort_consumes_no_attempt_or_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=_successor_identity(),
    )

    assert validator._abort_unsigned_common_submission(
        runtime, attempt_id=SUCCESSOR_ATTEMPT_ID
    )
    state = validator._read_state(state_path)
    assert state["submission_pending_id"] is None
    assert state["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    ]
    assert state["submission_attempt_budgets"] == {
        "launch_full_gate": {
            "limit": 1,
            "ids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
        }
    }


def test_signed_successor_fence_forbids_any_replacement_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity()
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    validator._commit_pending_signed_attempt(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        intent={
            "extrinsic_hash": SUCCESSOR_EXTRINSIC_HASH,
            "nonce": 11,
            "era_reference_block": MAPPING_BLOCK,
            "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
            "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
            "wire_uids": [8, 124],
            "wire_weights": [65535, 65535],
        },
    )
    before = state_path.read_bytes()

    with pytest.raises(
        ValueError,
        match="predecessor journal bytes changed|pending reconciliation",
    ):
        validator._reserve_common_submission(
            runtime,
            lane="authority",
            attempt_id="sha256:" + "9" * 64,
            identity=identity,
        )

    assert state_path.read_bytes() == before
    assert validator._read_state(state_path)["submission_attempt_budgets"][
        "authority_bounded"
    ] == {"limit": 1, "ids": [SUCCESSOR_ATTEMPT_ID]}


def _preflight(
    substrate: object,
    *,
    hotkey_to_uid: dict[str, int] | None = None,
    blocks_since_update: int | None = None,
) -> validator.ChainPreflight:
    return validator.ChainPreflight(
        wallet=SimpleNamespace(
            hotkey=SimpleNamespace(
                ss58_address=validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
            )
        ),
        subtensor=SimpleNamespace(substrate=substrate),
        hotkey_to_uid=hotkey_to_uid
        or {
            validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY: 30,
            validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: 8,
            validator.SN39_UID30_LAUNCH_MINER_HOTKEY: 124,
        },
        validator_hotkey=validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
        validator_uid=30,
        block=MAPPING_BLOCK,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        commit_reveal_enabled=False,
        genesis_hash=validator.FINNEY_GENESIS_HASH,
        subnet_owner_hotkey=validator.SN39_BURN_HOTKEY,
        blocks_until_next_epoch=200,
        next_epoch_start_block=MAPPING_BLOCK + 200,
        weights_rate_limit=100,
        validator_blocks_since_last_update=(
            blocks_since_update
            if blocks_since_update is not None
            else MAPPING_BLOCK - validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        ),
        replacement_safe_hotkeys=frozenset(
            {
                validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
                validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
            }
        ),
        finalized_hash=FINALIZED_HASH,
    )


def _authorization_substrate(*, current_rows: object | None = None) -> object:
    anchor_hashes = {
        MAPPING_BLOCK - 2: "0x" + "a" * 64,
        MAPPING_BLOCK - 1: "0x" + "b" * 64,
    }

    def get_block_hash(block: int) -> str:
        if block == MAPPING_BLOCK:
            return FINALIZED_HASH
        if block == validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK:
            return validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        return anchor_hashes[block]

    def query(*, storage_function: str, block_hash: str, **_kwargs):
        if storage_function == "WeightsVersionKey":
            assert block_hash == FINALIZED_HASH
            return 0
        if storage_function == "Weights":
            if block_hash == FINALIZED_HASH:
                return (
                    current_rows
                    if current_rows is not None
                    else [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]]
                )
            assert block_hash == validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
            return [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]]
        raise AssertionError(storage_function)

    return SimpleNamespace(
        get_chain_finalised_head=lambda: FINALIZED_HASH,
        get_block_number=lambda block_hash: (
            MAPPING_BLOCK if block_hash == FINALIZED_HASH else pytest.fail(block_hash)
        ),
        get_block_hash=get_block_hash,
        query=query,
        get_account_next_index=lambda _hotkey: (_ for _ in ()).throw(
            AssertionError("refusal must precede nonce access")
        ),
    )


def test_exact_successor_pre_sign_authorization_accepts_dynamic_mapping_and_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity()
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    preflight = _preflight(_authorization_substrate())
    monkeypatch.setattr(
        validator,
        "_require_uid_mapping_stability",
        lambda *_args, **_kwargs: identity["uid_safety"],
    )
    monkeypatch.setattr(
        validator,
        "_classify_finalized_receipt",
        lambda *_args, **_kwargs: validator.PASS,
    )

    assert (
        validator._authorize_reviewed_uid30_submission(
            runtime,
            preflight=preflight,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65535],
        )
        is None
    )
    assert validator._read_state(state_path)["submission_pending_phase"] == (
        "unsigned_reserved"
    )


@pytest.mark.parametrize(
    "case",
    [
        "forward_mapping",
        "reverse_mapping",
        "last_update",
        "predecessor_row",
        "budget_scope",
        "canonical_root",
    ],
)
def test_successor_pre_sign_counterexamples_refuse_before_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity()
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    journal = validator._read_state(state_path)
    current_rows = None
    mappings = {
        validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY: 30,
        validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: 8,
        validator.SN39_UID30_LAUNCH_MINER_HOTKEY: 124,
    }
    blocks_since_update = None
    if case == "forward_mapping":
        mappings[validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY] = 9
    elif case == "reverse_mapping":
        mappings["5G6mgvL59o6AM8rFRYbbUpbzjjGwcVLUidpQ1vsz5UkZyw2o"] = 8
    elif case == "last_update":
        blocks_since_update = (
            MAPPING_BLOCK - validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK - 1
        )
    elif case == "predecessor_row":
        current_rows = [[8, 65535], [124, 65535]]
    elif case == "budget_scope":
        journal["submission_pending_budget_scope"] = "authority_unbounded"
    elif case == "canonical_root":
        runtime.runtime_root = tmp_path / "other-runtime"
    substrate = _authorization_substrate(current_rows=current_rows)
    preflight = _preflight(
        substrate,
        hotkey_to_uid=mappings,
        blocks_since_update=blocks_since_update,
    )
    monkeypatch.setattr(validator, "_read_state", lambda _path: journal)
    monkeypatch.setattr(
        validator,
        "_require_uid_mapping_stability",
        lambda *_args, **_kwargs: identity["uid_safety"],
    )
    monkeypatch.setattr(
        validator,
        "_classify_finalized_receipt",
        lambda *_args, **_kwargs: validator.PASS,
    )

    with pytest.raises(validator.wire.VectorError):
        validator._submit_exact_sn39_extrinsic(
            preflight,
            runtime_contract=runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
            netuid=39,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65535],
            mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
        )


def test_successor_finalization_and_restart_recovery_keep_two_rows_and_zero_burn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=_successor_identity(),
    )
    validator._commit_pending_signed_attempt(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        intent={
            "extrinsic_hash": SUCCESSOR_EXTRINSIC_HASH,
            "nonce": 11,
            "era_reference_block": MAPPING_BLOCK,
            "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
            "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
            "wire_uids": [8, 124],
            "wire_weights": [65535, 65535],
        },
    )
    validator._finalize_common_submission(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        submission=validator.ChainSubmission(
            success=True,
            extrinsic_hash=SUCCESSOR_EXTRINSIC_HASH,
            block_hash=SUCCESSOR_BLOCK_HASH,
            block_number=MAPPING_BLOCK + 2,
            finalized=True,
        ),
        version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
    )
    state = validator._read_state(state_path)
    assert state["submission_finalized_reviewed_uid30_contract"] == (
        "two_miner_successor"
    )
    assert state["submission_launch_attempt_id"] == (
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    )
    assert state["submission_attempt_budgets"]["authority_bounded"] == {
        "limit": 1,
        "ids": [SUCCESSOR_ATTEMPT_ID],
    }

    recovered = validator._recover_common_finalized_submission(runtime, state)
    assert isinstance(recovered, validator.RecoveredAuthoritySubmission)
    assert recovered.attempt_id == SUCCESSOR_ATTEMPT_ID
    assert recovered.uid_weights == ((8, 1.0), (124, 1.0))
    assert recovered.burn_uid is None
    assert recovered.burn_share == 0.0
    assert recovered.extrinsic_hash == SUCCESSOR_EXTRINSIC_HASH
