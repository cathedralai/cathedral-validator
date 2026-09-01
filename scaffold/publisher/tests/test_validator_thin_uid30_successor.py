from __future__ import annotations

import base64
import copy
import hashlib
import zlib
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as validator


MAPPING_BLOCK = validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK + 200
FINALIZED_HASH = "0x" + "f" * 64
SUCCESSOR_EXTRINSIC_HASH = "0x" + "d" * 64
SUCCESSOR_BLOCK_HASH = "0x" + "c" * 64
REVIEWED_FIXTURE_TIME = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
REVIEWED_FIXTURE_EXPIRY = datetime(2026, 9, 1, tzinfo=UTC)


def _set_validator_clock(
    monkeypatch: pytest.MonkeyPatch,
    *moments: datetime,
) -> None:
    clock = iter(moments)
    last = moments[-1]

    class _ReviewedFixtureDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            nonlocal last
            last = next(clock, last)
            if tz is None:
                return last.replace(tzinfo=None)
            return last.astimezone(tz)

    monkeypatch.setattr(validator, "datetime", _ReviewedFixtureDatetime)


@pytest.fixture(autouse=True)
def _freeze_reviewed_fixture_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the reviewed launch fixture inside its recorded evidence window."""

    _set_validator_clock(monkeypatch, REVIEWED_FIXTURE_TIME)


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
        "identity_sha256": (validator.SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256),
        "intent_sha256": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256,
        "receipt_sha256": (validator.SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256),
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
        "extrinsic_hash": (validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH),
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
        "report_data_sha256": hashlib.sha256(f"report:{hotkey}".encode()).hexdigest(),
        "tls_spki_sha256": spki,
        "sat_units": 20,
        "sat_rule": validator.SN39_UID30_SUCCESSOR_SAT_RULE,
        "anchor_number": anchor_number,
        "anchor_hash": anchor_hash,
    }


def _successor_identity(
    *,
    second_uid: int = 8,
    primary_uid: int = 124,
) -> dict[str, object]:
    proofs = [
        _proof(
            hotkey=validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
            uid=second_uid,
            ip="34.46.19.69",
            spki="2" * 64,
            anchor_number=MAPPING_BLOCK - 2,
            anchor_hash="0x" + "a" * 64,
        ),
        _proof(
            hotkey=validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
            uid=primary_uid,
            ip="35.222.166.235",
            spki="3" * 64,
            anchor_number=MAPPING_BLOCK - 1,
            anchor_hash="0x" + "b" * 64,
        ),
    ]
    safety = {
        "schema": "cathedral_sn39_uid_safety_v2",
        "targets": [
            [second_uid, validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY],
            [primary_uid, validator.SN39_UID30_LAUNCH_MINER_HOTKEY],
        ],
    }
    predecessor = _predecessor()
    preview_digest = "sha256:" + "1" * 64
    reviewed = {
        "valid_from_block": MAPPING_BLOCK - 2,
        "valid_until_block": MAPPING_BLOCK + 64,
        "miners": copy.deepcopy(proofs),
        "vector": {
            "dests": [second_uid, primary_uid],
            "weights_u16": [65535, 65535],
            "normalized": [[second_uid, "1.0"], [primary_uid, "1.0"]],
            "expected_storage": [
                [second_uid, 65535],
                [primary_uid, 65535],
            ],
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
        "uid_weights": [[second_uid, 1.0], [primary_uid, 1.0]],
        "uid_hotkeys": [
            [second_uid, validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY],
            [primary_uid, validator.SN39_UID30_LAUNCH_MINER_HOTKEY],
        ],
        "allocation_contract": validator.SN39_UID30_SUCCESSOR_POLICY,
        "burn_destination": None,
        "burn_share": 0.0,
        "subnet_owner_hotkey": validator.SN39_BURN_HOTKEY,
        "uid_safety": safety,
        "uid_safety_sha256": validator._sha256_document(safety).removeprefix("sha256:"),
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


SUCCESSOR_ATTEMPT_ID = validator._reviewed_uid30_attempt_id(_successor_identity())


def test_shared_attempt_id_preserves_the_live_predecessor_hash() -> None:
    predecessor_dedup_identity = {
        "allocation_contract": "uid30_single_verified_miner_100_v1",
        "burn_destination": None,
        "burn_share": 0.0,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "inclusion_policy": {
            "expected_next_epoch_start_block": 8_945_708,
            "mortal_period_blocks": 16,
            "require_commit_reveal_disabled": True,
            "valid_from_block": 8_945_351,
            "valid_from_time": "2026-08-28T18:17:27.996Z",
            "valid_until_block": 8_945_692,
            "valid_until_time": "2026-08-28T18:32:27.996Z",
        },
        "netuid": 39,
        "network": "finney",
        "next_epoch_start_block": 8_945_708,
        "report_id": (
            "sha256:738d26b175c98fe38042bf7c5eccbd9d04fb1b57f776c3a12a5f4d13b80afa68"
        ),
        "reviewed_preview": {
            "miner": {
                "anchor_hash": (
                    "0x5eebef5ca30888e7e1f5aa3a339fe12fedfb3eec34ca10c711a00d7ad97dfc42"
                ),
                "anchor_number": 8_945_350,
                "hotkey": validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
                "ip": "34.67.178.53",
                "port": 8081,
                "quote_sha256": (
                    "3e84da671b6baa655a8964117483415b15c2b53fea1beafb9a31c717d9a09509"
                ),
                "qvl_digest": validator.SN39_UID30_SUCCESSOR_QVL_SHA256,
                "report_data_sha256": (
                    "86077789af0d5767a2add66a8cff9dadec1cac42ffdd687a0e9c3511ac257a78"
                ),
                "sat_rule": validator.SN39_UID30_SUCCESSOR_SAT_RULE,
                "sat_units": 20,
                "tls_spki_sha256": (
                    "9b18f64e65a93d7724942fa00696bc8679f701b8cc342457481015e3ff962fd6"
                ),
                "uid": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID,
            },
            "valid_from_block": 8_945_351,
            "valid_until_block": 8_945_692,
            "vector": {
                "burn_destination": None,
                "burn_weight_u16": 0,
                "dests": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID],
                "normalized": [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, "1.0"]],
                "sum_u16": 65_535,
                "weights_u16": [65_535],
            },
        },
        "source_epoch": validator.SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH,
        "subnet_owner_hotkey": validator.SN39_BURN_HOTKEY,
        "uid30_launch_policy": "uid30_single_verified_miner_100_v1",
        "uid30_launch_preview_sha256": (
            "sha256:738d26b175c98fe38042bf7c5eccbd9d04fb1b57f776c3a12a5f4d13b80afa68"
        ),
        "uid30_launch_schema": "cathedral_sn39_uid30_launch_preview_v1",
        "uid_hotkeys": [
            [
                validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID,
                validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
            ]
        ],
        "uid_weights": [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 1.0]],
        "validator_hotkey": validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
        "validator_uid": validator.SN39_UID30_LAUNCH_VALIDATOR_UID,
    }

    assert validator._reviewed_uid30_attempt_id(predecessor_dedup_identity) == (
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    )


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
        validator._strict_zero_burn_uid30_successor_contract(identity, lane="authority")


@pytest.mark.parametrize("bad_uid", [True, "8"])
def test_strict_successor_contract_rejects_non_integer_uid(bad_uid: object) -> None:
    identity = _successor_identity()
    identity["uid_weights"][0][0] = bad_uid

    with pytest.raises(validator.wire.VectorError, match="two-row identity"):
        validator._strict_zero_burn_uid30_successor_contract(identity, lane="authority")


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
        "submission_validator_hotkey": (validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY),
        # The live finalized launch journal keeps its historical pending
        # receipt fields with pending_id=null.  Preserve that shape so an
        # unsigned successor rollback has to restore the exact raw preimage,
        # not a smaller semantically similar document.
        "submission_pending_id": None,
        "submission_pending_lane": "authority",
        "submission_pending_identity": identity,
        "submission_pending_at": "2026-08-28T18:20:26.588Z",
        "submission_pending_phase": "signed_intent",
        "submission_pending_launch_attempt": True,
        "submission_pending_launch_budget_limit": 1,
        "submission_pending_budget_scope": "launch_full_gate",
        "submission_pending_budget_limit": 1,
        "submission_pending_policy_version": None,
        "submission_pending_source_epoch": (
            validator.SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH
        ),
        "submission_pending_lane_transition_from": None,
        "submission_pending_broadcast_intent": intent,
        "submission_pending_broadcast_started_at": "2026-08-28T18:20:29.382Z",
        "submission_pending_receipt_candidate": receipt,
        "submission_pending_proof_status": validator.PASS,
        "submission_pending_receipt_recorded_at": "2026-08-28T18:21:03.270Z",
        "submission_pending_proof_checked_at": "2026-08-28T18:21:06.976Z",
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
        _submission_validator_hotkey=(validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY),
        _uid30_two_miner_successor_preview_sha256="1" * 64,
    )


def _write_predecessor_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, SimpleNamespace]:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    runtime_root.chmod(0o700)
    state_path = (
        runtime_root / validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
    )
    state = _predecessor_state(monkeypatch)
    body = validator._canonical_json_bytes(state)
    state_path.write_bytes(body)
    state_path.chmod(0o600)
    monkeypatch.setattr(
        validator,
        "SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256",
        hashlib.sha256(body).hexdigest(),
    )
    monkeypatch.setitem(
        globals(),
        "SUCCESSOR_ATTEMPT_ID",
        validator._reviewed_uid30_attempt_id(_successor_identity()),
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
    assert "submission_pending_predecessor_journal_zlib_b64" not in signed
    assert signed["submission_launch_attempt_id"] == (
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    )


def test_unsigned_successor_abort_consumes_no_attempt_or_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    predecessor_bytes = state_path.read_bytes()
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=_successor_identity(),
    )

    assert validator._abort_unsigned_common_submission(
        runtime, attempt_id=SUCCESSOR_ATTEMPT_ID
    )
    assert state_path.read_bytes() == predecessor_bytes
    state = validator._read_state(state_path)
    assert state["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    ]
    assert state["submission_attempt_budgets"] == {
        "launch_full_gate": {
            "limit": 1,
            "ids": [validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
        }
    }
    assert "authority_bounded" not in state["submission_attempt_budgets"]

    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=_successor_identity(),
    )
    retried = validator._read_state(state_path)
    assert retried["submission_pending_id"] == SUCCESSOR_ATTEMPT_ID
    assert retried["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    ]
    assert "authority_bounded" not in retried["submission_attempt_budgets"]
    assert validator._abort_unsigned_common_submission(
        runtime, attempt_id=SUCCESSOR_ATTEMPT_ID
    )
    assert state_path.read_bytes() == predecessor_bytes


@pytest.mark.parametrize(
    "tamper",
    ["missing", "changed", "missing_kind", "bool_nonpending", "bool_budget"],
)
def test_unsigned_successor_abort_keeps_tampered_rollback_preimage_fenced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=_successor_identity(),
    )
    state = validator._read_state(state_path)
    if tamper == "missing":
        state.pop("submission_pending_predecessor_journal_zlib_b64")
    elif tamper == "missing_kind":
        state.pop("submission_pending_reviewed_uid30_contract")
    elif tamper == "bool_nonpending":
        state["submission_attempt_count"] = True
    elif tamper == "bool_budget":
        state["submission_pending_budget_limit"] = True
    else:
        state["submission_pending_predecessor_journal_zlib_b64"] = "AAAA"
    validator._replace_private_state(state_path, state)
    tampered_bytes = state_path.read_bytes()

    with pytest.raises(
        ValueError,
        match="rollback bytes|rollback identity|pristine predecessor lineage",
    ):
        validator._abort_unsigned_common_submission(
            runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
        )

    assert state_path.read_bytes() == tampered_bytes
    fenced = validator._read_state(state_path)
    assert fenced["submission_pending_id"] == SUCCESSOR_ATTEMPT_ID
    assert fenced["submission_pending_phase"] == "unsigned_reserved"
    assert fenced["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID
    ]
    assert "authority_bounded" not in fenced["submission_attempt_budgets"]


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
        match=(
            "predecessor journal bytes changed|pending reconciliation|"
            "predecessor bytes differ from their pin"
        ),
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


def test_signed_successor_cannot_be_disguised_as_unsigned_and_rolled_back(
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
    unsigned = validator._read_state(state_path)
    rollback_preimage = unsigned["submission_pending_predecessor_journal_zlib_b64"]
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
    disguised = validator._read_state(state_path)
    disguised["submission_pending_phase"] = "unsigned_reserved"
    disguised.pop("submission_pending_broadcast_intent")
    disguised.pop("submission_pending_broadcast_started_at")
    disguised["submission_pending_predecessor_journal_zlib_b64"] = rollback_preimage
    validator._replace_private_state(state_path, disguised)
    before = state_path.read_bytes()

    with pytest.raises(ValueError, match="pristine predecessor lineage"):
        validator._abort_unsigned_common_submission(
            runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
        )

    assert state_path.read_bytes() == before
    fenced = validator._read_state(state_path)
    assert fenced["submission_attempt_ids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
        SUCCESSOR_ATTEMPT_ID,
    ]
    assert fenced["submission_attempt_budgets"]["authority_bounded"] == {
        "limit": 1,
        "ids": [SUCCESSOR_ATTEMPT_ID],
    }


def test_successor_commit_and_abort_linearize_without_crossing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    predecessor_bytes = state_path.read_bytes()
    identity = _successor_identity()
    intent = {
        "extrinsic_hash": SUCCESSOR_EXTRINSIC_HASH,
        "nonce": 11,
        "era_reference_block": MAPPING_BLOCK,
        "mortal_period_blocks": validator.SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": validator.SN39_UID30_LAUNCH_VERSION_KEY,
        "wire_uids": [8, 124],
        "wire_weights": [65535, 65535],
    }
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    assert validator._abort_unsigned_common_submission(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
    )
    assert state_path.read_bytes() == predecessor_bytes
    with pytest.raises(ValueError, match="pristine unsigned reservation"):
        validator._commit_pending_signed_attempt(
            runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
            intent=intent,
        )
    assert state_path.read_bytes() == predecessor_bytes

    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    validator._commit_pending_signed_attempt(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        intent=intent,
    )
    signed_bytes = state_path.read_bytes()
    assert not validator._abort_unsigned_common_submission(
        runtime,
        attempt_id=SUCCESSOR_ATTEMPT_ID,
    )
    assert state_path.read_bytes() == signed_bytes


def test_successor_unsigned_restore_requires_canonical_runtime_path(
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
    before = state_path.read_bytes()
    monkeypatch.setattr(validator, "_VALIDATOR_RUNTIME_ROOT", tmp_path / "elsewhere")

    with pytest.raises(ValueError, match="rollback identity"):
        validator._abort_unsigned_common_submission(
            runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
        )

    assert state_path.read_bytes() == before


def test_successor_rollback_decoder_rejects_bounded_corruption() -> None:
    payload = b'{"fixture":"bounded-rollback"}'
    payload_sha = hashlib.sha256(payload).hexdigest()
    cases = [
        "A" * (validator.SN39_UID30_SUCCESSOR_ROLLBACK_B64_MAX_BYTES + 1),
        base64.b64encode(
            zlib.compress(
                b"x" * (validator.SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES + 1)
            )
        ).decode("ascii"),
        base64.b64encode(zlib.compress(payload) + zlib.compress(b"trailer")).decode(
            "ascii"
        ),
        base64.b64encode(zlib.compress(payload)[:-1]).decode("ascii"),
    ]
    tampered = bytearray(zlib.compress(payload))
    tampered[len(tampered) // 2] ^= 0xFF
    cases.append(base64.b64encode(tampered).decode("ascii"))

    for encoded in cases:
        with pytest.raises(ValueError):
            validator._decode_uid30_successor_predecessor_bytes(
                encoded,
                expected_sha256=(
                    hashlib.sha256(
                        b"x" * (validator.SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES + 1)
                    ).hexdigest()
                    if encoded == cases[1]
                    else payload_sha
                ),
            )


def test_generic_recovery_keeps_signed_successor_fenced_for_fixed_recovery(
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
    before = state_path.read_bytes()

    monkeypatch.setattr(validator, "_prepare_tick_preflight", lambda _args: None)
    monkeypatch.setattr(
        validator,
        "_pending_recovery_tick_lock",
        lambda _args: nullcontext(),
    )
    for forbidden in (
        "_locate_pending_broadcast_receipt",
        "_classify_finalized_receipt",
        "_classify_zero_burn_uid30_historical_weights",
        "_record_pending_proof_status",
        "_finalize_common_submission",
    ):
        monkeypatch.setattr(
            validator,
            forbidden,
            lambda *_args, _forbidden=forbidden, **_kwargs: pytest.fail(
                f"generic successor recovery reached {_forbidden}"
            ),
        )

    with pytest.raises(
        validator._PendingReceiptNotProven,
        match="successor-recover.*two later finalized heads",
    ):
        validator._recover_pending_launch_receipt(runtime)

    assert state_path.read_bytes() == before
    fenced = validator._read_state(state_path)
    assert fenced["submission_pending_id"] == SUCCESSOR_ATTEMPT_ID
    assert fenced["submission_pending_phase"] == "signed_intent"
    assert fenced["submission_pending_reviewed_uid30_contract"] == (
        "two_miner_successor"
    )


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


def test_reviewed_successor_refuses_at_time_window_expiry() -> None:
    policy = validator._policy_from_submission_identity(_successor_identity())

    with pytest.raises(
        validator.wire.VectorError,
        match="submission time is outside the evidence inclusion window",
    ):
        validator._require_inclusion_policy_ready(
            policy,
            _preflight(_authorization_substrate()),
            now=REVIEWED_FIXTURE_EXPIRY,
        )


def _descendant_preflight(
    *,
    second_uid: int = 8,
    primary_uid: int = 124,
    drift: int = 1,
    case: str = "ok",
) -> tuple[validator.ChainPreflight, dict[str, object]]:
    latest_block = MAPPING_BLOCK + drift
    latest_hash = "0x" + "e" * 64
    intermediate_hash = "0x" + "9" * 64
    unrelated_hash = "0x" + "7" * 64
    signed_hash = "0x" + "6" * 64
    calls: dict[str, object] = {
        "nonce": 0,
        "sign": 0,
        "submit": 0,
        "era_current": None,
    }
    uid_by_hotkey = {
        validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY: 30,
        validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: second_uid,
        validator.SN39_UID30_LAUNCH_MINER_HOTKEY: primary_uid,
    }
    hotkey_by_uid = {uid: hotkey for hotkey, uid in uid_by_hotkey.items()}

    def get_block_hash(block: int) -> str:
        if block == MAPPING_BLOCK:
            return FINALIZED_HASH
        if block == latest_block:
            return latest_hash
        if block == validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK:
            return validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        if block == MAPPING_BLOCK - 2:
            return "0x" + "a" * 64
        if block == MAPPING_BLOCK - 1:
            return "0x" + "b" * 64
        raise AssertionError(block)

    parents = {
        latest_hash: (
            unrelated_hash
            if case == "ancestry"
            else FINALIZED_HASH
            if drift == 1
            else intermediate_hash
        ),
        intermediate_hash: FINALIZED_HASH,
    }

    def query(
        *, storage_function: str, params: list[object], block_hash: str, **_kwargs
    ):
        if storage_function == "Uids":
            hotkey = str(params[1])
            if case == "second_mapping" and hotkey == (
                validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY
            ):
                return second_uid + 1
            return uid_by_hotkey[hotkey]
        if storage_function == "Keys":
            uid = int(params[1])
            if case == "primary_mapping" and uid == primary_uid:
                return validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY
            return hotkey_by_uid[uid]
        if storage_function == "WeightsVersionKey":
            return (
                validator.SN39_UID30_LAUNCH_VERSION_KEY + 1
                if case == "version" and block_hash == latest_hash
                else 0
            )
        if storage_function == "StakeThreshold":
            assert params == [] and block_hash == latest_hash
            return 1_000
        if storage_function == "Weights":
            if block_hash == latest_hash:
                return (
                    [[second_uid, 65535], [primary_uid, 65535]]
                    if case == "row"
                    else [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]]
                )
            if block_hash == FINALIZED_HASH:
                return [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]]
            assert block_hash == validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
            return [[validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]]
        raise AssertionError(storage_function)

    def nonce(_hotkey: str) -> int:
        calls["nonce"] = int(calls["nonce"]) + 1
        return 17

    signed = SimpleNamespace(extrinsic_hash=bytes.fromhex("6" * 64))

    def sign(**kwargs):
        calls["sign"] = int(calls["sign"]) + 1
        calls["era_current"] = kwargs["era"]["current"]
        return signed

    def submit(*_args, **_kwargs):
        calls["submit"] = int(calls["submit"]) + 1
        return SimpleNamespace(extrinsic_hash=signed_hash, is_success=True)

    substrate = SimpleNamespace(
        get_chain_finalised_head=lambda: latest_hash,
        get_block_number=lambda block_hash: (
            latest_block if block_hash == latest_hash else pytest.fail(block_hash)
        ),
        get_block_hash=get_block_hash,
        get_block_header=lambda *, block_hash: {
            "header": {"parentHash": parents[block_hash]}
        },
        query=query,
        get_account_next_index=nonce,
        create_signed_extrinsic=sign,
        submit_extrinsic=submit,
    )
    second_axon: object = {
        "ip": int.from_bytes(bytes((34, 46, 19, 69)), "big"),
        "ip_type": 6 if case == "axon_ip_type" else 4,
        "port": 8082 if case == "second_axon" else 8081,
        "protocol": 4,
    }
    if case == "axon_shape":
        second_axon = SimpleNamespace(ip="34.46.19.69", port=8081, protocol=4)
    primary_axon = {
        "ip": int.from_bytes(bytes((35, 222, 166, 235)), "big"),
        "ip_type": 4,
        "port": 8081,
        "protocol": 3 if case == "primary_axon" else 4,
    }
    info_size = max(30, second_uid, primary_uid) + 1
    hotkeys = [f"unused-{index}" for index in range(info_size)]
    permits: list[object] = [False] * info_size
    last_update = [0] * info_size
    total_stake = [SimpleNamespace(rao=0) for _ in range(info_size)]
    axons: list[object] = [{} for _ in range(info_size)]
    for hotkey, uid in uid_by_hotkey.items():
        hotkeys[uid] = hotkey
    permits[30] = "False" if case == "permit_type" else case != "permit"
    last_update[30] = (
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK + 1
        if case == "last_update"
        else validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
    )
    total_stake[30] = SimpleNamespace(rao=999 if case == "stake" else 1_001)
    axons[30] = {}
    axons[second_uid] = second_axon
    axons[primary_uid] = primary_axon
    info = SimpleNamespace(
        block=latest_block,
        hotkeys=hotkeys,
        validator_permit=permits,
        last_update=last_update,
        total_stake=total_stake,
        axons=axons,
    )
    subtensor = SimpleNamespace(
        substrate=substrate,
        commit_reveal_enabled=lambda *, netuid, block: (
            False
            if netuid == 39 and block == latest_block and case != "commit"
            else True
        ),
        get_subnet_owner_hotkey=lambda netuid, *, block: (
            validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY
            if case == "owner"
            else validator.SN39_BURN_HOTKEY
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        min_allowed_weights=lambda *, netuid, block: (
            2
            if case == "min_weights"
            else 1
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        max_weight_limit=lambda *, netuid, block: (
            0.5
            if case == "max_weight"
            else 1.0
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        get_next_epoch_start_block=lambda netuid, *, block: (
            MAPPING_BLOCK + 201
            if case == "epoch"
            else MAPPING_BLOCK + 200
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        weights_rate_limit=lambda netuid, *, block: (
            validator.SN39_MORTAL_PERIOD_BLOCKS - 1
            if case == "rate_limit"
            else 100
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        get_mechanism_count=lambda netuid, *, block: (
            0
            if case == "mechanism"
            else 1
            if netuid == 39 and block == latest_block
            else pytest.fail((netuid, block))
        ),
        get_metagraph_info=lambda netuid, mechid, *, block: (
            info
            if (netuid, mechid, block) == (39, 0, latest_block)
            else pytest.fail((netuid, mechid, block))
        ),
    )
    preflight = validator.ChainPreflight(
        wallet=SimpleNamespace(
            hotkey=SimpleNamespace(
                ss58_address=validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
            )
        ),
        subtensor=subtensor,
        hotkey_to_uid=uid_by_hotkey,
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
            MAPPING_BLOCK - validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        ),
        replacement_safe_hotkeys=frozenset(
            {
                validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
                validator.SN39_UID30_LAUNCH_MINER_HOTKEY,
                "5G6mgvL59o6AM8rFRYbbUpbzjjGwcVLUidpQ1vsz5UkZyw2o",
            }
        ),
        finalized_hash=FINALIZED_HASH,
    )
    return preflight, calls


def _reserved_descendant_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, str, validator.ChainPreflight, dict[str, object]]:
    _state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity()
    attempt_id = validator._reviewed_uid30_attempt_id(identity)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )
    preflight, calls = _descendant_preflight()
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
    return runtime, attempt_id, preflight, calls


def _refuse_irreversible_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "bittensor.core.types.ExtrinsicResponse.unlock_wallet",
        lambda *_args, **_kwargs: pytest.fail("refusal must precede wallet unlock"),
    )
    monkeypatch.setattr(
        "bittensor.core.extrinsics.pallets.SubtensorModule",
        lambda _subtensor: pytest.fail("refusal must precede call composition"),
    )
    monkeypatch.setattr(
        validator,
        "_record_pending_broadcast_intent",
        lambda *_args, **_kwargs: pytest.fail(
            "refusal must precede signed-intent journaling"
        ),
    )


def test_exact_successor_descendant_refuses_at_time_window_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, attempt_id, preflight, calls = _reserved_descendant_submission(
        tmp_path,
        monkeypatch,
    )
    _set_validator_clock(monkeypatch, REVIEWED_FIXTURE_EXPIRY)
    _refuse_irreversible_signing(monkeypatch)

    with pytest.raises(
        validator.wire.VectorError,
        match="UID30 successor descendant lacks reviewed time, block, or epoch room",
    ):
        validator._submit_exact_sn39_extrinsic(
            preflight,
            runtime_contract=runtime,
            attempt_id=attempt_id,
            netuid=39,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65535],
            mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
            allow_reviewed_uid30_finalized_descendant=True,
        )

    assert calls == {
        "nonce": 0,
        "sign": 0,
        "submit": 0,
        "era_current": None,
    }


def test_exact_successor_descendant_refuses_if_window_expires_before_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, attempt_id, preflight, calls = _reserved_descendant_submission(
        tmp_path,
        monkeypatch,
    )
    _set_validator_clock(
        monkeypatch,
        REVIEWED_FIXTURE_TIME,
        REVIEWED_FIXTURE_TIME,
        REVIEWED_FIXTURE_EXPIRY,
    )
    _refuse_irreversible_signing(monkeypatch)

    with pytest.raises(
        validator.wire.VectorError,
        match="UID30 descendant signing evidence time window expired before signature",
    ):
        validator._submit_exact_sn39_extrinsic(
            preflight,
            runtime_contract=runtime,
            attempt_id=attempt_id,
            netuid=39,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65535],
            mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
            allow_reviewed_uid30_finalized_descendant=True,
        )

    assert calls == {
        "nonce": 0,
        "sign": 0,
        "submit": 0,
        "era_current": None,
    }


@pytest.mark.parametrize(
    ("drift", "second_uid", "primary_uid"),
    [(1, 17, 201), (2, 8, 124)],
)
def test_exact_successor_signer_accepts_only_bounded_reviewed_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: int,
    second_uid: int,
    primary_uid: int,
) -> None:
    _state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity(
        second_uid=second_uid,
        primary_uid=primary_uid,
    )
    attempt_id = validator._reviewed_uid30_attempt_id(identity)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )
    preflight, calls = _descendant_preflight(
        second_uid=second_uid,
        primary_uid=primary_uid,
        drift=drift,
    )
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
    monkeypatch.setattr(
        "bittensor.core.types.ExtrinsicResponse.unlock_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(success=True),
    )
    monkeypatch.setattr(
        "bittensor.core.extrinsics.pallets.SubtensorModule",
        lambda _subtensor: SimpleNamespace(
            set_mechanism_weights=lambda **_kwargs: "call"
        ),
    )
    intents: list[dict[str, object]] = []
    monkeypatch.setattr(
        validator,
        "_record_pending_broadcast_intent",
        lambda *_args, **kwargs: intents.append(kwargs),
    )

    receipt = validator._submit_exact_sn39_extrinsic(
        preflight,
        runtime_contract=runtime,
        attempt_id=attempt_id,
        netuid=39,
        version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
        wire_uids=[second_uid, primary_uid],
        wire_weights=[65535, 65535],
        mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
        allow_reviewed_uid30_finalized_descendant=True,
    )

    assert receipt.is_success is True
    assert calls == {
        "nonce": 1,
        "sign": 1,
        "submit": 1,
        "era_current": MAPPING_BLOCK,
    }
    assert intents[0]["wire_uids"] == [second_uid, primary_uid]
    assert intents[0]["wire_weights"] == [65535, 65535]


@pytest.mark.parametrize(
    "case",
    [
        "durable_kind",
        "digest",
        "second_mapping",
        "primary_mapping",
        "row",
        "permit",
        "permit_type",
        "last_update",
        "rate_limit",
        "second_axon",
        "primary_axon",
        "axon_ip_type",
        "axon_shape",
        "version",
        "commit",
        "owner",
        "min_weights",
        "max_weight",
        "stake",
        "mechanism",
        "epoch",
        "too_far",
        "ancestry",
        "signed_pending",
        "wire",
    ],
)
def test_successor_descendant_counterexamples_refuse_before_irreversible_touch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    predecessor_bytes = state_path.read_bytes()
    identity = _successor_identity()
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=SUCCESSOR_ATTEMPT_ID,
        identity=identity,
    )
    journal = validator._read_state(state_path)
    if case == "durable_kind":
        journal["submission_pending_reviewed_uid30_contract"] = "one_miner_launch"
        validator._replace_private_state(state_path, journal)
    elif case == "digest":
        runtime._uid30_two_miner_successor_preview_sha256 = "2" * 64
    elif case == "signed_pending":
        journal["submission_pending_phase"] = "signed_intent"
        journal["submission_pending_broadcast_intent"] = {
            "extrinsic_hash": SUCCESSOR_EXTRINSIC_HASH
        }
        validator._replace_private_state(state_path, journal)
    drift = 3 if case == "too_far" else 1
    preflight, calls = _descendant_preflight(
        drift=drift,
        case=case,
    )
    monkeypatch.setattr(
        "bittensor.core.types.ExtrinsicResponse.unlock_wallet",
        lambda *_args, **_kwargs: pytest.fail("refusal must precede wallet unlock"),
    )
    monkeypatch.setattr(
        "bittensor.core.extrinsics.pallets.SubtensorModule",
        lambda _subtensor: pytest.fail("refusal must precede call composition"),
    )
    monkeypatch.setattr(
        validator,
        "_record_pending_broadcast_intent",
        lambda *_args, **_kwargs: pytest.fail(
            "refusal must precede signed-intent journaling"
        ),
    )

    with pytest.raises(validator.wire.VectorError):
        validator._submit_exact_sn39_extrinsic(
            preflight,
            runtime_contract=runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
            netuid=39,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65534] if case == "wire" else [65535, 65535],
            mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
            allow_reviewed_uid30_finalized_descendant=True,
        )

    assert calls == {
        "nonce": 0,
        "sign": 0,
        "submit": 0,
        "era_current": None,
    }
    if case not in {"durable_kind", "signed_pending"}:
        assert validator._abort_unsigned_common_submission(
            runtime,
            attempt_id=SUCCESSOR_ATTEMPT_ID,
        )
        assert state_path.read_bytes() == predecessor_bytes


def test_generic_descendant_flag_does_not_authorize_an_unreviewed_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight, calls = _descendant_preflight()
    monkeypatch.setattr(validator, "_read_state", lambda _path: {})
    monkeypatch.setattr(
        validator,
        "_submission_state_path",
        lambda _args: Path("/not-read/generic.json"),
    )
    monkeypatch.setattr(
        "bittensor.core.types.ExtrinsicResponse.unlock_wallet",
        lambda *_args, **_kwargs: pytest.fail("refusal must precede wallet unlock"),
    )
    monkeypatch.setattr(
        "bittensor.core.extrinsics.pallets.SubtensorModule",
        lambda _subtensor: pytest.fail("refusal must precede call composition"),
    )

    with pytest.raises(validator.wire.VectorError):
        validator._submit_exact_sn39_extrinsic(
            preflight,
            runtime_contract=SimpleNamespace(
                require_full_provenance_for_broadcast=False,
            ),
            attempt_id="sha256:" + "4" * 64,
            netuid=39,
            version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
            wire_uids=[8, 124],
            wire_weights=[65535, 65535],
            mortal_period_blocks=validator.SN39_MORTAL_PERIOD_BLOCKS,
            allow_reviewed_uid30_finalized_descendant=True,
        )

    assert calls == {
        "nonce": 0,
        "sign": 0,
        "submit": 0,
        "era_current": None,
    }


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


def test_successor_pre_sign_follows_uid_churn_while_predecessor_stays_uid124(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second_uid = 17
    primary_uid = 201
    state_path, runtime = _write_predecessor_journal(tmp_path, monkeypatch)
    identity = _successor_identity(
        second_uid=second_uid,
        primary_uid=primary_uid,
    )
    attempt_id = validator._reviewed_uid30_attempt_id(identity)
    validator._reserve_common_submission(
        runtime,
        lane="authority",
        attempt_id=attempt_id,
        identity=identity,
    )
    preflight = _preflight(
        _authorization_substrate(),
        hotkey_to_uid={
            validator.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY: 30,
            validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: second_uid,
            validator.SN39_UID30_LAUNCH_MINER_HOTKEY: primary_uid,
        },
    )
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

    validator._authorize_reviewed_uid30_submission(
        runtime,
        preflight=preflight,
        attempt_id=attempt_id,
        version_key=validator.SN39_UID30_LAUNCH_VERSION_KEY,
        wire_uids=[second_uid, primary_uid],
        wire_weights=[65535, 65535],
    )

    reserved = validator._read_state(state_path)
    assert reserved["submission_pending_identity"]["uid_weights"] == [
        [second_uid, 1.0],
        [primary_uid, 1.0],
    ]
    assert reserved["submission_finalized_receipt"]["wire_uids"] == [
        validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID
    ]
    assert reserved["submission_finalized_receipt"]["wire_weights"] == [65535]


@pytest.mark.parametrize(
    "case",
    [
        "forward_mapping",
        "reverse_mapping",
        "last_update",
        "predecessor_row",
        "budget_scope",
        "canonical_root",
        "lineage_type_confusion",
        "fresh_identity_rehash",
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
    elif case == "lineage_type_confusion":
        journal["submission_attempt_count"] = True
    elif case == "fresh_identity_rehash":
        pending_identity = journal["submission_pending_identity"]
        fresh = pending_identity["fresh_miner_evidence"]
        fresh[0]["sat_units"] += 1
        pending_identity["fresh_evidence_sha256"] = validator._sha256_document(
            {"proofs": fresh}
        ).removeprefix("sha256:")
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
