from __future__ import annotations

import copy
import fcntl
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin import uid30_launch as launch
from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    MAX_WEIGHT_LIMIT,
    MIN_ALLOWED_WEIGHTS,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST
from scaffold import validator_thin as canonical_validator


@pytest.fixture(autouse=True)
def _canonical_test_runtime_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", tmp_path / "runtime")


def _state(**changes) -> launch.UID30ChainState:
    values = {
        "preflight": SimpleNamespace(),
        "block_number": 1_000,
        "block_hash": "0x" + "1" * 64,
        "genesis_hash": FINNEY_GENESIS_HASH,
        "validator_hotkey": launch.UID30_HOTKEY,
        "validator_uid": launch.UID30,
        "validator_permit": True,
        "validator_stake_rao": 2_000,
        "stake_threshold_rao": 1_000,
        "last_update": 800,
        "blocks_since_last_update": 200,
        "weights_rate_limit": 100,
        "mechanism_count": 1,
        "weights_version_key": VERSION_KEY,
        "min_allowed_weights": MIN_ALLOWED_WEIGHTS,
        "max_weight_limit": MAX_WEIGHT_LIMIT,
        "commit_reveal_enabled": COMMIT_REVEAL_ENABLED,
        "miner_hotkey": launch.MINER_HOTKEY,
        "miner_uid": 61,
        "next_epoch_start_block": 1_200,
        "blocks_until_next_epoch": 200,
        "uid_safety": {
            "schema": "cathedral_sn39_uid_safety_v2",
            "stability_basis": "operator_controlled_coldkeys",
            "registration": {
                "replacement_safe_hotkeys": [launch.MINER_HOTKEY],
            },
            "rotation": {
                "status": canonical_validator.PASS,
                "mapping_block": 1_000,
                "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
                "era_last_block": 1_015,
                "targets": [
                    {
                        "uid": 61,
                        "hotkey": launch.MINER_HOTKEY,
                        "pending_coldkey_swap": None,
                        "registration_replacement_safe": True,
                    }
                ],
            },
            "excluded_hotkeys": [],
        },
    }
    values.update(changes)
    return launch.UID30ChainState(**values)


def _proof(**changes) -> launch.VerifiedMinerProof:
    values = {
        "hotkey": launch.MINER_HOTKEY,
        "uid": 61,
        "ip": "8.8.8.8",
        "port": 8081,
        "qvl_digest": LAUNCH_QVL_DIGEST,
        "quote_sha256": "2" * 64,
        "report_data_sha256": "3" * 64,
        "tls_spki_sha256": "4" * 64,
        "sat_units": 1,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "anchor_number": 999,
        "anchor_hash": "0x" + "5" * 64,
    }
    values.update(changes)
    return launch.VerifiedMinerProof(**values)


def _preview_files(
    tmp_path: Path,
    *,
    state: launch.UID30ChainState | None = None,
    proof: launch.VerifiedMinerProof | None = None,
) -> tuple[Path, str, Path]:
    runtime_root = tmp_path / "runtime"
    document = launch.build_preview(
        state=state or _state(),
        miner=proof or _proof(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )
    path, digest_path, digest = launch.write_preview(
        document, runtime_root / "uid30-preview.json"
    )
    assert digest_path.read_text(encoding="ascii") == digest + "\n"
    return path, digest, runtime_root


def _intent_then_receipt(
    _preflight,
    *,
    runtime_contract,
    attempt_id,
    netuid,
    version_key,
    wire_uids,
    wire_weights,
    mortal_period_blocks,
):
    assert netuid == 39
    canonical_validator._record_pending_broadcast_intent(
        runtime_contract,
        attempt_id=attempt_id,
        extrinsic_hash="0x" + "a" * 64,
        nonce=7,
        era_reference_block=1_000,
        mortal_period_blocks=mortal_period_blocks,
        version_key=version_key,
        wire_uids=wire_uids,
        wire_weights=wire_weights,
    )
    return SimpleNamespace(
        is_success=True,
        extrinsic_hash="0x" + "a" * 64,
        block_hash="0x" + "b" * 64,
        block_number=1_002,
    )


def test_wrong_validator_uid_is_refused() -> None:
    with pytest.raises(launch.UID30LaunchError, match="not 30"):
        launch.validate_chain_state(_state(validator_uid=29))


def test_wrong_validator_hotkey_is_refused() -> None:
    with pytest.raises(launch.UID30LaunchError, match="not the pinned UID30"):
        launch.validate_chain_state(_state(validator_hotkey=launch.MINER_HOTKEY))


def test_wrong_miner_hotkey_proof_is_refused() -> None:
    with pytest.raises(launch.UID30LaunchError, match="wrong miner hotkey"):
        launch.validate_miner_proof(_proof(hotkey=launch.UID30_HOTKEY), state=_state())


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"validator_permit": False}, "lacks the current validator permit"),
        ({"validator_stake_rao": 999}, "below the current weight stake threshold"),
        (
            {"last_update": 901, "blocks_since_last_update": 99},
            "inside the current weight cooldown",
        ),
    ],
)
def test_current_permit_stake_and_cooldown_are_mandatory(changes, message) -> None:
    with pytest.raises(launch.UID30LaunchError, match=message):
        launch.validate_chain_state(_state(**changes))


def test_private_miner_address_is_refused() -> None:
    with pytest.raises(launch.UID30LaunchError, match="not canonical public IP"):
        launch.validate_miner_proof(_proof(ip="10.0.0.2"), state=_state())


def test_burn_destination_present_is_refused(tmp_path: Path) -> None:
    document = launch.build_preview(
        state=_state(),
        miner=_proof(),
        runtime_root=tmp_path / "runtime",
        created_at="2026-08-28T12:00:00Z",
    )
    changed = copy.deepcopy(document)
    changed["proposed_vector"]["burn_destination"] = 204
    with pytest.raises(launch.UID30LaunchError, match="exactly one miner"):
        launch.validate_preview(changed)


def test_preview_is_owner_only_canonical_json_with_detached_digest(
    tmp_path: Path,
) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    digest_path = path.with_suffix(path.suffix + ".sha256")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(digest_path.stat().st_mode) == 0o600
    document, observed = launch.load_reviewed_preview(path, reviewed_sha256=digest)
    assert observed == digest
    assert document["weight_submission"] == {
        "call": "SubtensorModule.set_mechanism_weights",
        "version_key": VERSION_KEY,
        "vector_built": True,
        "extrinsic_built": False,
        "signed": False,
        "submitted": False,
        "readback": None,
    }


def test_reviewed_digest_mismatch_is_refused(tmp_path: Path) -> None:
    path, _digest, _runtime_root = _preview_files(tmp_path)
    with pytest.raises(launch.UID30LaunchError, match="does not match"):
        launch.load_reviewed_preview(path, reviewed_sha256="f" * 64)


def test_confirmation_is_required_before_loading_chain(tmp_path: Path) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    called = False

    def chain_loader():
        nonlocal called
        called = True
        raise AssertionError("chain must not be read")

    with pytest.raises(launch.UID30LaunchError, match="confirm-uid30-launch"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/not/read",
            confirm=False,
            chain_loader=chain_loader,
        )
    assert called is False


def test_remote_writer_assertion_is_required_before_loading_chain(
    tmp_path: Path,
) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    called = False

    def chain_loader():
        nonlocal called
        called = True
        raise AssertionError("chain must not be read")

    with pytest.raises(launch.UID30LaunchError, match="assert-exclusive-writer"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/not/read",
            confirm=True,
            chain_loader=chain_loader,
        )
    assert called is False


def test_live_submit_refuses_a_noncanonical_runtime_root(tmp_path: Path) -> None:
    runtime_root = tmp_path / "different-runtime"
    document = launch.build_preview(
        state=_state(),
        miner=_proof(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )
    path, _digest_path, digest = launch.write_preview(
        document, runtime_root / "uid30-preview.json"
    )
    called = False

    def chain_loader():
        nonlocal called
        called = True
        raise AssertionError("chain must not be read")

    with pytest.raises(launch.UID30LaunchError, match="canonical runtime root"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/not/read",
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=chain_loader,
        )
    assert called is False


def test_stale_last_update_is_refused_before_signing(tmp_path: Path) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    signed = False
    fresh = _state(
        block_number=1_001,
        block_hash="0x" + "6" * 64,
        last_update=801,
        blocks_since_last_update=200,
        blocks_until_next_epoch=199,
    )

    def submit_call(*_args, **_kwargs):
        nonlocal signed
        signed = True
        raise AssertionError("must not sign")

    with pytest.raises(launch.UID30LaunchError, match="last_update"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/not/read",
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=lambda: fresh,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=submit_call,
        )
    assert signed is False


def test_duplicate_writer_lock_is_refused_before_chain_read(tmp_path: Path) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)
    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
    )
    descriptor = canonical_validator._open_private_lock(
        canonical_validator._submission_lock_path(args)
    )
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    called = False

    def chain_loader():
        nonlocal called
        called = True
        raise AssertionError("chain must not be read")

    try:
        with pytest.raises(launch.UID30LaunchError, match="writer lock refused"):
            launch.submit_reviewed_preview(
                preview_path=path,
                reviewed_sha256=digest,
                qvl_path="/not/read",
                confirm=True,
                exclusive_writer_asserted=True,
                chain_loader=chain_loader,
            )
    finally:
        os.close(descriptor)
    assert called is False


def test_pre_sign_failure_clears_only_the_unsigned_reservation(tmp_path: Path) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    with pytest.raises(launch.UID30LaunchError, match="before signed intent"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("wallet refused before signing")
            ),
        )
    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
    )
    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    assert journal["submission_pending_id"] is None
    assert journal.get("submission_attempt_ids", []) == []


def test_signed_broadcast_ambiguity_is_durable_and_never_retried(
    tmp_path: Path,
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous, match="do not retry"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=ambiguous,
        )
    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
    )
    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    assert journal["submission_pending_phase"] == "signed_intent"
    assert journal["submission_pending_broadcast_intent"]["wire_weights"] == [W]

    with pytest.raises(launch.UID30LaunchError, match="prior.*pending"):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=lambda *_args, **_kwargs: pytest.fail("must not retry"),
        )


def test_exact_u16_vector_is_signed_read_back_and_finalized_once(
    tmp_path: Path,
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)
    captured: dict[str, object] = {}
    chain_reads = 0

    def chain_loader():
        nonlocal chain_reads
        chain_reads += 1
        return _state()

    def submit_call(*args, **kwargs):
        captured["uids"] = list(kwargs["wire_uids"])
        captured["weights"] = list(kwargs["wire_weights"])
        return _intent_then_receipt(*args, **kwargs)

    def readback_call(*, state, submission):
        assert submission.finalized is False
        return {
            "block_number": submission.block_number,
            "block_hash": submission.block_hash,
            "validator_uid": launch.UID30,
            "dests": [state.miner_uid],
            "weights_u16": [W],
        }

    result = launch.submit_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        qvl_path="/pinned/qvl",
        confirm=True,
        exclusive_writer_asserted=True,
        chain_loader=chain_loader,
        miner_loader=lambda *_args, **_kwargs: _proof(),
        submit_call=submit_call,
        readback_call=readback_call,
    )
    assert captured == {"uids": [61], "weights": [65535]}
    assert result.miner_uid == 61
    assert result.stored_weight == 65535
    assert chain_reads == 2

    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
    )
    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    assert journal["submission_pending_id"] is None
    assert journal["submission_finalized_receipt"]["wire_uids"] == [61]
    assert journal["submission_finalized_receipt"]["wire_weights"] == [65535]
    assert journal["submission_finalized_identity"]["exclusive_writer_assertion"] == {
        "asserted": True,
        "scope": "all_other_uid30_processes_and_hosts_stopped",
    }
    assert journal["submission_finalized_count"] == 1
    assert SN39_MORTAL_PERIOD_BLOCKS == 16
