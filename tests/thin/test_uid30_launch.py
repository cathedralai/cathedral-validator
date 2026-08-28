from __future__ import annotations

import copy
import fcntl
import os
import stat
from datetime import UTC, datetime
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
from scripts import publish_sn39_validator_status as status_publisher

TEST_NOW = datetime(2026, 8, 28, 12, 1, tzinfo=UTC)


class _Substrate:
    def __init__(self, block: int, block_hash: str) -> None:
        self.block = block
        self.block_hash = block_hash

    def get_block_hash(self, block: int) -> str:
        if block == self.block:
            return self.block_hash
        if block == 1_002:
            return "0x" + "b" * 64
        if block == 1_000:
            return "0x" + "1" * 64
        if block == 999:
            return "0x" + "5" * 64
        return "0x" + "6" * 64

    def get_chain_finalised_head(self) -> str:
        return self.block_hash

    def get_block_number(self, block_hash: str) -> int:
        assert block_hash == self.block_hash
        return self.block

    def query(self, **_kwargs):
        return [[61, W]]


class _Subtensor:
    def __init__(self, block: int, block_hash: str) -> None:
        self.substrate = _Substrate(block, block_hash)
        self.block = block

    def metagraph(self, _netuid: int, *, block: int):
        return SimpleNamespace(
            block=block,
            uids=[61],
            hotkeys=[launch.MINER_HOTKEY],
            axons=[SimpleNamespace(ip="8.8.8.8", port=8081, is_serving=True)],
        )


def _preflight(block: int, block_hash: str, next_epoch: int) -> SimpleNamespace:
    return SimpleNamespace(
        block=block,
        finalized_hash=block_hash,
        genesis_hash=FINNEY_GENESIS_HASH,
        validator_hotkey=launch.UID30_HOTKEY,
        validator_uid=launch.UID30,
        subnet_owner_hotkey=canonical_validator.SN39_BURN_HOTKEY,
        commit_reveal_enabled=False,
        weights_rate_limit=100,
        validator_blocks_since_last_update=200,
        next_epoch_start_block=next_epoch,
        blocks_until_next_epoch=next_epoch - block,
        subtensor=_Subtensor(block, block_hash),
    )


@pytest.fixture(autouse=True)
def _canonical_test_runtime_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", tmp_path / "runtime")


def _state(**changes) -> launch.UID30ChainState:
    values = {
        "preflight": None,
        "block_number": 1_000,
        "block_hash": "0x" + "1" * 64,
        "genesis_hash": FINNEY_GENESIS_HASH,
        "subnet_owner_hotkey": canonical_validator.SN39_BURN_HOTKEY,
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
    if "preflight" not in changes:
        values["preflight"] = _preflight(
            int(values["block_number"]),
            str(values["block_hash"]),
            int(values["next_epoch_start_block"]),
        )
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
            now=TEST_NOW,
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
            now=TEST_NOW,
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
            now=TEST_NOW,
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
            now=TEST_NOW,
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
                now=TEST_NOW,
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
            now=TEST_NOW,
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
            now=TEST_NOW,
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
            now=TEST_NOW,
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
        now=TEST_NOW,
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


def test_submit_refuses_regressed_or_unrelated_finalized_head(tmp_path: Path) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    preview, _observed = launch.load_reviewed_preview(path, reviewed_sha256=digest)
    regressed = _state(
        block_number=999,
        block_hash="0x" + "5" * 64,
        last_update=799,
        blocks_since_last_update=200,
        blocks_until_next_epoch=201,
    )
    with pytest.raises(launch.UID30LaunchError, match="regressed"):
        launch._fresh_state_matches_preview(regressed, preview, now=TEST_NOW)
    unrelated = _state(block_hash="0x" + "6" * 64)
    with pytest.raises(launch.UID30LaunchError, match="not canonical"):
        launch._fresh_state_matches_preview(unrelated, preview, now=TEST_NOW)


def test_private_or_wrong_port_axon_is_refused_before_dial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for ip, port, message in (
        ("10.0.0.2", 8081, "not canonical public IP"),
        ("8.8.8.8", 443, "port 8081"),
    ):
        preflight = _preflight(1_000, "0x" + "1" * 64, 1_200)
        preflight.subtensor.metagraph = lambda _netuid, *, block, ip=ip, port=port: (
            SimpleNamespace(
                block=block,
                uids=[61],
                hotkeys=[launch.MINER_HOTKEY],
                axons=[SimpleNamespace(ip=ip, port=port, is_serving=True)],
            )
        )
        dialed: list[str] = []

        def dial(url, *_args, _dialed=dialed, **_kwargs):
            _dialed.append(url)
            raise AssertionError("endpoint gate must run before dial")

        monkeypatch.setattr(launch, "_try_collect", dial)
        with pytest.raises(launch.UID30LaunchError, match=message):
            launch.collect_verified_miner(
                _state(preflight=preflight), qvl_path="/not/read"
            )
        assert dialed == []


def test_fresh_miner_requires_same_current_finalized_axon(tmp_path: Path) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    preview, _observed = launch.load_reviewed_preview(path, reviewed_sha256=digest)
    preflight = _preflight(1_000, "0x" + "1" * 64, 1_200)
    preflight.subtensor.metagraph = lambda _netuid, *, block: SimpleNamespace(
        block=block,
        uids=[61],
        hotkeys=[launch.MINER_HOTKEY],
        axons=[SimpleNamespace(ip="1.1.1.1", port=8081, is_serving=True)],
    )
    with pytest.raises(launch.UID30LaunchError, match="no longer the same"):
        launch._fresh_miner_matches_preview(
            _proof(), state=_state(preflight=preflight), preview=preview
        )


def test_finalized_readback_requires_exact_signed_call_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state()
    preview = launch.build_preview(
        state=state,
        miner=_proof(),
        runtime_root=tmp_path / "runtime",
        created_at="2026-08-28T12:00:00Z",
    )
    identity = launch._attempt_identity(
        preview=preview,
        preview_sha256="a" * 64,
        state=state,
        fresh_miner=_proof(),
    )
    observed: dict[str, object] = {}

    def classify(_subtensor, **kwargs):
        observed["extrinsic_hash"] = kwargs["extrinsic_hash"]
        observed["uid_hotkeys"] = kwargs["uid_hotkeys"]
        return canonical_validator.FAIL

    monkeypatch.setattr(
        canonical_validator,
        "_classify_finalized_receipt_awaiting_finality",
        classify,
    )
    submission = canonical_validator.ChainSubmission(
        success=True,
        extrinsic_hash="0x" + "9" * 64,
        block_hash=state.block_hash,
        block_number=state.block_number,
        finalized=False,
    )
    with pytest.raises(launch.UID30LaunchAmbiguous, match="signed-call proof"):
        launch._finalized_readback(
            state=state,
            submission=submission,
            receipt=SimpleNamespace(is_success=True),
            identity=identity,
        )
    assert observed == {
        "extrinsic_hash": "0x" + "9" * 64,
        "uid_hotkeys": {
            61: launch.MINER_HOTKEY,
            launch.UID30: launch.UID30_HOTKEY,
        },
    }


@pytest.mark.parametrize(
    ("uid30_hotkey", "signer_uid", "expected"),
    (
        (launch.UID30_HOTKEY, launch.UID30, canonical_validator.PASS),
        ("5AttackerAtUid30", 62, canonical_validator.FAIL),
    ),
)
def test_real_classifier_binds_uid30_to_the_signer_at_inclusion(
    uid30_hotkey: str, signer_uid: int, expected: str
) -> None:
    block_number = 1_002
    finalized_number = 1_003
    block_hash = "0x" + "b" * 64
    finalized_hash = "0x" + "d" * 64
    extrinsic_hash = "0x" + "a" * 64
    call = {
        "call_module": "SubtensorModule",
        "call_function": "set_mechanism_weights",
        "call_args": [
            {"name": "netuid", "value": launch.NETUID},
            {"name": "mecid", "value": launch.MECID},
            {"name": "version_key", "value": VERSION_KEY},
            {"name": "dests", "value": [61]},
            {"name": "weights", "value": [W]},
        ],
    }
    substrate = SimpleNamespace(
        get_chain_finalised_head=lambda: finalized_hash,
        get_block_number=lambda value: (
            finalized_number if value == finalized_hash else block_number
        ),
        get_block_hash=lambda number: (
            finalized_hash if number == finalized_number else block_hash
        ),
        get_block=lambda **_kwargs: {
            "extrinsics": [
                SimpleNamespace(
                    value={
                        "extrinsic_hash": extrinsic_hash,
                        "address": launch.UID30_HOTKEY,
                        "call": call,
                    }
                )
            ]
        },
        retrieve_extrinsic_by_hash=lambda *_args: SimpleNamespace(
            is_success=True,
            error_message=None,
            extrinsic_idx=0,
        ),
    )
    if signer_uid == launch.UID30:
        inclusion = SimpleNamespace(
            block=block_number,
            uids=[launch.UID30, 61],
            hotkeys=[uid30_hotkey, launch.MINER_HOTKEY],
            validator_permit=[True, False],
        )
    else:
        inclusion = SimpleNamespace(
            block=block_number,
            uids=[launch.UID30, 61, signer_uid],
            hotkeys=[uid30_hotkey, launch.MINER_HOTKEY, launch.UID30_HOTKEY],
            validator_permit=[False, False, True],
        )
    subtensor = SimpleNamespace(
        substrate=substrate,
        metagraph=lambda _netuid, *, block: inclusion,
    )

    assert (
        canonical_validator._classify_finalized_receipt(
            subtensor,
            receipt=None,
            extrinsic_hash=extrinsic_hash,
            block_hash=block_hash,
            block_number=block_number,
            validator_hotkey=launch.UID30_HOTKEY,
            netuid=launch.NETUID,
            version_key=VERSION_KEY,
            wire_uids=[61],
            wire_weights=[W],
            uid_hotkeys={
                61: launch.MINER_HOTKEY,
                launch.UID30: launch.UID30_HOTKEY,
            },
            require_receipt=False,
        )
        == expected
    )


def test_primary_finalization_rejects_nonexact_historical_weights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state()
    historical_queries: list[dict[str, object]] = []
    state.preflight.subtensor.substrate.query = lambda **kwargs: (
        historical_queries.append(kwargs) or [[62, W]]
    )
    preview = launch.build_preview(
        state=state,
        miner=_proof(),
        runtime_root=tmp_path / "runtime",
        created_at="2026-08-28T12:00:00Z",
    )
    identity = launch._attempt_identity(
        preview=preview,
        preview_sha256="a" * 64,
        state=state,
        fresh_miner=_proof(),
    )
    monkeypatch.setattr(
        canonical_validator,
        "_classify_finalized_receipt_awaiting_finality",
        lambda *_args, **_kwargs: canonical_validator.PASS,
    )
    submission = canonical_validator.ChainSubmission(
        success=True,
        extrinsic_hash="0x" + "9" * 64,
        block_hash=state.block_hash,
        block_number=state.block_number,
        finalized=False,
    )

    with pytest.raises(launch.UID30LaunchContradiction, match="mechanism weights"):
        launch._finalized_readback(
            state=state,
            submission=submission,
            receipt=SimpleNamespace(is_success=True),
            identity=identity,
        )
    assert historical_queries == [
        {
            "module": "SubtensorModule",
            "storage_function": "Weights",
            "params": [39, launch.UID30],
            "block_hash": state.block_hash,
        }
    ]


def test_signed_ambiguity_has_read_only_exact_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=ambiguous,
        )
    recovered_preflight = _preflight(1_002, "0x" + "b" * 64, 1_200)
    monkeypatch.setattr(
        canonical_validator,
        "_classify_finalized_receipt",
        lambda *_args, **_kwargs: canonical_validator.PASS,
    )

    def locate(*_args, **_kwargs):
        return (
            canonical_validator.PASS,
            canonical_validator.ChainSubmission(
                success=True,
                extrinsic_hash="0x" + "a" * 64,
                block_hash="0x" + "b" * 64,
                block_number=1_002,
                finalized=True,
            ),
        )

    result = launch.recover_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
        preflight_loader=lambda: recovered_preflight,
        locate_call=locate,
    )
    assert result.status == "RECOVERED_FINALIZED"
    assert result.miner_uid == 61
    assert result.stored_weight == W

    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
        authorized=True,
    )
    args.state_file = str(runtime_root / "uid30-authority-state.json")
    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    mirrored = canonical_validator._recover_common_finalized_submission(args, journal)
    assert mirrored is not None
    assert mirrored.burn_uid is None
    assert mirrored.burn_share == 0.0


def test_recovery_expires_absent_attempt_without_retry(tmp_path: Path) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=ambiguous,
        )
    result = launch.recover_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
        preflight_loader=lambda: _preflight(1_020, "0x" + "c" * 64, 1_200),
        locate_call=lambda *_args, **_kwargs: (
            canonical_validator.EXPIRED_WITHOUT_INCLUSION,
            None,
        ),
    )
    assert result.status == canonical_validator.EXPIRED_WITHOUT_INCLUSION
    assert result.stored_weight is None


def test_recovery_durably_fences_a_positive_historical_mismatch(
    tmp_path: Path,
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
            confirm=True,
            exclusive_writer_asserted=True,
            chain_loader=_state,
            miner_loader=lambda *_args, **_kwargs: _proof(),
            submit_call=ambiguous,
        )

    with pytest.raises(launch.UID30LaunchContradiction, match="not uniquely proven"):
        launch.recover_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            exclusive_writer_asserted=True,
            preflight_loader=lambda: _preflight(1_002, "0x" + "b" * 64, 1_200),
            locate_call=lambda *_args, **_kwargs: (canonical_validator.FAIL, None),
        )

    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
        authorized=True,
    )
    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    assert journal["submission_pending_proof_status"] == canonical_validator.FAIL

    called = False

    def forbidden_locate(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("positive mismatch must fence before an archive retry")

    with pytest.raises(launch.UID30LaunchContradiction, match="recovery is forbidden"):
        launch.recover_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            exclusive_writer_asserted=True,
            preflight_loader=lambda: _preflight(1_002, "0x" + "b" * 64, 1_200),
            locate_call=forbidden_locate,
        )
    assert called is False


def test_already_finalized_recovery_reproves_the_exact_chain_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest, _runtime_root = _preview_files(tmp_path)
    result = launch.submit_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        qvl_path="/pinned/qvl",
        now=TEST_NOW,
        confirm=True,
        exclusive_writer_asserted=True,
        chain_loader=_state,
        miner_loader=lambda *_args, **_kwargs: _proof(),
        submit_call=_intent_then_receipt,
        readback_call=lambda **_kwargs: {
            "dests": [61],
            "weights_u16": [W],
        },
    )
    assert result.extrinsic_hash == "0x" + "a" * 64

    observed: dict[str, object] = {}

    def classify(_subtensor, **kwargs):
        observed.update(kwargs)
        return canonical_validator.PASS

    monkeypatch.setattr(
        canonical_validator,
        "_classify_finalized_receipt",
        classify,
    )
    recovered = launch.recover_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
        preflight_loader=lambda: _preflight(1_003, "0x" + "d" * 64, 1_200),
    )
    assert recovered.status == "ALREADY_FINALIZED"
    assert recovered.extrinsic_hash == "0x" + "a" * 64
    assert observed["extrinsic_hash"] == "0x" + "a" * 64
    assert observed["block_hash"] == "0x" + "b" * 64
    assert observed["wire_uids"] == [61]
    assert observed["wire_weights"] == [W]
    assert observed["require_receipt"] is False


def test_canonical_startup_recovers_zero_burn_uid30_without_resubmitting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
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
        authorized=True,
    )
    args.state_file = str(runtime_root / "uid30-authority-state.json")
    args._tick_preflight = _preflight(1_003, "0x" + "d" * 64, 1_200)
    historical_queries: list[dict[str, object]] = []
    args._tick_preflight.subtensor.substrate.query = lambda **kwargs: (
        historical_queries.append(kwargs) or [[61, W]]
    )
    monkeypatch.setattr(
        canonical_validator,
        "_prepare_tick_preflight",
        lambda _args: None,
    )
    monkeypatch.setattr(canonical_validator, "ChainPreflight", SimpleNamespace)
    monkeypatch.setattr(
        canonical_validator,
        "_locate_pending_broadcast_receipt",
        lambda *_args, **_kwargs: (
            canonical_validator.PASS,
            canonical_validator.ChainSubmission(
                success=True,
                extrinsic_hash="0x" + "a" * 64,
                block_hash="0x" + "b" * 64,
                block_number=1_002,
                finalized=True,
            ),
        ),
    )
    classifier_args: dict[str, object] = {}

    def classify(*_args, **kwargs):
        classifier_args.update(kwargs)
        return canonical_validator.PASS

    monkeypatch.setattr(canonical_validator, "_classify_finalized_receipt", classify)

    recovered = canonical_validator._recover_pending_launch_receipt(args)
    assert isinstance(recovered, canonical_validator.RecoveredAuthoritySubmission)
    assert recovered.uid_weights == ((61, 1.0),)
    assert recovered.burn_uid is None
    assert recovered.burn_share == 0.0
    assert recovered.extrinsic_hash == "0x" + "a" * 64
    assert classifier_args["uid_hotkeys"] == {
        61: launch.MINER_HOTKEY,
        launch.UID30: launch.UID30_HOTKEY,
    }
    assert historical_queries == [
        {
            "module": "SubtensorModule",
            "storage_function": "Weights",
            "params": [39, launch.UID30],
            "block_hash": "0x" + "b" * 64,
        }
    ]
    assert recovered.boundary_detail == (
        "authority=full_provenance uids=1 vector=61:1.000000"
    )
    assert status_publisher.parse_weight_boundary(recovered.boundary_detail) == {
        "authority": "full_provenance",
        "uid_count": 1,
        "burn_uid": None,
        "burn_share": None,
        "uid_weights": {"61": 1.0},
    }


def test_canonical_zero_burn_recovery_fences_historical_storage_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
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
        authorized=True,
    )
    args.state_file = str(runtime_root / "uid30-authority-state.json")
    args._tick_preflight = _preflight(1_003, "0x" + "d" * 64, 1_200)
    args._tick_preflight.subtensor.substrate.query = lambda **_kwargs: [[62, W]]
    monkeypatch.setattr(
        canonical_validator, "_prepare_tick_preflight", lambda _args: None
    )
    monkeypatch.setattr(canonical_validator, "ChainPreflight", SimpleNamespace)
    monkeypatch.setattr(
        canonical_validator,
        "_locate_pending_broadcast_receipt",
        lambda *_args, **_kwargs: (
            canonical_validator.PASS,
            canonical_validator.ChainSubmission(
                success=True,
                extrinsic_hash="0x" + "a" * 64,
                block_hash="0x" + "b" * 64,
                block_number=1_002,
                finalized=True,
            ),
        ),
    )
    monkeypatch.setattr(
        canonical_validator,
        "_classify_finalized_receipt",
        lambda *_args, **_kwargs: canonical_validator.PASS,
    )

    with pytest.raises(
        canonical_validator._PostSignedSubmissionMismatch,
        match="historical inclusion contract",
    ):
        canonical_validator._recover_pending_launch_receipt(args)

    journal = canonical_validator._read_state(
        canonical_validator._submission_state_path(args)
    )
    assert journal["submission_pending_proof_status"] == canonical_validator.FAIL
    assert journal["submission_pending_id"] is not None
    assert journal.get("submission_finalized_id") is None
    assert Path(args.state_file).exists() is False


def test_zero_burn_historical_storage_rpc_failure_is_not_positive_mismatch() -> None:
    subtensor = SimpleNamespace(
        substrate=SimpleNamespace(
            query=lambda **_kwargs: (_ for _ in ()).throw(
                ConnectionError("archive unavailable")
            )
        )
    )
    reasons: list[str] = []
    assert (
        canonical_validator._classify_zero_burn_uid30_historical_weights(
            subtensor,
            block_hash="0x" + "b" * 64,
            wire_uids=[61],
            wire_weights=[W],
            reason_out=reasons,
        )
        == canonical_validator.NOT_PROVEN
    )
    assert reasons[-1].startswith("chain read failed at substrate.query")


def test_canonical_startup_rejects_malformed_zero_burn_before_finalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)

    def ambiguous(*args, **kwargs):
        _intent_then_receipt(*args, **kwargs)
        raise ConnectionError("receipt transport closed after broadcast")

    with pytest.raises(launch.UID30LaunchAmbiguous):
        launch.submit_reviewed_preview(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            now=TEST_NOW,
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
        authorized=True,
    )
    args.state_file = str(runtime_root / "uid30-authority-state.json")
    args._tick_preflight = _preflight(1_003, "0x" + "d" * 64, 1_200)
    state_path = canonical_validator._submission_state_path(args)
    journal = canonical_validator._read_state(state_path)
    pending_id = journal["submission_pending_id"]
    malformed = copy.deepcopy(journal)
    malformed["submission_pending_identity"]["uid_weights"] = [
        [61, 0.5],
        [62, 0.5],
    ]
    malformed["submission_pending_identity"]["uid_hotkeys"] = [
        [61, launch.MINER_HOTKEY],
        [62, launch.UID30_HOTKEY],
    ]
    canonical_validator._replace_private_state(state_path, malformed)

    monkeypatch.setattr(
        canonical_validator,
        "_prepare_tick_preflight",
        lambda _args: None,
    )
    monkeypatch.setattr(canonical_validator, "ChainPreflight", SimpleNamespace)
    located = False

    def forbidden_locate(*_args, **_kwargs):
        nonlocal located
        located = True
        raise AssertionError(
            "malformed zero-burn identity must fail before archive reads"
        )

    monkeypatch.setattr(
        canonical_validator,
        "_locate_pending_broadcast_receipt",
        forbidden_locate,
    )
    with pytest.raises(
        canonical_validator._PostSignedSubmissionMismatch,
        match="one exact target row",
    ):
        canonical_validator._recover_pending_launch_receipt(args)
    assert located is False
    after = canonical_validator._read_state(state_path)
    assert after["submission_pending_id"] == pending_id
    assert after.get("submission_finalized_id") is None
    assert after.get("submission_pending_receipt_candidate") is None


def test_finalized_mirror_rejects_loose_zero_burn_markers_before_lane_write(
    tmp_path: Path,
) -> None:
    path, digest, runtime_root = _preview_files(tmp_path)
    launch.submit_reviewed_preview(
        preview_path=path,
        reviewed_sha256=digest,
        qvl_path="/pinned/qvl",
        now=TEST_NOW,
        confirm=True,
        exclusive_writer_asserted=True,
        chain_loader=_state,
        miner_loader=lambda *_args, **_kwargs: _proof(),
        submit_call=_intent_then_receipt,
        readback_call=lambda **_kwargs: {
            "dests": [61],
            "weights_u16": [W],
        },
    )
    args = launch._submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=digest,
        authorized=True,
    )
    lane_state = runtime_root / "uid30-authority-state.json"
    args.state_file = str(lane_state)
    common_state = canonical_validator._submission_state_path(args)
    journal = canonical_validator._read_state(common_state)
    malformed = copy.deepcopy(journal)
    identity = malformed["submission_finalized_identity"]
    identity["validator_hotkey"] = "5FakeValidator"
    identity["uid_hotkeys"] = [[61, "5ArbitraryMiner"]]
    identity["subnet_owner_hotkey"] = "not-an-ss58"
    identity["burn_share"] = False
    identity.pop("exclusive_writer_assertion")
    malformed["submission_validator_hotkey"] = "5FakeValidator"
    canonical_validator._replace_private_state(common_state, malformed)

    with pytest.raises(
        canonical_validator.wire.VectorError,
        match="exact reviewed launch contract",
    ):
        canonical_validator._recover_common_finalized_submission(args, malformed)
    assert lane_state.exists() is False


@pytest.mark.parametrize(
    "contradiction",
    (
        {"burn_share": False},
        {"burn_hotkey": canonical_validator.SN39_BURN_HOTKEY},
    ),
)
def test_specialized_recovery_uses_the_strict_zero_burn_identity(
    tmp_path: Path, contradiction: dict[str, object]
) -> None:
    state = _state()
    proof = _proof()
    preview = launch.build_preview(
        state=state,
        miner=proof,
        runtime_root=tmp_path / "runtime",
        created_at="2026-08-28T12:00:00Z",
    )
    identity = launch._attempt_identity(
        preview=preview,
        preview_sha256="a" * 64,
        state=state,
        fresh_miner=proof,
    )
    identity.update(contradiction)
    with pytest.raises(launch.UID30LaunchError, match="identity is invalid"):
        launch._validate_attempt_identity(
            identity,
            preview=preview,
            preview_sha256="a" * 64,
        )
