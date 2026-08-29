from __future__ import annotations

import copy
import contextlib
import inspect
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin import second_miner_plan
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
from scaffold import validator_thin as canonical


BLOCK = canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK + 200
BLOCK_HASH = "0x" + "f" * 64
NEXT_EPOCH = BLOCK + 200


class _Substrate:
    def get_block_hash(self, block: int) -> str:
        if block == BLOCK:
            return BLOCK_HASH
        if block == BLOCK - 2:
            return "0x" + "a" * 64
        if block == BLOCK - 1:
            return "0x" + "b" * 64
        raise AssertionError(block)


def _base_state() -> launch.UID30ChainState:
    preflight = SimpleNamespace(
        subtensor=SimpleNamespace(substrate=_Substrate()),
        hotkey_to_uid={
            launch.UID30_HOTKEY: launch.UID30,
            launch.MINER_HOTKEY: 124,
            canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: 8,
        },
    )
    return launch.UID30ChainState(
        preflight=preflight,
        block_number=BLOCK,
        block_hash=BLOCK_HASH,
        genesis_hash=FINNEY_GENESIS_HASH,
        subnet_owner_hotkey=canonical.SN39_BURN_HOTKEY,
        validator_hotkey=launch.UID30_HOTKEY,
        validator_uid=launch.UID30,
        validator_permit=True,
        validator_stake_rao=2_000,
        stake_threshold_rao=1_000,
        last_update=canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        blocks_since_last_update=(
            BLOCK - canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        ),
        weights_rate_limit=100,
        mechanism_count=1,
        weights_version_key=VERSION_KEY,
        min_allowed_weights=MIN_ALLOWED_WEIGHTS,
        max_weight_limit=MAX_WEIGHT_LIMIT,
        commit_reveal_enabled=COMMIT_REVEAL_ENABLED,
        miner_hotkey=launch.MINER_HOTKEY,
        miner_uid=124,
        serving_axon=launch.ServingAxon(
            uid=124,
            hotkey=launch.MINER_HOTKEY,
            ip="35.222.166.235",
            port=8081,
        ),
        next_epoch_start_block=NEXT_EPOCH,
        blocks_until_next_epoch=NEXT_EPOCH - BLOCK,
        uid_safety={"primary": "safe"},
    )


def _target(
    *, uid: int, hotkey: str, ip: str
) -> second_miner_plan.Neuron:
    return second_miner_plan.Neuron(
        uid=uid,
        hotkey=hotkey,
        coldkey=second_miner_plan.CATHEDRAL_COLDKEY,
        validator_permit=False,
        last_update=BLOCK - 100,
        ip=ip,
        port=second_miner_plan.HTTPS_PORT,
        protocol=second_miner_plan.HTTPS_PROTOCOL,
        serving=True,
    )


def _successor_state() -> launch.UID30SuccessorState:
    return launch.UID30SuccessorState(
        base=_base_state(),
        targets=(
            _target(
                uid=8,
                hotkey=canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
                ip="34.46.19.69",
            ),
            _target(uid=124, hotkey=launch.MINER_HOTKEY, ip="35.222.166.235"),
        ),
        uid_safety={
            "schema": "cathedral_sn39_uid_safety_v2",
            "targets": [
                [8, canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY],
                [124, launch.MINER_HOTKEY],
            ],
        },
        current_weights=((canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, W),),
    )


def _proof(
    *, hotkey: str, uid: int, ip: str, spki: str, anchor: int, anchor_hash: str
) -> launch.VerifiedMinerProof:
    return launch.VerifiedMinerProof(
        hotkey=hotkey,
        uid=uid,
        ip=ip,
        port=8081,
        qvl_digest=LAUNCH_QVL_DIGEST,
        quote_sha256=("2" if uid == 8 else "3") * 64,
        report_data_sha256=("4" if uid == 8 else "5") * 64,
        tls_spki_sha256=spki,
        sat_units=20,
        sat_rule=SAT_WORK_UNIT_RULE,
        anchor_number=anchor,
        anchor_hash=anchor_hash,
    )


def _proofs() -> tuple[launch.VerifiedMinerProof, launch.VerifiedMinerProof]:
    return (
        _proof(
            hotkey=canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
            uid=8,
            ip="34.46.19.69",
            spki="6" * 64,
            anchor=BLOCK - 2,
            anchor_hash="0x" + "a" * 64,
        ),
        _proof(
            hotkey=launch.MINER_HOTKEY,
            uid=124,
            ip="35.222.166.235",
            spki="7" * 64,
            anchor=BLOCK - 1,
            anchor_hash="0x" + "b" * 64,
        ),
    )


def test_successor_state_resolves_both_hotkeys_dynamically_at_one_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _base_state()
    targets = _successor_state().targets
    snapshot = second_miner_plan.FinalizedSnapshot(
        block_number=BLOCK,
        block_hash=BLOCK_HASH,
        genesis_hash=FINNEY_GENESIS_HASH,
        neurons=(
            _target(uid=30, hotkey=launch.UID30_HOTKEY, ip="8.8.8.8"),
            *targets,
        ),
        uid30_weights=((canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, W),),
    )
    expected_mapping = {
        8: canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
        124: launch.MINER_HOTKEY,
    }
    monkeypatch.setattr(launch, "read_uid30_chain_state", lambda: base)
    monkeypatch.setattr(
        second_miner_plan,
        "read_snapshot_at",
        lambda **kwargs: (
            snapshot
            if kwargs
            == {
                "subtensor": base.preflight.subtensor,
                "block_number": BLOCK,
                "block_hash": BLOCK_HASH,
                "genesis_hash": FINNEY_GENESIS_HASH,
            }
            else pytest.fail(kwargs)
        ),
    )
    monkeypatch.setattr(
        second_miner_plan,
        "build_plan",
        lambda observed: (
            {"status": second_miner_plan.STATUS_PROOF}
            if observed is snapshot
            else pytest.fail(observed)
        ),
    )
    monkeypatch.setattr(
        canonical,
        "_require_uid_mapping_stability",
        lambda preflight, mapping, *, mortal_period_blocks: (
            {"combined": "safe"}
            if preflight is base.preflight
            and mapping == expected_mapping
            and mortal_period_blocks == SN39_MORTAL_PERIOD_BLOCKS
            else pytest.fail((preflight, mapping, mortal_period_blocks))
        ),
    )

    state = launch.read_uid30_successor_state()

    assert [target.uid for target in state.targets] == [8, 124]
    assert {target.hotkey for target in state.targets} == set(
        expected_mapping.values()
    )
    assert state.current_weights == ((124, W),)
    assert state.uid_safety == {"combined": "safe"}


def test_successor_state_requires_exact_historical_predecessor_row() -> None:
    state = _successor_state()
    changed = launch.UID30SuccessorState(
        base=state.base,
        targets=state.targets,
        uid_safety=state.uid_safety,
        current_weights=((8, W), (124, W)),
    )

    with pytest.raises(launch.UID30LaunchError, match="one-miner predecessor"):
        launch.validate_uid30_successor_state(changed)


def test_successor_preview_is_exact_two_rows_zero_burn_and_two_later_heads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(launch, "_assert_successor_writer_available", lambda _args: None)

    preview = launch.build_successor_preview(
        state=_successor_state(),
        miners=_proofs(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )

    assert preview["proposed_vector"] == {
        "dests": [8, 124],
        "weights_u16": [65535, 65535],
        "normalized": [[8, "1.0"], [124, "1.0"]],
        "expected_storage": [[8, 65535], [124, 65535]],
        "burn_destination": None,
        "burn_weight_u16": 0,
    }
    assert preview["weight_submission"]["attempt_budget"] == {
        "scope": "authority_bounded",
        "limit": 1,
    }
    assert preview["weight_submission"]["later_finalized_heads_required"] == 2
    assert preview["predecessor"] == launch._successor_predecessor_artifact()


@pytest.mark.parametrize(
    "mutation",
    ["extra_row", "burn", "wrong_hotkey", "duplicate_spki", "qvl_not_pass"],
)
def test_successor_preview_rejects_non_exact_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(launch, "_assert_successor_writer_available", lambda _args: None)
    preview = launch.build_successor_preview(
        state=_successor_state(),
        miners=_proofs(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )
    changed = copy.deepcopy(preview)
    if mutation == "extra_row":
        changed["proposed_vector"]["dests"].append(200)
    elif mutation == "burn":
        changed["proposed_vector"]["burn_weight_u16"] = 1
    elif mutation == "wrong_hotkey":
        changed["miners"][0]["hotkey"] = launch.UID30_HOTKEY
    elif mutation == "duplicate_spki":
        changed["miners"][1]["tls_spki_sha256"] = changed["miners"][0][
            "tls_spki_sha256"
        ]
    elif mutation == "qvl_not_pass":
        changed["miners"][1]["qvl_status"] = canonical.FAIL

    with pytest.raises(launch.UID30LaunchError):
        launch.validate_successor_preview(changed)


def test_successor_preview_write_and_load_is_owner_only_and_digest_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(launch, "_assert_successor_writer_available", lambda _args: None)
    preview = launch.build_successor_preview(
        state=_successor_state(),
        miners=_proofs(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )

    path, digest_path, digest = launch.write_successor_preview(
        preview, runtime_root / "successor.json"
    )
    loaded, loaded_digest = launch.load_reviewed_successor_preview(
        path, reviewed_sha256=digest
    )

    assert loaded == preview
    assert loaded_digest == digest
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(digest_path.stat().st_mode) == 0o600
    with pytest.raises(launch.UID30LaunchError, match="differs from its bytes"):
        launch.load_reviewed_successor_preview(path, reviewed_sha256="0" * 64)


def _later_snapshot(
    *, block: int, block_hash: str, case: str | None = None
) -> second_miner_plan.FinalizedSnapshot:
    validator_row = second_miner_plan.Neuron(
        uid=30,
        hotkey=launch.UID30_HOTKEY,
        coldkey=second_miner_plan.CATHEDRAL_COLDKEY,
        validator_permit=case != "permit",
        last_update=BLOCK,
        ip=None,
        port=0,
        protocol=0,
        serving=False,
    )
    second_uid = 9 if case == "mapping" else 8
    second = _target(
        uid=second_uid,
        hotkey=canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
        ip="34.46.19.69",
    )
    if case == "ip":
        second = replace(second, ip="34.46.19.70")
    elif case == "port":
        second = replace(second, port=8080)
    elif case == "protocol":
        second = replace(second, protocol=0)
    elif case == "serving":
        second = replace(second, serving=False)
    return second_miner_plan.FinalizedSnapshot(
        block_number=block,
        block_hash=block_hash,
        genesis_hash=FINNEY_GENESIS_HASH,
        neurons=(
            validator_row,
            second,
            _target(uid=124, hotkey=launch.MINER_HOTKEY, ip="35.222.166.235"),
        ),
        uid30_weights=(
            ((124, W),)
            if case == "row"
            else ((8, W), (124, W))
        ),
    )


def _later_head_state(
    *,
    monkeypatch: pytest.MonkeyPatch,
    latest_number: int,
    case: str | None = None,
) -> tuple[launch.UID30SuccessorState, list[tuple[int, str]]]:
    latest_hash = "0x" + "d" * 64
    hashes = {
        latest_number - 1: "0x" + "c" * 64,
        latest_number: latest_hash,
    }

    def get_block_hash(block: int) -> str:
        if case == "reverse" and block == latest_number:
            return "0x" + "e" * 64
        return hashes[block]

    substrate = SimpleNamespace(
        get_chain_finalised_head=lambda: latest_hash,
        get_block_number=lambda block_hash: (
            latest_number if block_hash == latest_hash else pytest.fail(block_hash)
        ),
        get_block_hash=get_block_hash,
    )
    base = _base_state()
    state = _successor_state()
    state = launch.UID30SuccessorState(
        base=replace(
            base,
            preflight=SimpleNamespace(subtensor=SimpleNamespace(substrate=substrate)),
        ),
        targets=state.targets,
        uid_safety=state.uid_safety,
        current_weights=state.current_weights,
    )
    calls: list[tuple[int, str]] = []

    def read_snapshot_at(**kwargs):
        block = kwargs["block_number"]
        block_hash = kwargs["block_hash"]
        calls.append((block, block_hash))
        if case == "rpc":
            raise second_miner_plan.SecondMinerPlanError("archive unavailable")
        assert kwargs == {
            "subtensor": state.preflight.subtensor,
            "block_number": block,
            "block_hash": block_hash,
            "genesis_hash": FINNEY_GENESIS_HASH,
        }
        return _later_snapshot(block=block, block_hash=block_hash, case=case)

    monkeypatch.setattr(second_miner_plan, "read_snapshot_at", read_snapshot_at)
    return state, calls


def test_successor_verifies_exact_row_and_identities_at_two_later_finalized_heads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inclusion = BLOCK + 2
    latest = inclusion + 2
    state, calls = _later_head_state(
        monkeypatch=monkeypatch,
        latest_number=latest,
    )

    proven = launch._verify_successor_later_finalized_heads(
        state=state,
        submission=SimpleNamespace(block_number=inclusion),
        wire_uids=[8, 124],
        wire_weights=[W, W],
    )

    assert proven == (
        (latest - 1, "0x" + "c" * 64),
        (latest, "0x" + "d" * 64),
    )
    assert calls == list(proven)


def test_successor_recovery_state_is_accepted_by_the_same_two_later_head_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inclusion = BLOCK + 2
    latest = inclusion + 2
    proof_state, calls = _later_head_state(
        monkeypatch=monkeypatch,
        latest_number=latest,
    )
    preflight = SimpleNamespace(
        genesis_hash=FINNEY_GENESIS_HASH,
        validator_hotkey=launch.UID30_HOTKEY,
        validator_uid=launch.UID30,
        validator_permit=True,
        hotkey_to_uid={
            launch.UID30_HOTKEY: launch.UID30,
            canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: 8,
            launch.MINER_HOTKEY: 124,
        },
        subtensor=proof_state.preflight.subtensor,
    )
    recovery_state = launch._successor_recovery_state(
        preflight=preflight,
        preview={
            "network": {"genesis_hash": FINNEY_GENESIS_HASH},
            "miners": [
                launch._successor_proof_artifact(proof) for proof in _proofs()
            ],
        },
        uid_hotkeys={
            8: canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
            124: launch.MINER_HOTKEY,
        },
    )

    proven = launch._verify_successor_later_finalized_heads(
        state=recovery_state,
        submission=SimpleNamespace(block_number=inclusion),
        wire_uids=[8, 124],
        wire_weights=[W, W],
    )

    assert calls == list(proven)


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("not_later", launch.UID30LaunchAmbiguous),
        ("reverse", launch.UID30LaunchAmbiguous),
        ("rpc", launch.UID30LaunchAmbiguous),
        ("row", launch.UID30LaunchContradiction),
        ("mapping", launch.UID30LaunchContradiction),
        ("permit", launch.UID30LaunchContradiction),
        ("ip", launch.UID30LaunchContradiction),
        ("port", launch.UID30LaunchContradiction),
        ("protocol", launch.UID30LaunchContradiction),
        ("serving", launch.UID30LaunchContradiction),
    ],
)
def test_successor_later_heads_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    error: type[Exception],
) -> None:
    inclusion = BLOCK + 2
    latest = inclusion + (1 if case == "not_later" else 2)
    state, _calls = _later_head_state(
        monkeypatch=monkeypatch,
        latest_number=latest,
        case=None if case == "not_later" else case,
    )

    with pytest.raises(error):
        launch._verify_successor_later_finalized_heads(
            state=state,
            submission=SimpleNamespace(block_number=inclusion),
            wire_uids=[8, 124],
            wire_weights=[W, W],
        )


@pytest.mark.parametrize(
    ("uids", "weights"),
    [
        ([8, 124, 200], [W, W, W]),
        ([8, 124], [W, 0]),
        ([True, 124], [W, W]),
        ([124, 8], [W, W]),
    ],
)
def test_successor_later_heads_reject_noncanonical_input_vector(
    monkeypatch: pytest.MonkeyPatch,
    uids: list[int],
    weights: list[int],
) -> None:
    inclusion = BLOCK + 2
    state, _calls = _later_head_state(
        monkeypatch=monkeypatch,
        latest_number=inclusion + 2,
    )

    with pytest.raises(launch.UID30LaunchContradiction, match="noncanonical"):
        launch._verify_successor_later_finalized_heads(
            state=state,
            submission=SimpleNamespace(block_number=inclusion),
            wire_uids=uids,
            wire_weights=weights,
        )


def _written_successor_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, str, launch.UID30SuccessorState]:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(launch, "DEFAULT_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(launch, "_assert_successor_writer_available", lambda _args: None)
    state = _successor_state()
    preview = launch.build_successor_preview(
        state=state,
        miners=_proofs(),
        runtime_root=runtime_root,
        created_at="2026-08-28T12:00:00Z",
    )
    path, _digest_path, digest = launch.write_successor_preview(
        preview,
        runtime_root / "successor.json",
    )
    return path, digest, state


def test_successor_submit_exposes_no_pluggable_authority_callbacks() -> None:
    parameters = set(inspect.signature(launch.submit_reviewed_successor).parameters)

    assert parameters.isdisjoint(
        {"submit_call", "readback_call", "later_heads_call", "finalize_call"}
    )


def test_successor_submit_uses_only_fixed_canonical_write_and_proof_seams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, state = _written_successor_preview(tmp_path, monkeypatch)
    sequence: list[str] = []
    observed_submit: dict[str, object] = {}
    receipt = SimpleNamespace(
        is_success=True,
        extrinsic_hash="0x" + "8" * 64,
        block_hash="0x" + "9" * 64,
        block_number=BLOCK + 2,
    )
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: (
            contextlib.nullcontext()
            if lane == "authority"
            else pytest.fail(lane)
        ),
    )
    monkeypatch.setattr(launch, "read_uid30_successor_state", lambda: state)
    monkeypatch.setattr(
        launch,
        "_fresh_successor_state_matches_preview",
        lambda observed, _preview: (
            None if observed is state else pytest.fail(observed)
        ),
    )
    monkeypatch.setattr(
        launch,
        "collect_verified_successor_miners",
        lambda observed, *, qvl_path: (
            _proofs()
            if observed is state and qvl_path == "/pinned/qvl"
            else pytest.fail((observed, qvl_path))
        ),
    )
    monkeypatch.setattr(
        canonical,
        "_reserve_common_submission",
        lambda *_args, **_kwargs: sequence.append("reserve"),
    )

    def submit(preflight, **kwargs):
        sequence.append("submit")
        observed_submit.update(kwargs)
        assert preflight is state.preflight
        return receipt

    monkeypatch.setattr(canonical, "_submit_exact_sn39_extrinsic", submit)
    monkeypatch.setattr(
        canonical,
        "_record_pending_submission_receipt",
        lambda *_args, **_kwargs: sequence.append("receipt"),
    )
    monkeypatch.setattr(
        launch,
        "_finalized_readback",
        lambda **_kwargs: sequence.append("readback")
        or {"dests": [8, 124], "weights_u16": [W, W]},
    )
    later_heads = ((BLOCK + 3, "0x" + "a" * 64), (BLOCK + 4, "0x" + "b" * 64))
    monkeypatch.setattr(
        launch,
        "_verify_successor_later_finalized_heads",
        lambda **_kwargs: sequence.append("later_heads") or later_heads,
    )
    monkeypatch.setattr(
        canonical,
        "_record_pending_proof_status",
        lambda *_args, **_kwargs: sequence.append("proof"),
    )
    monkeypatch.setattr(
        canonical,
        "_finalize_common_submission",
        lambda *_args, **_kwargs: sequence.append("finalize"),
    )
    monkeypatch.setattr(
        canonical,
        "_abort_unsigned_common_submission",
        lambda *_args, **_kwargs: pytest.fail("successful submit must not abort"),
    )

    result = launch.submit_reviewed_successor(
        preview_path=path,
        reviewed_sha256=digest,
        qvl_path="/pinned/qvl",
        confirm=True,
        exclusive_writer_asserted=True,
    )

    assert sequence == [
        "reserve",
        "submit",
        "receipt",
        "readback",
        "later_heads",
        "proof",
        "finalize",
    ]
    assert observed_submit["wire_uids"] == [8, 124]
    assert observed_submit["wire_weights"] == [W, W]
    assert observed_submit["netuid"] == 39
    assert observed_submit["version_key"] == VERSION_KEY
    assert result.wire_uids == (8, 124)
    assert result.wire_weights == (W, W)
    assert result.later_finalized_heads == later_heads


def test_successor_signed_failure_stays_ambiguous_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, state = _written_successor_preview(tmp_path, monkeypatch)
    calls = {"reserve": 0, "submit": 0, "abort": 0}
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: contextlib.nullcontext(),
    )
    monkeypatch.setattr(launch, "read_uid30_successor_state", lambda: state)
    monkeypatch.setattr(
        launch,
        "_fresh_successor_state_matches_preview",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        launch,
        "collect_verified_successor_miners",
        lambda *_args, **_kwargs: _proofs(),
    )

    def reserve(*_args, **_kwargs):
        calls["reserve"] += 1

    def submit(*_args, **_kwargs):
        calls["submit"] += 1
        raise TimeoutError("receipt unavailable after signed intent")

    def abort(*_args, **_kwargs):
        calls["abort"] += 1
        return False

    monkeypatch.setattr(canonical, "_reserve_common_submission", reserve)
    monkeypatch.setattr(canonical, "_submit_exact_sn39_extrinsic", submit)
    monkeypatch.setattr(canonical, "_abort_unsigned_common_submission", abort)

    with pytest.raises(launch.UID30LaunchAmbiguous, match="do not retry"):
        launch.submit_reviewed_successor(
            preview_path=path,
            reviewed_sha256=digest,
            qvl_path="/pinned/qvl",
            confirm=True,
            exclusive_writer_asserted=True,
        )

    assert calls == {"reserve": 1, "submit": 1, "abort": 1}


def test_finalized_successor_recovery_is_read_only_and_returns_exact_two_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, state = _written_successor_preview(tmp_path, monkeypatch)
    preview, _loaded_digest = launch.load_reviewed_successor_preview(
        path,
        reviewed_sha256=digest,
    )
    identity = launch._successor_attempt_identity(
        preview=preview,
        preview_sha256=digest,
        state=state,
        fresh_miners=_proofs(),
    )
    attempt_id = launch._attempt_id(identity)
    intent = {
        "extrinsic_hash": "0x" + "8" * 64,
        "nonce": 11,
        "era_reference_block": BLOCK,
        "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
        "version_key": VERSION_KEY,
        "wire_uids": [8, 124],
        "wire_weights": [W, W],
    }
    receipt = {
        "extrinsic_hash": intent["extrinsic_hash"],
        "block_hash": "0x" + "9" * 64,
        "block_number": BLOCK + 2,
        "version_key": VERSION_KEY,
        "wire_uids": [8, 124],
        "wire_weights": [W, W],
    }
    journal = {
        "submission_pending_id": None,
        "submission_finalized_id": attempt_id,
        "submission_finalized_lane": "authority",
        "submission_finalized_identity": identity,
        "submission_finalized_broadcast_intent": intent,
        "submission_finalized_receipt": receipt,
        "submission_finalized_reviewed_uid30_contract": "two_miner_successor",
    }
    preflight = SimpleNamespace(
        genesis_hash=FINNEY_GENESIS_HASH,
        validator_hotkey=launch.UID30_HOTKEY,
        validator_uid=launch.UID30,
        validator_permit=True,
        hotkey_to_uid={
            launch.UID30_HOTKEY: 30,
            canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY: 8,
            launch.MINER_HOTKEY: 124,
        },
        subtensor=state.preflight.subtensor,
    )
    monkeypatch.setattr(
        canonical,
        "_submission_tick_lock",
        lambda _args, *, lane: contextlib.nullcontext(),
    )
    monkeypatch.setattr(canonical, "_read_state", lambda _path: journal)
    monkeypatch.setattr(launch, "_recovery_preflight", lambda: preflight)
    monkeypatch.setattr(
        launch,
        "_finalized_readback",
        lambda **_kwargs: {"dests": [8, 124], "weights_u16": [W, W]},
    )
    later_heads = ((BLOCK + 3, "0x" + "a" * 64), (BLOCK + 4, "0x" + "b" * 64))
    monkeypatch.setattr(
        launch,
        "_verify_successor_later_finalized_heads",
        lambda **_kwargs: later_heads,
    )
    monkeypatch.setattr(
        canonical,
        "_submit_exact_sn39_extrinsic",
        lambda *_args, **_kwargs: pytest.fail("recovery must never submit"),
    )
    monkeypatch.setattr(
        canonical,
        "_finalize_common_submission",
        lambda *_args, **_kwargs: pytest.fail("already-finalized recovery must not finalize"),
    )

    recovered = launch.recover_reviewed_successor(
        preview_path=path,
        reviewed_sha256=digest,
        exclusive_writer_asserted=True,
    )

    assert recovered.status == "ALREADY_FINALIZED"
    assert recovered.attempt_id == attempt_id
    assert recovered.wire_uids == (8, 124)
    assert recovered.wire_weights == (W, W)
    assert recovered.later_finalized_heads == later_heads
