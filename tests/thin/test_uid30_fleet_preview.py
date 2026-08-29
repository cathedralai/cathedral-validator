from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin import uid30_fleet_preview as preview
from cathedral_thin.independent.compute import machine_id_from_stable_platform_id
from cathedral_thin.independent.constants import W
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.fleet_score import MultiComputeRound
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST
from cathedral_thin.independent_runtime.validator_request import FleetDiscovery
from cathedral_thin.uid30_state import MINER_HOTKEY, UID30, UID30_HOTKEY

OTHER_UID = 8
MINER_UID = 124
OTHER_HOTKEY = "5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq"
ROOT = "https://1.1.1.1:8081"
SECOND = "https://8.8.8.8:8081"
EVIDENCE_HASH = "0x" + "a1" * 32
FRESH_HASH = "0x" + "b2" * 32
GENESIS = "0x" + "c3" * 32
OWNER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
CURRENT_WEIGHTS = ((OTHER_UID, W), (MINER_UID, W))
CURRENT_AXONS = (
    ServingAxon(OTHER_UID, OTHER_HOTKEY, "8.8.8.8", 8081),
    ServingAxon(MINER_UID, MINER_HOTKEY, "1.1.1.1", 8081),
)


class _Substrate:
    def __init__(self, *, fresh_hash: str = FRESH_HASH) -> None:
        self.hashes = {100: EVIDENCE_HASH, 101: fresh_hash}

    def get_block_hash(self, block: int) -> str:
        return self.hashes[block]


def _state(*, block: int, block_hash: str, substrate: _Substrate):
    keypair = SimpleNamespace(
        ss58_address=UID30_HOTKEY,
        sign=lambda _body: b"s" * 64,
    )
    preflight = SimpleNamespace(
        wallet=SimpleNamespace(hotkey=keypair),
        subtensor=SimpleNamespace(substrate=substrate),
        hotkey_to_uid={MINER_HOTKEY: MINER_UID, OTHER_HOTKEY: OTHER_UID},
    )
    return SimpleNamespace(
        preflight=preflight,
        block_number=block,
        block_hash=block_hash,
        genesis_hash=GENESIS,
        subnet_owner_hotkey=OWNER,
        validator_hotkey=UID30_HOTKEY,
        validator_uid=UID30,
        miner_hotkey=MINER_HOTKEY,
        miner_uid=MINER_UID,
        serving_axon=CURRENT_AXONS[1],
    )


def _states(*, fresh_hash: str = FRESH_HASH):
    substrate = _Substrate(fresh_hash=fresh_hash)
    return (
        _state(block=100, block_hash=EVIDENCE_HASH, substrate=substrate),
        _state(block=101, block_hash=FRESH_HASH, substrate=substrate),
    )


def _machine(endpoint: str, marker: str) -> dict:
    stable = "tdx-platform-sha256:" + marker * 64
    return {
        "uid": MINER_UID,
        "hotkey": MINER_HOTKEY,
        "endpoint": endpoint,
        "verdict": "PASS",
        "platform_identity_verified": True,
        "stable_platform_id": stable,
        "machine_id": machine_id_from_stable_platform_id(stable),
        "channel_id": hashlib.sha256(("channel:" + marker).encode()).hexdigest(),
        "quote_sha256": hashlib.sha256(("quote:" + marker).encode()).hexdigest(),
        "report_data_sha256": hashlib.sha256(("report:" + marker).encode()).hexdigest(),
        "sat_units": 20,
        "counted_units": 20,
        "sat_rule": SAT_WORK_UNIT_RULE,
    }


def _round(**changes) -> MultiComputeRound:
    values = {
        "rows": (
            {
                "uid": OTHER_UID,
                "hotkey": OTHER_HOTKEY,
                "endpoint": SECOND,
                "counted_units": 0,
                "error": "assigned hotkey changed after consolidation",
            },
            _machine(ROOT, "a"),
            _machine(SECOND, "b"),
        ),
        "fleet": (
            {
                "uid": OTHER_UID,
                "hotkey": OTHER_HOTKEY,
                "primary": SECOND,
                "ok": False,
                "error": "assigned hotkey changed after consolidation",
            },
            {
                "uid": MINER_UID,
                "hotkey": MINER_HOTKEY,
                "primary": ROOT,
                "ok": True,
                "singleton_compatibility": False,
                "candidate_count": 2,
                "endpoints": [ROOT, SECOND],
            },
        ),
        "verified_units": {MINER_HOTKEY: 40},
        "pass_count": 2,
        "qvl_infra_count": 0,
        "feature_blocked": False,
        "exclusions": ("fleet uid 8: assigned hotkey changed after consolidation",),
        "blockers": (),
    }
    values.update(changes)
    return MultiComputeRound(**values)


def _document(**changes):
    evidence, fresh = _states()
    values = {
        "evidence_state": evidence,
        "fresh_state": fresh,
        "evidence_axons": CURRENT_AXONS,
        "fresh_axons": CURRENT_AXONS,
        "round_result": _round(),
        "refreshed_endpoints": (ROOT, SECOND),
        "fleet_recheck_error": None,
        "current_weights": CURRENT_WEIGHTS,
        "qvl_digest": LAUNCH_QVL_DIGEST,
    }
    values.update(changes)
    return preview.build_preview_document(**values)


def _contains_float(value) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_contains_float(row) for row in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_float(row) for row in value)
    return False


def test_current_two_uid_row_is_evidence_and_target_is_uid124_singleton():
    document = _document()
    assert document["status"] == preview.STATUS
    assert document["current"]["uid30_storage"] == [
        [OTHER_UID, W],
        [MINER_UID, W],
    ]
    assert document["current"]["weighted_serving_uids"] == [
        {
            "uid": OTHER_UID,
            "hotkey": OTHER_HOTKEY,
            "endpoint": SECOND,
            "stored_weight": W,
            "verified_work_units": 0,
        },
        {
            "uid": MINER_UID,
            "hotkey": MINER_HOTKEY,
            "endpoint": ROOT,
            "stored_weight": W,
            "verified_work_units": 40,
        },
    ]
    target = document["consolidation_target"]
    assert target["hotkey"] == MINER_HOTKEY
    assert target["uid"] == MINER_UID
    assert target["raw_uid_units"] == 40
    assert target["proof_complete"] is True
    assert target["non_authorizing_target_wire_row"] == [[MINER_UID, W]]
    assert len(target["machines"]) == 2
    assert document["current"]["burn_weight"] == 0
    assert document["burn_destination"] is None
    assert document["burn_weight"] == 0
    assert document["changes_current_chain_row"] is True
    assert document["authorized_for_chain_write"] is False
    assert document["chain_write_submitted"] is False
    assert document["weight_signed"] is False
    assert document["weight_submitted"] is False
    assert _contains_float(document) is False


@pytest.mark.parametrize(
    "change,message",
    [
        ({"refreshed_endpoints": (SECOND, ROOT)}, "endpoint list changed"),
        ({"fleet_recheck_error": "HTTP 401"}, "recheck failed"),
        (
            {"round_result": _round(verified_units={MINER_HOTKEY: 20})},
            "lacks 40",
        ),
    ],
)
def test_incomplete_same_uid_fleet_writes_not_proven_artifact(change, message):
    document = _document(**change)
    assert document["status"] == preview.NOT_PROVEN_STATUS
    assert document["consolidation_target"]["proof_complete"] is False
    assert any(
        message in reason
        for reason in document["consolidation_target"]["not_proven_reasons"]
    )
    assert document["consolidation_target"]["non_authorizing_target_wire_row"] == [
        [MINER_UID, W]
    ]
    assert document["authorized_for_chain_write"] is False


def test_duplicate_platform_or_wrong_target_uid_is_not_proven():
    duplicate = _machine(SECOND, "a")
    duplicate["channel_id"] = "b" * 64
    duplicate["quote_sha256"] = "c" * 64
    duplicate["report_data_sha256"] = "d" * 64
    document = _document(
        round_result=_round(
            rows=(
                _round().rows[0],
                _machine(ROOT, "a"),
                duplicate,
            )
        )
    )
    assert document["status"] == preview.NOT_PROVEN_STATUS
    assert (
        "distinct stable_platform"
        in document["consolidation_target"]["not_proven_reasons"][0]
    )

    wrong = _machine(ROOT, "a")
    wrong["uid"] = MINER_UID + 1
    document = _document(
        round_result=_round(rows=(_round().rows[0], wrong, _machine(SECOND, "b")))
    )
    assert document["status"] == preview.NOT_PROVEN_STATUS


def test_qvl_chain_or_weighted_axon_drift_refuses_without_artifact():
    with pytest.raises(preview.UID30FleetPreviewError, match="pinned launch QVL"):
        _document(qvl_digest="0" * 64)
    with pytest.raises(preview.UID30FleetPreviewError, match="serving axon changed"):
        _document(fresh_axons=tuple(reversed(CURRENT_AXONS)))
    evidence, fresh = _states(fresh_hash="0x" + "ff" * 32)
    with pytest.raises(preview.UID30FleetPreviewError, match="not canonical"):
        _document(evidence_state=evidence, fresh_state=fresh)


def test_weighted_axon_reader_uses_raw_metagraph_dicts_and_exact_protocol():
    evidence, _fresh = _states()
    hotkeys = [OWNER] * (MINER_UID + 1)
    hotkeys[OTHER_UID] = OTHER_HOTKEY
    hotkeys[MINER_UID] = MINER_HOTKEY
    empty = {"ip_type": 4, "ip": 0, "port": 0, "protocol": 0}
    axons = [dict(empty) for _ in hotkeys]
    axons[OTHER_UID] = {
        "ip_type": 4,
        "ip": int.from_bytes(bytes([8, 8, 8, 8]), "big"),
        "port": 8081,
        "protocol": 4,
    }
    axons[MINER_UID] = {
        "ip_type": 4,
        "ip": int.from_bytes(bytes([1, 1, 1, 1]), "big"),
        "port": 8081,
        "protocol": 4,
    }
    info = SimpleNamespace(block=100, hotkeys=hotkeys, axons=axons)
    evidence.preflight.subtensor.get_metagraph_info = lambda *_args, **_kwargs: info
    assert (
        preview.read_weighted_serving_axons(evidence, CURRENT_WEIGHTS) == CURRENT_AXONS
    )
    axons[MINER_UID]["protocol"] = 0
    with pytest.raises(preview.UID30FleetPreviewError, match="protocol 4"):
        preview.read_weighted_serving_axons(evidence, CURRENT_WEIGHTS)


def test_collect_rechecks_chain_fleet_and_current_row(monkeypatch):
    evidence, fresh = _states()
    states = iter((evidence, fresh))
    calls: list[str] = []

    class _Qvl:
        digest = LAUNCH_QVL_DIGEST

        def verify(self, quote, *, expected_report_data):
            del quote, expected_report_data
            raise AssertionError("scorer is stubbed")

    monkeypatch.setattr(
        preview,
        "read_uid30_chain_state",
        lambda **_kwargs: next(states),
    )
    monkeypatch.setattr(preview, "load_verifier", lambda _path: _Qvl())
    monkeypatch.setattr(
        preview,
        "read_current_uid30_weights",
        lambda _state: calls.append("weights") or CURRENT_WEIGHTS,
    )
    monkeypatch.setattr(
        preview,
        "read_weighted_serving_axons",
        lambda _state, _weights: calls.append("axons") or CURRENT_AXONS,
    )
    monkeypatch.setattr(
        preview,
        "score_multicompute_round",
        lambda **_kwargs: calls.append("score") or _round(),
    )

    def fleet(**kwargs):
        calls.append("fleet-recheck")
        assert kwargs["primary_origin"] == ROOT
        assert kwargs["worker_hotkey"] == MINER_HOTKEY
        assert kwargs["transport"].expected_spki == bytes.fromhex(
            _machine(ROOT, "a")["channel_id"]
        )
        return FleetDiscovery(MINER_HOTKEY, (ROOT, SECOND), False)

    monkeypatch.setattr(preview, "fetch_worker_fleet", fleet)
    document = preview.collect_preview("/reviewed/qvl")
    assert calls == [
        "weights",
        "axons",
        "score",
        "weights",
        "axons",
        "fleet-recheck",
    ]
    assert document["status"] == preview.STATUS
    assert document["current"]["uid30_storage"] == [
        [OTHER_UID, W],
        [MINER_UID, W],
    ]


def test_preview_cli_has_no_writer_surface():
    option_strings = {
        option
        for action in preview._parser()._actions
        for option in action.option_strings
    }
    assert option_strings == {"-h", "--help", "--qvl", "--output"}
    assert not any(
        name.startswith(("submit", "recover", "confirm")) for name in dir(preview)
    )
    source = Path(preview.__file__).read_text(encoding="utf-8")
    assert "independent_runtime.run" not in source
    assert "uid30_launch" not in source
    for forbidden in (
        "get_account_nonce",
        "create_signed_extrinsic",
        "submit_extrinsic",
        "_submit_exact_sn39_extrinsic",
        "submission_journal",
    ):
        assert forbidden not in source


def test_uid30_preview_import_graph_does_not_load_repo_chain_writers():
    forbidden = {
        "cathedral_thin.independent.canary",
        "cathedral_thin.independent.journal",
        "cathedral_thin.independent.submit",
        "cathedral_thin.independent_runtime.chain",
        "cathedral_thin.independent_runtime.run",
        "cathedral_thin.independent_runtime.workers",
        "cathedral_thin.uid30_launch",
        "scaffold.validator_thin",
    }
    script = (
        "import json,sys; import cathedral_thin.uid30_fleet_preview; "
        f"print(json.dumps(sorted(set(sys.modules) & {forbidden!r})))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == []


def test_artifact_is_owner_only_create_once_and_digest_bound(tmp_path):
    output = tmp_path / "uid30-fleet.json"
    path, digest_path, digest = preview.write_preview(_document(), output)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert digest_path.read_text(encoding="ascii") == f"{digest}  {output.name}\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(digest_path.stat().st_mode) == 0o600
    before = (path.read_bytes(), digest_path.read_bytes())
    with pytest.raises(FileExistsError):
        preview.write_preview(_document(), output)
    assert (path.read_bytes(), digest_path.read_bytes()) == before


def test_not_proven_cli_writes_artifact_but_exits_two(monkeypatch, tmp_path, capsys):
    document = _document(fleet_recheck_error="HTTP 401")
    monkeypatch.setattr(preview, "collect_preview", lambda _qvl: document)
    output = tmp_path / "preview.json"
    code = preview.main(["--qvl", "/qvl", "--output", str(output)])
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == preview.NOT_PROVEN_STATUS
    assert report["authorized_for_chain_write"] is False
    assert report["chain_write_submitted"] is False
    assert json.loads(output.read_text())["status"] == preview.NOT_PROVEN_STATUS
