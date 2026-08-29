from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import numpy as np

from cathedral_thin.independent.constants import (
    FINNEY_GENESIS_HASH,
    UID30_VALIDATOR_HOTKEY,
)
from cathedral_thin.independent_runtime import fleet_preview
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.fleet_score import MultiComputeRound

ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
BOB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
BLOCK_HASH = "0x" + "11" * 32
GENESIS_HASH = "0x" + "22" * 32


def _snapshot() -> fleet_preview.FinalizedFleetSnapshot:
    return fleet_preview.FinalizedFleetSnapshot(
        keypair=SimpleNamespace(
            ss58_address=UID30_VALIDATOR_HOTKEY, sign=lambda _body: b"s" * 64
        ),
        block_number=123,
        block_hash=BLOCK_HASH,
        genesis_hash=GENESIS_HASH,
        validator_uid=30,
        validator_hotkey=UID30_VALIDATOR_HOTKEY,
        uid_to_hotkey={8: ALICE, 124: BOB, 30: UID30_VALIDATOR_HOTKEY},
        hotkey_to_uid={ALICE: 8, BOB: 124, UID30_VALIDATOR_HOTKEY: 30},
        axons=(
            ServingAxon(8, ALICE, "1.1.1.1", 8081),
            ServingAxon(124, BOB, "8.8.8.8", 8081),
        ),
        skipped={"refuse_or_canary": 1},
    )


def _round(**changes) -> MultiComputeRound:
    values = {
        "rows": (),
        "fleet": (),
        "verified_units": {ALICE: 20, BOB: 40},
        "pass_count": 3,
        "qvl_infra_count": 0,
        "feature_blocked": False,
        "exclusions": ("one invalid candidate was excluded",),
        "blockers": (),
    }
    values.update(changes)
    return MultiComputeRound(**values)


def test_generic_preview_aggregates_before_normalization_and_has_no_authority():
    document = fleet_preview.build_preview_document(
        snapshot=_snapshot(), round_result=_round(), qvl_digest="a" * 64
    )
    assert document["status"] == fleet_preview.STATUS
    assert document["raw_uid_units"] == [
        {"uid": 8, "hotkey": ALICE, "raw_uid_units": 20},
        {"uid": 124, "hotkey": BOB, "raw_uid_units": 40},
    ]
    assert document["non_authorizing_normalized_row"] == [
        [8, 32768],
        [124, 65535],
    ]
    assert document["exclusions"] == ["one invalid candidate was excluded"]
    assert document["blockers"] == []
    assert document["authorized_for_chain_write"] is False
    assert document["chain_write_submitted"] is False
    assert document["weight_signed"] is False
    assert document["weight_submitted"] is False


def test_generic_finalized_reader_binds_uid30_and_serving_axons(monkeypatch):
    class Substrate:
        def get_chain_finalised_head(self):
            return BLOCK_HASH

        def get_block_number(self, block_hash):
            assert block_hash == BLOCK_HASH
            return 123

        def get_block_hash(self, block):
            return FINNEY_GENESIS_HASH if block == 0 else BLOCK_HASH

    hotkeys = [f"hotkey-{uid}" for uid in range(125)]
    hotkeys[30] = UID30_VALIDATOR_HOTKEY
    hotkeys[8] = ALICE
    hotkeys[124] = BOB
    axons = [SimpleNamespace(ip="0.0.0.0", port=0, is_serving=False) for _ in hotkeys]
    axons[8] = SimpleNamespace(ip="1.1.1.1", port=8081, is_serving=True)
    axons[124] = SimpleNamespace(ip="8.8.8.8", port=8081, is_serving=True)
    permits = [False] * len(hotkeys)
    permits[30] = np.bool_(True)
    metagraph = SimpleNamespace(
        block=123,
        uids=np.arange(len(hotkeys), dtype=np.int64),
        hotkeys=hotkeys,
        axons=axons,
        validator_permit=permits,
    )
    subtensor = SimpleNamespace(
        substrate=Substrate(),
        metagraph=lambda netuid, *, block: metagraph,
    )
    keypair = SimpleNamespace(
        ss58_address=UID30_VALIDATOR_HOTKEY, sign=lambda _body: b"s" * 64
    )
    monkeypatch.setattr(
        fleet_preview,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=keypair),
    )
    monkeypatch.setattr(
        fleet_preview, "make_subtensor", lambda *_args, **_kwargs: subtensor
    )
    snapshot = fleet_preview.read_finalized_snapshot(
        wallet_name="cathedral", wallet_hotkey="default", wallet_path=None
    )
    assert snapshot.validator_uid == 30
    assert snapshot.block_hash == BLOCK_HASH
    assert snapshot.axons == (
        ServingAxon(8, ALICE, "1.1.1.1", 8081),
        ServingAxon(124, BOB, "8.8.8.8", 8081),
    )


@pytest.mark.parametrize(
    "round_result",
    (
        _round(verified_units={}),
        _round(feature_blocked=True),
        _round(qvl_infra_count=1),
        _round(blockers=("whole-round failure",)),
    ),
)
def test_whole_preview_failure_is_not_proven(round_result):
    document = fleet_preview.build_preview_document(
        snapshot=_snapshot(), round_result=round_result, qvl_digest="a" * 64
    )
    assert document["status"] == fleet_preview.NOT_PROVEN_STATUS
    assert document["blockers"]
    assert document["authorized_for_chain_write"] is False


def test_preview_parser_has_only_read_and_local_output_options():
    option_strings = {
        option
        for action in fleet_preview._parser()._actions
        for option in action.option_strings
    }
    assert option_strings == {
        "-h",
        "--help",
        "--output",
        "--qvl",
        "--wallet-hotkey",
        "--wallet-name",
        "--wallet-path",
    }
    with pytest.raises(SystemExit):
        fleet_preview._parser().parse_args(
            ["--qvl", "/qvl", "--output", "/tmp/out", "--rent"]
        )


def test_preview_import_graph_does_not_load_repo_chain_writers():
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
        "import json,sys; "
        "import cathedral_thin.independent_runtime.fleet_preview; "
        f"print(json.dumps(sorted(set(sys.modules) & {forbidden!r})))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == []


def test_generic_cli_writes_create_once_artifact_and_never_exposes_writer_flags(
    monkeypatch, tmp_path, capsys
):
    document = fleet_preview.build_preview_document(
        snapshot=_snapshot(), round_result=_round(), qvl_digest="a" * 64
    )
    monkeypatch.setattr(fleet_preview, "collect_preview", lambda _options: document)
    output = tmp_path / "generic.json"
    code = fleet_preview.main(["--qvl", "/qvl", "--output", str(output)])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["status"] == fleet_preview.STATUS
    assert report["authorized_for_chain_write"] is False
    assert report["chain_write_submitted"] is False
    assert json.loads(output.read_text())["status"] == fleet_preview.STATUS
    code = fleet_preview.main(["--qvl", "/qvl", "--output", str(output)])
    refusal = json.loads(capsys.readouterr().err)
    assert code == 2
    assert refusal["status"] == "REFUSED_NO_CHAIN_WRITE"


def test_packaged_generic_preview_is_not_the_mixed_live_console():
    source = (Path(__file__).parents[2] / "pyproject.toml").read_text()
    assert (
        'cathedral-multicompute-preview = "cathedral_thin.independent_runtime.fleet_preview:main"'
        in source
    )
    run_source = (
        Path(__file__).parents[2] / "cathedral_thin/independent_runtime/run.py"
    ).read_text()
    assert "--multicompute" not in run_source
