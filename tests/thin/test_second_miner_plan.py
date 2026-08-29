from __future__ import annotations

import ast
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin import second_miner_plan as plan
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH


def _neuron(
    uid: int,
    hotkey: str,
    *,
    coldkey: str = plan.CATHEDRAL_COLDKEY,
    permit: bool = False,
    ip: str | None = None,
    port: int = 0,
    protocol: int = 0,
) -> plan.Neuron:
    return plan.Neuron(
        uid=uid,
        hotkey=hotkey,
        coldkey=coldkey,
        validator_permit=permit,
        last_update=800,
        ip=ip,
        port=port,
        protocol=protocol,
        serving=ip is not None and port > 0,
    )


def _snapshot(*, second: plan.Neuron | None = None) -> plan.FinalizedSnapshot:
    neurons = [
        _neuron(plan.UID30, plan.UID30_HOTKEY, permit=True),
        _neuron(
            124,
            plan.PRIMARY_MINER_HOTKEY,
            ip="34.48.111.10",
            port=plan.HTTPS_PORT,
            protocol=plan.HTTPS_PROTOCOL,
        ),
    ]
    if second is not None:
        neurons.append(second)
    return plan.FinalizedSnapshot(
        block_number=8_946_847,
        block_hash="0x" + "a" * 64,
        genesis_hash=FINNEY_GENESIS_HASH,
        neurons=tuple(neurons),
        uid30_weights=((124, plan.W),),
    )


def test_contract_pins_dedicated_second_hotkey() -> None:
    assert plan.NETWORK == "finney"
    assert (plan.NETUID, plan.MECID, plan.UID30) == (39, 0, 30)
    assert plan.SECOND_MINER_WALLET_HOTKEY == "serge_sat_test_2"
    assert plan.SECOND_MINER_HOTKEY == (
        "5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq"
    )


def test_equal_wire_is_order_independent_and_has_no_burn_row() -> None:
    expected = ([124, 200], [plan.W, plan.W])
    assert plan.equal_wire(124, 200) == expected
    assert plan.equal_wire(200, 124) == expected
    assert plan.UID30 not in expected[0]


@pytest.mark.parametrize("uids", [(124, 124), (plan.UID30, 124), (124, plan.UID30)])
def test_equal_wire_rejects_colliding_or_validator_uids(uids: tuple[int, int]) -> None:
    with pytest.raises(plan.SecondMinerPlanError, match="distinct non-validator"):
        plan.equal_wire(*uids)


def test_unregistered_second_miner_is_blocked_without_a_wire_row() -> None:
    document = plan.build_plan(_snapshot())

    assert document["status"] == plan.STATUS_UNREGISTERED
    assert document["authorized_for_chain_write"] is False
    assert document["second_miner"]["uid"] is None
    assert document["requested_outcome"]["wire"] is None
    assert document["requested_outcome"]["burn_destination"] is None
    assert document["requested_outcome"]["burn_weight"] == 0
    assert document["current_uid30_storage"] == [[124, plan.W]]


def test_registered_second_miner_without_https_axon_is_blocked() -> None:
    document = plan.build_plan(_snapshot(second=_neuron(200, plan.SECOND_MINER_HOTKEY)))

    assert document["status"] == plan.STATUS_AXON
    assert document["second_miner"]["uid"] == 200
    assert document["requested_outcome"]["wire"] == {
        "dests": [124, 200],
        "weights_u16": [plan.W, plan.W],
        "expected_storage": [[124, plan.W], [200, plan.W]],
    }


def test_registered_https_second_miner_still_requires_fresh_proofs() -> None:
    document = plan.build_plan(
        _snapshot(
            second=_neuron(
                200,
                plan.SECOND_MINER_HOTKEY,
                ip="34.46.19.69",
                port=plan.HTTPS_PORT,
                protocol=plan.HTTPS_PROTOCOL,
            )
        )
    )

    assert document["status"] == plan.STATUS_PROOF
    assert document["authorized_for_chain_write"] is False
    assert document["second_miner"]["axon"] == {
        "ip": "34.46.19.69",
        "port": plan.HTTPS_PORT,
        "protocol": plan.HTTPS_PROTOCOL,
        "serving": True,
    }
    assert any("QVL PASS" in blocker for blocker in document["blockers"])


def test_identity_and_chain_pin_failures_are_refused() -> None:
    wrong_genesis = _snapshot()
    wrong_genesis = plan.FinalizedSnapshot(
        **{**wrong_genesis.__dict__, "genesis_hash": "0x" + "b" * 64}
    )
    with pytest.raises(plan.SecondMinerPlanError, match="Finney genesis"):
        plan.build_plan(wrong_genesis)

    no_permit = _snapshot()
    no_permit = plan.FinalizedSnapshot(
        **{
            **no_permit.__dict__,
            "neurons": (
                _neuron(plan.UID30, plan.UID30_HOTKEY, permit=False),
                _neuron(124, plan.PRIMARY_MINER_HOTKEY),
            ),
        }
    )
    with pytest.raises(plan.SecondMinerPlanError, match="validator permit"):
        plan.build_plan(no_permit)

    foreign_second = _neuron(
        200,
        plan.SECOND_MINER_HOTKEY,
        coldkey=plan.UID30_HOTKEY,
    )
    with pytest.raises(plan.SecondMinerPlanError, match="Cathedral coldkey"):
        plan.build_plan(_snapshot(second=foreign_second))


def test_finalized_reader_uses_only_pinned_public_chain_queries() -> None:
    finalized_hash = "0x" + "c" * 64
    query_calls: list[dict[str, object]] = []
    metagraph_calls: list[tuple[int, bool, int, int]] = []

    class Substrate:
        def get_block_hash(self, block: int) -> str:
            if block == 0:
                return FINNEY_GENESIS_HASH
            assert block == 8_946_847
            return finalized_hash

        def get_chain_finalised_head(self) -> str:
            return finalized_hash

        def get_block_number(self, block_hash: str) -> int:
            assert block_hash == finalized_hash
            return 8_946_847

        def query(self, **kwargs):
            query_calls.append(kwargs)
            return SimpleNamespace(value=[[124, plan.W]])

    class Subtensor:
        substrate = Substrate()

        def metagraph(self, netuid: int, *, lite: bool, block: int, mechid: int):
            metagraph_calls.append((netuid, lite, block, mechid))
            axon = SimpleNamespace(ip="34.48.111.10", port=8081, protocol=4)
            return SimpleNamespace(
                block=block,
                uids=[plan.UID30, 124],
                hotkeys=[plan.UID30_HOTKEY, plan.PRIMARY_MINER_HOTKEY],
                coldkeys=[plan.CATHEDRAL_COLDKEY, plan.CATHEDRAL_COLDKEY],
                validator_permit=[True, False],
                last_update=[800, 801],
                axons=[SimpleNamespace(ip="0.0.0.0", port=0, protocol=0), axon],
            )

    snapshot = plan.read_finalized_snapshot(
        subtensor_factory=lambda *, network: (
            Subtensor() if network == plan.NETWORK else pytest.fail(network)
        )
    )

    assert snapshot.block_hash == finalized_hash
    assert snapshot.uid30_weights == ((124, plan.W),)
    assert metagraph_calls == [(plan.NETUID, True, 8_946_847, plan.MECID)]
    assert query_calls == [
        {
            "module": "SubtensorModule",
            "storage_function": "Weights",
            "params": [plan.NETUID, plan.UID30],
            "block_hash": finalized_hash,
        }
    ]


def test_finalized_reader_rejects_mixed_head_metagraph() -> None:
    finalized_hash = "0x" + "c" * 64

    class Substrate:
        def get_block_hash(self, block: int) -> str:
            if block == 0:
                return FINNEY_GENESIS_HASH
            assert block == 8_946_847
            return finalized_hash

        def get_chain_finalised_head(self) -> str:
            return finalized_hash

        def get_block_number(self, block_hash: str) -> int:
            assert block_hash == finalized_hash
            return 8_946_847

    class Subtensor:
        substrate = Substrate()

        def metagraph(self, *_args, **_kwargs):
            return SimpleNamespace(block=8_946_846)

    with pytest.raises(plan.SecondMinerPlanError, match="requested snapshot block"):
        plan.read_finalized_snapshot(
            subtensor_factory=lambda *, network: (
                Subtensor() if network == plan.NETWORK else pytest.fail(network)
            )
        )


def test_snapshot_reader_rejects_mismatched_block_number_and_hash() -> None:
    requested_hash = "0x" + "c" * 64
    canonical_hash = "0x" + "d" * 64

    substrate = SimpleNamespace(
        get_block_hash=lambda block: (
            FINNEY_GENESIS_HASH if block == 0 else canonical_hash
        )
    )
    subtensor = SimpleNamespace(substrate=substrate)

    with pytest.raises(
        plan.SecondMinerPlanError,
        match="block number and hash do not match",
    ):
        plan.read_snapshot_at(
            subtensor=subtensor,
            block_number=8_946_847,
            block_hash=requested_hash,
            genesis_hash=FINNEY_GENESIS_HASH,
        )


def test_ready_status_requires_primary_and_second_https_axons() -> None:
    snapshot = _snapshot(
        second=_neuron(
            200,
            plan.SECOND_MINER_HOTKEY,
            ip="34.46.19.69",
            port=plan.HTTPS_PORT,
            protocol=plan.HTTPS_PROTOCOL,
        )
    )
    primary = snapshot.neurons[1]
    invalid_primary = plan.Neuron(**{**primary.__dict__, "port": 80, "serving": True})
    snapshot = plan.FinalizedSnapshot(
        **{
            **snapshot.__dict__,
            "neurons": (snapshot.neurons[0], invalid_primary, snapshot.neurons[2]),
        }
    )

    document = plan.build_plan(snapshot)

    assert document["status"] == plan.STATUS_AXON
    assert any("primary miner" in blocker for blocker in document["blockers"])


def test_plan_writer_is_owner_only_hashed_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "private" / "plan.json"
    document = plan.build_plan(_snapshot())

    written, digest_path, digest = plan.write_plan(output, document)

    body = written.read_bytes()
    assert hashlib.sha256(body).hexdigest() == digest
    assert json.loads(body) == document
    assert digest_path.read_text(encoding="ascii") == f"{digest}  plan.json\n"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(digest_path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        plan.write_plan(output, document)
    assert written.read_bytes() == body


def test_plan_writer_refuses_a_group_accessible_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o750)
    parent.chmod(0o750)
    with pytest.raises(plan.SecondMinerPlanError, match="owner-controlled"):
        plan.write_plan(parent / "plan.json", plan.build_plan(_snapshot()))


def test_cli_writes_no_authority_summary(tmp_path: Path, capsys) -> None:
    output = tmp_path / "plan.json"

    assert (
        plan.main(
            ["preview", "--output", str(output)],
            reader=lambda: _snapshot(),
        )
        == 0
    )

    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == plan.STATUS_UNREGISTERED
    assert summary["authorized_for_chain_write"] is False
    assert output.exists()


def test_module_has_no_chain_mutation_call_site() -> None:
    source = Path(plan.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    prohibited = {
        "compose_call",
        "register",
        "serve_axon",
        "set_mechanism_weights",
        "submit_extrinsic",
    }
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
    assert calls.isdisjoint(prohibited)
