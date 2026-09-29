"""The signed pool inventory: what the round probed, available and healthy."""

from __future__ import annotations

import json
import random
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

import cathedral_thin.independent_runtime.direct_validator as runtime
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import pool_inventory as inventory
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.fleet_score import MultiComputeRound
from cathedral_thin.independent_runtime.qvl import DIRECT_VALIDATOR_QVL_DIGEST

# The subnet is deploy-time config; draw one per run.
NETUID = random.SystemRandom().randrange(1, 65_536)
NETWORK = "finney"
VALIDATOR_KEY = Keypair.create_from_seed("0x" + "11" * 32)
OTHER_KEY = Keypair.create_from_seed("0x" + "22" * 32)
MINER = "5MinerOne"
AXON = ServingAxon(19, MINER, "1.1.1.1", 8081)
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)


def _row(
    marker: str, *, paid: bool = True, ok: bool = True, **extra
) -> dict[str, object]:
    row: dict[str, object] = {
        "uid": 19,
        "hotkey": MINER,
        "endpoint": f"https://1.1.19.{marker}:8081",
        "ok": ok,
        "tee_kind": "tdx",
        "verdict": "PASS" if paid else "FAIL",
        "platform_identity_verified": paid,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "sat_units": 20 if paid else 0,
        "counted_units": 20 if paid else 0,
        "channel_id": f"channel-{marker}",
        "machine_id": f"machine-{marker}",
    }
    row.update(extra)
    return row


def _round(*rows: dict[str, object]) -> MultiComputeRound:
    paid = [row for row in rows if row["counted_units"]]
    return MultiComputeRound(
        rows=tuple(dict(row) for row in rows),
        fleet=(
            {
                "uid": 19,
                "hotkey": MINER,
                "primary": "https://1.1.1.1:8081",
                "ok": True,
                "singleton_compatibility": False,
                "candidate_count": len(rows),
                "endpoints": [row["endpoint"] for row in rows],
            },
        ),
        verified_units={MINER: sum(int(row["counted_units"]) for row in paid)}
        if paid
        else {},
        pass_count=len(paid),
        qvl_infra_count=0,
        feature_blocked=False,
        exclusions=(),
        blockers=(),
    )


def _snapshot() -> FinalizedMetagraphSnapshot:
    return FinalizedMetagraphSnapshot(
        block_number=100,
        block_hash="0x" + "a" * 64,
        validator_uid=7,
        validator_hotkey=VALIDATOR_KEY.ss58_address,
        miners=(AXON,),
        skipped_axons={"refuse_or_canary": 0, "port_zero": 0, "unusable_ip": 0},
        netuid=NETUID,
    )


ROWS = (
    _row("a"),
    _row("b", paid=False, sat_error="SatWorkError: " + "x" * 400),
    _row(
        "c",
        paid=False,
        ok=False,
        error="ConnectionRefusedError: refused",
        tee_kind=None,
        machine_id=None,
    ),
)


def _document() -> dict[str, object]:
    return inventory.build_pool_inventory(
        rows=ROWS,
        healthy_rows=ROWS[:1],
        miner_count=1,
        network=NETWORK,
        netuid=NETUID,
        block_number=100,
        block_hash="0x" + "a" * 64,
        validator_uid=7,
        validator_hotkey=VALIDATOR_KEY.ss58_address,
        generated_at=NOW,
    )


def test_each_probed_machine_is_healthy_unverified_or_unreachable():
    document = _document()
    states = {machine["endpoint"]: machine for machine in document["machines"]}
    assert states["https://1.1.19.a:8081"]["state"] == "healthy"
    assert states["https://1.1.19.a:8081"]["reason"] is None
    assert states["https://1.1.19.b:8081"]["state"] == "unverified"
    assert len(states["https://1.1.19.b:8081"]["reason"]) == inventory.MAX_REASON_CHARS
    assert states["https://1.1.19.c:8081"]["state"] == "unreachable"
    assert states["https://1.1.19.c:8081"]["reason"].startswith(
        "ConnectionRefusedError"
    )
    assert document["totals"] == {
        "miners": 1,
        "machines": 3,
        "available": 2,
        "healthy": 1,
        "assigned": 0,
    }
    assert document["assignment_source"] is None
    assert document["netuid"] == NETUID


def test_a_signed_inventory_verifies_and_any_edit_breaks_it():
    signed = inventory.sign_pool_inventory(_document(), keypair=VALIDATOR_KEY)
    assert inventory.verify_pool_inventory(json.loads(json.dumps(signed))) == signed

    edited = json.loads(json.dumps(signed))
    edited["machines"][1]["state"] = "healthy"
    edited["totals"]["healthy"] = 2
    with pytest.raises(inventory.PoolInventoryError, match="receipt root"):
        inventory.verify_pool_inventory(edited)

    lying = json.loads(json.dumps(signed))
    lying["totals"]["available"] = 3
    with pytest.raises(inventory.PoolInventoryError, match="totals"):
        inventory.verify_pool_inventory(lying)

    forged = json.loads(json.dumps(signed))
    forged["signature"]["value_base64"] = inventory.sign_pool_inventory(
        {
            **_document(),
            "validator": {"uid": 7, "hotkey": OTHER_KEY.ss58_address},
            "inventory_id": inventory._inventory_id(
                {
                    **_document(),
                    "validator": {"uid": 7, "hotkey": OTHER_KEY.ss58_address},
                }
            ),
        },
        keypair=OTHER_KEY,
    )["signature"]["value_base64"]
    with pytest.raises(inventory.PoolInventoryError, match="verification failed"):
        inventory.verify_pool_inventory(forged)


def test_only_the_named_validator_can_sign():
    with pytest.raises(inventory.PoolInventoryError, match="signer"):
        inventory.sign_pool_inventory(_document(), keypair=OTHER_KEY)


def test_a_counted_machine_must_be_one_the_round_probed():
    with pytest.raises(inventory.PoolInventoryError, match="missing"):
        inventory.build_pool_inventory(
            rows=ROWS[1:],
            healthy_rows=ROWS[:1],
            miner_count=1,
            network=NETWORK,
            netuid=NETUID,
            block_number=100,
            block_hash="0x" + "a" * 64,
            validator_uid=7,
            validator_hotkey=VALIDATOR_KEY.ss58_address,
            generated_at=NOW,
        )


def test_the_published_file_is_replaced_atomically_and_never_followed(tmp_path: Path):
    target = tmp_path / "pool-inventory.json"
    signed = inventory.sign_pool_inventory(_document(), keypair=VALIDATOR_KEY)
    inventory.write_pool_inventory(target, signed)
    assert target.stat().st_mode & 0o777 == 0o644
    assert json.loads(inventory.read_pool_inventory(target)) == signed
    assert [path.name for path in tmp_path.iterdir()] == ["pool-inventory.json"]

    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(inventory.PoolInventoryError):
        inventory.write_pool_inventory(linked, signed)
    with pytest.raises(inventory.PoolInventoryError):
        inventory.read_pool_inventory(linked)


def test_the_read_only_server_serves_only_the_inventory(tmp_path: Path):
    target = tmp_path / "pool-inventory.json"
    server = inventory.make_inventory_server(target, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(base + inventory.ROUTE, timeout=5)
        assert missing.value.code == 503
        signed = inventory.sign_pool_inventory(_document(), keypair=VALIDATOR_KEY)
        inventory.write_pool_inventory(target, signed)
        with urllib.request.urlopen(base + inventory.ROUTE, timeout=5) as response:
            assert json.loads(response.read()) == signed
        with pytest.raises(urllib.error.HTTPError) as other:
            urllib.request.urlopen(base + "/v1/other", timeout=5)
        assert other.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as posted:
            urllib.request.urlopen(
                urllib.request.Request(base + inventory.ROUTE, data=b"{}"), timeout=5
            )
        assert posted.value.code == 501
    finally:
        server.shutdown()
        server.server_close()


def test_the_verify_command_reports_valid_and_invalid_files(tmp_path: Path, capsys):
    target = tmp_path / "pool-inventory.json"
    inventory.write_pool_inventory(
        target, inventory.sign_pool_inventory(_document(), keypair=VALIDATOR_KEY)
    )
    assert runtime.main(["pool-inventory", "verify", "--inventory", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "POOL_INVENTORY_VALID"
    target.write_text("{}")
    assert runtime.main(["pool-inventory", "verify", "--inventory", str(target)]) == 1
    assert capsys.readouterr().out.startswith("POOL_INVENTORY_INVALID")


def _cycle(monkeypatch, tmp_path: Path, inventory_path: Path):
    receipt = SimpleNamespace(
        status="CONFIRMED", as_document=lambda: {"status": "CONFIRMED"}
    )
    writer = SimpleNamespace(
        recover=lambda: None,
        submit=lambda plan, **_kwargs: receipt,
        netuid=NETUID,
    )
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: _snapshot()
    )
    monkeypatch.setattr(
        runtime, "score_multicompute_round", lambda **_kwargs: _round(*ROWS)
    )
    return runtime.run_direct_cycle(
        subtensor=object(),
        keypair=VALIDATOR_KEY,
        verifier_adapter=SimpleNamespace(qvl_digest=DIRECT_VALIDATOR_QVL_DIGEST),
        writer=writer,
        report_recovery=lambda _event: pytest.fail("no recovery expected"),
        netuid=NETUID,
        pool_inventory=(inventory_path, NETWORK),
    )


def test_a_cycle_publishes_the_signed_inventory_after_its_write(
    monkeypatch, tmp_path: Path
):
    target = tmp_path / "pool-inventory.json"
    event = _cycle(monkeypatch, tmp_path, target)
    published = inventory.verify_pool_inventory(json.loads(target.read_bytes()))
    assert event["status"] == "CONFIRMED"
    assert event["pool_inventory"] == {
        "status": "PUBLISHED",
        "inventory_id": published["inventory_id"],
    }
    assert published["totals"]["healthy"] == 1
    assert event["wire_uids"] == [19]


def test_an_inventory_failure_never_changes_the_cycle(monkeypatch, tmp_path: Path):
    event = _cycle(
        monkeypatch, tmp_path, tmp_path / "missing-dir" / "pool-inventory.json"
    )
    assert event["status"] == "CONFIRMED"
    assert event["pool_inventory"] == {"status": "FAILED"}
    assert event["wire_uids"] == [19]


def _hashes(count: int) -> list[bytes]:
    return [inventory._leaf_hash(bytes([index])) for index in range(count)]


def test_merkle_root_matches_rfc6962_shape():
    import hashlib

    assert inventory.merkle_root([]) == hashlib.sha256(b"").digest()
    one = _hashes(1)
    assert inventory.merkle_root(one) == one[0] == hashlib.sha256(b"\x00\x00").digest()
    three = _hashes(3)
    left = inventory._node_hash(three[0], three[1])
    assert inventory.merkle_root(three) == inventory._node_hash(left, three[2])


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 33])
def test_every_inclusion_proof_reaches_the_root_and_only_there(size):
    hashes = _hashes(size)
    root = inventory.merkle_root(hashes)
    for index in range(size):
        proof = inventory.inclusion_proof(index, hashes)
        assert inventory.root_from_proof(hashes[index], index, size, proof) == root
        if size > 1:
            wrong = (index + 1) % size
            assert inventory.root_from_proof(hashes[wrong], index, size, proof) != root
            with pytest.raises(inventory.PoolInventoryError):
                inventory.root_from_proof(hashes[index], index, size, proof[:-1])
            with pytest.raises(inventory.PoolInventoryError):
                inventory.root_from_proof(hashes[index], index, size, proof + [root])


def _signed() -> dict[str, object]:
    return inventory.sign_pool_inventory(_document(), keypair=VALIDATOR_KEY)


def test_each_machine_gets_a_receipt_that_verifies_alone():
    signed = _signed()
    for machine in signed["machines"]:
        receipt = inventory.machine_receipt(
            signed, uid=machine["uid"], endpoint=machine["endpoint"]
        )
        standalone = json.loads(json.dumps(receipt))
        assert inventory.verify_machine_receipt(standalone)["leaf"] == machine
        assert "machines" not in standalone["header"]
    with pytest.raises(inventory.PoolInventoryError, match="no machine"):
        inventory.machine_receipt(signed, uid=19, endpoint="https://9.9.9.9:8081")


def _receipt() -> dict[str, object]:
    signed = _signed()
    machine = signed["machines"][1]
    return json.loads(
        json.dumps(
            inventory.machine_receipt(
                signed, uid=machine["uid"], endpoint=machine["endpoint"]
            )
        )
    )


@pytest.mark.parametrize(
    ("tamper", "match"),
    [
        (lambda r: r["leaf"].__setitem__("state", "healthy"), "signed root"),
        (lambda r: r["leaf"].__setitem__("reason", None), "signed root"),
        (lambda r: r.__setitem__("index", 0), "signed root"),
        (lambda r: r["proof"].__setitem__(0, "00" * 32), "signed root"),
        (lambda r: r["header"]["totals"].__setitem__("healthy", 3), "signed identity"),
        (
            lambda r: r["header"]["receipts"].__setitem__("merkle_root", "11" * 32),
            "signed identity",
        ),
        (
            lambda r: r.__setitem__("inventory_id", "sha256:" + "0" * 64),
            "signed identity",
        ),
        (lambda r: r["header"]["receipts"].__setitem__("leaves", 0), "tree"),
        (lambda r: r.__setitem__("schema", "other"), "schema"),
        (lambda r: r.pop("proof"), "fields"),
    ],
)
def test_a_tampered_receipt_is_refused(tamper, match):
    receipt = _receipt()
    tamper(receipt)
    with pytest.raises(inventory.PoolInventoryError, match=match):
        inventory.verify_machine_receipt(receipt)


def test_a_receipt_signed_by_another_key_is_refused():
    receipt = _receipt()
    other = inventory.sign_pool_inventory(
        {
            **_document(),
            "validator": {"uid": 7, "hotkey": OTHER_KEY.ss58_address},
            "inventory_id": inventory._inventory_id(
                {
                    **_document(),
                    "validator": {"uid": 7, "hotkey": OTHER_KEY.ss58_address},
                }
            ),
        },
        keypair=OTHER_KEY,
    )
    receipt["signature"] = other["signature"]
    with pytest.raises(inventory.PoolInventoryError, match="verification failed"):
        inventory.verify_machine_receipt(receipt)


def test_the_server_returns_a_machine_receipt(tmp_path: Path):
    target = tmp_path / "pool-inventory.json"
    inventory.write_pool_inventory(target, _signed())
    server = inventory.make_inventory_server(target, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}{inventory.RECEIPT_ROUTE}"
    try:
        from urllib.parse import urlencode

        query = urlencode({"uid": 19, "endpoint": "https://1.1.19.b:8081"})
        with urllib.request.urlopen(f"{base}?{query}", timeout=5) as response:
            verified = inventory.verify_machine_receipt(json.loads(response.read()))
        assert verified["leaf"]["state"] == "unverified"
        for bad in ("uid=19", "uid=x&endpoint=e", "uid=19&endpoint=https://9.9.9.9:1"):
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(f"{base}?{bad}", timeout=5)
            assert refused.value.code in {400, 404}
    finally:
        server.shutdown()
        server.server_close()


def test_the_receipt_commands_print_and_verify(tmp_path: Path, capsys):
    target = tmp_path / "pool-inventory.json"
    inventory.write_pool_inventory(target, _signed())
    argv = ["pool-inventory", "receipt", "--inventory", str(target), "--uid", "19"]
    assert runtime.main([*argv, "--endpoint", "https://1.1.19.a:8081"]) == 0
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(capsys.readouterr().out)
    assert (
        runtime.main(
            ["pool-inventory", "verify-receipt", "--receipt", str(receipt_file)]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "MACHINE_RECEIPT_VALID"
    receipt_file.write_text(
        receipt_file.read_text().replace('"healthy"', '"unverified"', 1)
    )
    assert (
        runtime.main(
            ["pool-inventory", "verify-receipt", "--receipt", str(receipt_file)]
        )
        == 1
    )
    assert capsys.readouterr().out.startswith("MACHINE_RECEIPT_INVALID")
    assert runtime.main([*argv, "--endpoint", "https://9.9.9.9:8081"]) == 1
