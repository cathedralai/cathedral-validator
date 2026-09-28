"""A validator's own capacity inventory (capacity_inventory.py)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from cathedral_thin.independent_runtime import capacity_inventory as inv

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def _row(box_id="box-1", verdict="ACCEPTED", **changes):
    row = {
        "box_id": box_id,
        "miner_hotkey": "hk-a",
        "uid": 3,
        "kind": "bare_metal",
        "tee_kind": None,
        "hardware_id_kind": "probe_fingerprint",
        "hardware_id": "f0" * 32,
        "vcpus": 8,
        "memory_gib": 32,
        "value": 224_000,
        "recheck": "off",
        "verdict": verdict,
    }
    if verdict != "ACCEPTED":
        row["reason"] = "a sampled challenge lane does not recompute"
    row.update(changes)
    return row


def _cycle(previous, rows, round_=7, minutes=0, netuid=94):
    return inv.update_inventory(
        previous,
        rows,
        netuid=netuid,
        round_=round_,
        now=NOW + timedelta(minutes=minutes),
    )


def test_boxes_are_healthy_unhealthy_or_missing_by_what_this_validator_saw() -> None:
    first = _cycle(
        None,
        [_row(), _row("box-2", verdict="REFUSED", kind="tee", tee_kind="tdx", uid=5)],
    )
    assert first["boxes"]["box-2"]["tee_kind"] == "tdx"
    assert first["boxes"]["box-1"]["tee_kind"] is None
    assert first["boxes"]["box-1"]["status"] == inv.HEALTHY
    assert first["boxes"]["box-1"]["streak"] == 1
    assert first["boxes"]["box-2"]["status"] == inv.UNHEALTHY
    assert (
        first["boxes"]["box-2"]["reason"]
        == "a sampled challenge lane does not recompute"
    )
    second = _cycle(first, [_row()], round_=8, minutes=25)
    assert second["boxes"]["box-1"]["streak"] == 2
    assert second["boxes"]["box-1"]["first_seen"] == "2026-09-28T12:00:00Z"
    assert second["boxes"]["box-1"]["last_seen"] == "2026-09-28T12:25:00Z"
    assert second["boxes"]["box-2"]["status"] == inv.MISSING
    assert second["boxes"]["box-2"]["missed_cycles"] == 1
    back = _cycle(second, [_row("box-2", kind="tee", uid=5)], round_=9, minutes=50)
    assert back["boxes"]["box-2"]["status"] == inv.HEALTHY
    assert back["boxes"]["box-2"]["streak"] == 1
    assert back["boxes"]["box-1"]["status"] == inv.MISSING


def test_a_refused_receipt_resets_the_streak() -> None:
    doc = _cycle(None, [_row()])
    doc = _cycle(doc, [_row()], round_=8)
    doc = _cycle(doc, [_row(verdict="REFUSED")], round_=9)
    assert doc["boxes"]["box-1"]["streak"] == 0
    assert _cycle(doc, [_row()], round_=10)["boxes"]["box-1"]["streak"] == 1


def test_a_quiet_box_is_dropped_after_missing_cycles() -> None:
    doc = _cycle(None, [_row()])
    for cycle in range(1, inv.MISSING_CYCLES):
        doc = _cycle(doc, [], round_=7 + cycle)
    assert doc["boxes"]["box-1"]["missed_cycles"] == inv.MISSING_CYCLES - 1
    assert _cycle(doc, [], round_=99)["boxes"] == {}


def test_unverified_receipts_never_enter_and_a_repeated_box_keeps_its_first_row() -> (
    None
):
    doc = _cycle(
        None,
        [
            {"verdict": "REFUSED", "reason": "receipt signature does not verify"},
            _row("twice", verdict="REFUSED"),
            _row("twice"),
        ],
    )
    assert list(doc["boxes"]) == ["twice"]
    assert doc["boxes"]["twice"]["status"] == inv.UNHEALTHY


def test_an_inventory_for_another_netuid_or_schema_starts_over() -> None:
    doc = _cycle(None, [_row()])
    assert _cycle(doc, [], netuid=39)["boxes"] == {}
    assert _cycle({**doc, "schema": "other"}, [])["boxes"] == {}
    assert _cycle({"boxes": "junk"}, [])["boxes"] == {}


def test_the_aggregate_names_no_box_hotkey_or_hardware() -> None:
    doc = _cycle(
        None,
        [
            _row(),
            _row("box-2", hardware_id="f1" * 32),
            _row("box-3", kind="tee", value=300_000),
            _row("box-4", verdict="REFUSED"),
        ],
    )
    assert doc["aggregate"] == {
        "boxes": {inv.HEALTHY: 3, inv.UNHEALTHY: 1, inv.MISSING: 0},
        "healthy_by_kind": {
            "bare_metal": {"boxes": 2, "vcpus": 16, "memory_gib": 64, "value": 448_000},
            "tee": {"boxes": 1, "vcpus": 8, "memory_gib": 32, "value": 300_000},
        },
    }
    text = json.dumps(doc["aggregate"])
    assert "box-" not in text and "hk-a" not in text and "f0f0" not in text


def test_the_box_count_is_bounded_keeping_this_cycles_boxes(monkeypatch) -> None:
    monkeypatch.setattr(inv, "MAX_BOXES", 3)
    doc = _cycle(None, [_row(f"old-{i}") for i in range(3)])
    doc = _cycle(doc, [_row("new-1"), _row("new-2")], round_=8)
    assert len(doc["boxes"]) == 3
    assert {"new-1", "new-2"} <= set(doc["boxes"])


def test_the_file_is_written_atomically_and_read_back(tmp_path) -> None:
    path = tmp_path / "capacity-inventory.json"
    aggregate = inv.record_cycle(path, [_row()], netuid=94, round_=7, now=NOW)
    assert aggregate["boxes"][inv.HEALTHY] == 1
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert inv.load_inventory(path)["boxes"]["box-1"]["status"] == inv.HEALTHY
    inv.record_cycle(path, [], netuid=94, round_=8, now=NOW)
    assert inv.load_inventory(path)["boxes"]["box-1"]["status"] == inv.MISSING
    assert [p.name for p in tmp_path.iterdir()] == ["capacity-inventory.json"]


def test_a_temp_file_left_by_a_crash_never_blocks_a_write(tmp_path) -> None:
    path = tmp_path / "capacity-inventory.json"
    stale = tmp_path / f".capacity-inventory.json.{os.getpid()}.tmp"
    stale.write_text("half-written")
    inv.record_cycle(path, [_row()], netuid=94, round_=7, now=NOW)
    inv.record_cycle(path, [_row()], netuid=94, round_=8, now=NOW)
    assert inv.load_inventory(path)["boxes"]["box-1"]["streak"] == 2


@pytest.mark.parametrize("content", [b"not json", b"[" * 100_000, b"[]"])
def test_a_corrupt_file_starts_a_new_inventory(tmp_path, content) -> None:
    path = tmp_path / "capacity-inventory.json"
    path.write_bytes(content)
    assert inv.load_inventory(path) is None
    inv.record_cycle(path, [_row()], netuid=94, round_=7, now=NOW)
    assert list(inv.load_inventory(path)["boxes"]) == ["box-1"]


def test_a_symlinked_or_special_inventory_path_is_not_followed(tmp_path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    link = tmp_path / "capacity-inventory.json"
    link.symlink_to(target)
    with pytest.raises(inv.CapacityInventoryError):
        inv.load_inventory(link)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    assert inv.load_inventory(fifo) is None  # refused at once, never blocks


def test_the_command_prints_the_inventory_or_only_the_aggregate(
    tmp_path, capsys
) -> None:
    path = tmp_path / "capacity-inventory.json"
    inv.record_cycle(path, [_row()], netuid=94, round_=7, now=NOW)
    assert inv.main([str(path)]) == 0
    assert "box-1" in json.loads(capsys.readouterr().out)["boxes"]
    assert inv.main([str(path), "--aggregate"]) == 0
    public = json.loads(capsys.readouterr().out)
    assert "boxes" not in public and public["aggregate"]["boxes"][inv.HEALTHY] == 1
    assert inv.main([str(tmp_path / "absent.json")]) == 2
