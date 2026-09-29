"""Shadow scoring of SN94 prober capacity receipts (capacity_shadow.py)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cathedral_thin.independent_runtime import capacity_shadow as cs

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
URL = "https://receipts.example/v1/capacity/receipts"
HOTKEY_A = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
HOTKEY_B = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NONCE = "ab" * 32


def test_without_the_library_the_shadow_record_fails_closed(monkeypatch) -> None:
    def missing():
        raise cs.CapacityPolicyError(
            "the installed cathedral-sandbox has no cathedral.capacity library"
        )

    monkeypatch.setattr(cs, "_library", missing)
    with pytest.raises(cs.CapacityPolicyError, match="no cathedral.capacity"):
        cs.parse_capacity_policy(b"{}", now=NOW)
    policy = SimpleNamespace(
        mode="shadow",
        digest="sha256:" + "0" * 64,
        receipts_url=URL,
        price_table=SimpleNamespace(sequence=1, currency="usd"),
    )

    def feed(url):
        netuid, nonce = url.rsplit("/", 2)[1:]
        return json.dumps(
            {
                "schema": cs.FEED_SCHEMA,
                "netuid": int(netuid),
                "round": 7,
                "validator_nonce": nonce,
                "receipts": [],
            }
        ).encode()

    record = cs.CapacityShadow(policy, fetch=feed).record(netuid=94, hotkey_to_uid={})
    assert record["status"] == "FAILED"
    assert "no cathedral.capacity" in record["error"]


def test_a_missing_policy_changes_nothing_and_a_bad_one_never_stops_the_validator(
    monkeypatch, tmp_path, capsys
) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    monkeypatch.delenv(cs.CAPACITY_POLICY_ENV, raising=False)
    assert runtime._capacity_shadow_from_environment() is None
    monkeypatch.setenv(cs.CAPACITY_POLICY_ENV, str(tmp_path / "absent.json"))
    assert runtime._capacity_shadow_from_environment() is None
    event = json.loads(capsys.readouterr().out)
    assert event["capacity_shadow"]["status"] == "DISABLED"


@pytest.mark.parametrize("error", [RecursionError, ValueError, MemoryError, OSError])
def test_no_policy_load_error_escapes_startup(monkeypatch, capsys, error) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    def explode(*_args, **_kwargs):
        raise error("boom")

    monkeypatch.setenv(cs.CAPACITY_POLICY_ENV, "/etc/cathedral-validator/capacity.json")
    monkeypatch.setattr(runtime, "load_capacity_policy", explode)
    assert runtime._capacity_shadow_from_environment() is None
    event = json.loads(capsys.readouterr().out)
    assert event["capacity_shadow"] == {"status": "DISABLED", "error": error.__name__}


def test_a_fifo_policy_path_is_refused_without_blocking(tmp_path) -> None:
    fifo = tmp_path / "capacity.json"
    os.mkfifo(fifo)
    with pytest.raises(cs.CapacityPolicyError, match="regular file"):
        cs._safe_bytes(fifo)


def test_shadow_runs_only_for_fresh_cycles_and_never_raises() -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    calls: list[tuple[int, dict[str, int]]] = []

    class Shadow:
        def record(self, *, netuid, hotkey_to_uid):
            calls.append((netuid, dict(hotkey_to_uid)))
            return {"status": "RECORDED"}

    anchor = {
        "block_number": 123,
        "miners": [{"uid": 19, "hotkey": "hk-19", "ip": "1.1.1.1", "port": 8081}],
    }
    fresh = {"status": "CONFIRMED", "anchor": anchor, "wire_uids": [19]}
    before = dict(fresh)
    assert runtime._capacity_shadow_event(fresh, Shadow(), 94) == {
        "anchor_block": 123,
        "capacity_shadow": {"status": "RECORDED"},
    }
    assert calls == [(94, {"hk-19": 19})]
    assert fresh == before  # the cycle's own event is never changed

    recovery = {"status": "RECOVERED", "anchor": anchor}
    assert runtime._capacity_shadow_event(recovery, Shadow(), 94) is None
    assert len(calls) == 1
    assert runtime._capacity_shadow_event(fresh, None, 94) is None

    class Broken:
        def record(self, **_kwargs):
            raise RuntimeError("shadow bug")

    assert runtime._capacity_shadow_event(fresh, Broken(), 94) == {
        "anchor_block": 123,
        "capacity_shadow": {"status": "FAILED", "error": "RuntimeError"},
    }
