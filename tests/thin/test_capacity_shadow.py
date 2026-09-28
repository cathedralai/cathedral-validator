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


@pytest.mark.parametrize("digest", [None, "ab" * 32])
def test_startup_says_once_when_no_price_table_digest_is_pinned(
    monkeypatch, capsys, digest
) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    policy = SimpleNamespace(price_table_digest=digest, minimum_price_table_sequence=4)
    monkeypatch.setenv(cs.CAPACITY_POLICY_ENV, "/etc/cathedral-validator/capacity.json")
    monkeypatch.setattr(runtime, "load_capacity_policy", lambda *_a, **_k: policy)
    assert runtime._capacity_shadow_from_environment().policy is policy
    out = capsys.readouterr().out
    if digest is not None:
        assert out == ""
        return
    event = json.loads(out)["capacity_shadow"]
    assert event["status"] == "LOADED"
    assert "price_table_digest is not pinned" in event["warning"]
    assert "sequence 4" in event["warning"]


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


def test_a_refusal_reason_is_bounded_printable_ascii() -> None:
    assert cs._reason("x" * 500) == "x" * cs.MAX_ERROR_CHARS
    assert cs._reason('bad "quote" \\ café\n') == "bad ?quote? ? caf??"
    line = json.dumps({"reason": cs._reason('é"\\\x00' * 100)})
    assert len(line) == len('{"reason": ""}') + cs.MAX_ERROR_CHARS


def test_the_worst_case_record_fits_one_journal_line(monkeypatch, capsys) -> None:
    """Every capped part at its largest: the most rows, each with the longest
    fields the library allows (a 128-character box id, SEV-SNP evidence, the
    largest capacity and value, a reason of MAX_ERROR_CHARS), 4096 paid UIDs
    with values past any real total, and 1024 distinct longest reasons."""

    from cathedral_thin.independent_runtime import direct_validator as runtime

    snp = "c3" * 48
    value = 10**12 * (1024 + 10 * 1024)  # MAX_MICRO rates, 1024 vCPUs, 10 GiB each
    row = {
        "box_id": "b" * 128,
        "miner_hotkey": HOTKEY_A,
        "uid": 65535,
        "kind": "bare_metal",
        "tee_kind": "sev_snp",
        "hardware_id_kind": "probe_fingerprint",
        "hardware_id": "f" * 64,
        "vcpus": 1024,
        "memory_gib": 10 * 1024,
        "value": value,
        "evidence": {
            "evidence_kind": "sev_snp",
            "evidence_sha256": "e" * 64,
            "measurement": snp,
            "verifier_digest": "sha256:" + "5e" * 32,
            "tls_spki_sha256": "7" * 64,
        },
        "measurement_allowed": False,
        "recheck": "skipped",
        "verdict": "REFUSED",
        "reason": "r" * cs.MAX_ERROR_CHARS,
    }
    count = 1024
    scored = {
        "receipts": count,
        "accepted": count,
        "refused": {
            f"{i:04d}".ljust(cs.MAX_ERROR_CHARS, "r"): count for i in range(count)
        },
        "recheck_failures": count,
        "units": [[uid, 10**20] for uid in range(4096)],
        "rows": [dict(row) for _ in range(count)],
    }
    monkeypatch.setattr(cs, "score_receipts", lambda *_a, **_k: scored)
    big = 10**20
    aggregate = {
        "boxes": {"healthy": 4096, "unhealthy": 4096, "missing": 4096},
        "healthy_by_kind": {
            kind: {"boxes": 4096, "vcpus": big, "memory_gib": big, "value": big}
            for kind in ("bare_metal", "tee")
        },
    }
    monkeypatch.setattr(cs, "record_cycle", lambda *_a, **_k: aggregate)
    policy = SimpleNamespace(
        mode="shadow",
        digest="sha256:" + "0" * 64,
        receipts_url=URL,
        price_table=SimpleNamespace(sequence=2**63 - 1, currency="abcdefgh"),
        inventory_path="/var/lib/cathedral-validator/capacity-inventory.json",
        measurement_policies={
            kind: SimpleNamespace(mode="enforce", digest="sha256:" + "d" * 64)
            for kind in ("tdx", "sev_snp")
        },
    )

    def feed(url):
        netuid, nonce = url.rsplit("/", 2)[1:]
        return json.dumps(
            {
                "schema": cs.FEED_SCHEMA,
                "netuid": int(netuid),
                "round": 2**63 - 1,
                "validator_nonce": nonce,
                "receipts": [],
            }
        ).encode()

    record = cs.CapacityShadow(policy, fetch=feed).record(
        netuid=65535, hotkey_to_uid={}
    )
    assert record["status"] == "RECORDED"
    assert len(record["rows"]) == cs.MAX_EVENT_ROWS
    assert record["rows_omitted"] == count - cs.MAX_EVENT_ROWS
    assert len(record["units"]) == cs.MAX_EVENT_UNITS
    assert record["units_omitted"] == 4096 - cs.MAX_EVENT_UNITS
    assert record["units_total"] == 4096 * 10**20
    assert len(record["refused"]) == cs.MAX_EVENT_REASONS
    assert record["refused_omitted"] == (count - cs.MAX_EVENT_REASONS) * count
    assert record["inventory"] == {"status": "WRITTEN", "aggregate": aggregate}
    # The line exactly as the validator prints it.
    runtime._print_event({"anchor_block": 2**63 - 1, "capacity_shadow": record})
    line = capsys.readouterr().out.encode()
    assert line.count(b"\n") == 1
    assert len(line) < cs.MAX_EVENT_LINE_BYTES < 48 * 1024


def test_the_record_keeps_the_most_valuable_uids_and_most_common_reasons(
    monkeypatch,
) -> None:
    scored = {
        "receipts": 5,
        "accepted": 3,
        "refused": {"b": 1, "a": 1, "c": 3},
        "recheck_failures": 0,
        "units": [[1, 10], [2, 30], [3, 20], [4, 30]],
        "rows": [],
    }
    monkeypatch.setattr(cs, "MAX_EVENT_UNITS", 3)
    monkeypatch.setattr(cs, "MAX_EVENT_REASONS", 2)
    fields = cs._event_fields(scored)
    assert fields["units"] == [[2, 30], [3, 20], [4, 30]]  # by uid; uid 1 is least
    assert fields["units_omitted"] == 1 and fields["units_total"] == 90
    assert fields["refused"] == {"a": 1, "c": 3} and fields["refused_omitted"] == 1
