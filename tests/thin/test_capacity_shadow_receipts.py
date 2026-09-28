"""Shadow scoring of SN94 prober capacity receipts against cathedral-sandbox's
``cathedral.capacity`` library. Skipped where the installed sandbox predates it."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral_thin.independent_runtime import capacity_shadow as cs

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
URL = "https://receipts.example/v1/capacity/receipts"
HOTKEY_A = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
HOTKEY_B = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NONCE = "ab" * 32


pytest.importorskip("cathedral.capacity")
from cathedral.capacity import challenge as ch  # noqa: E402
from cathedral.capacity import pricing, receipt  # noqa: E402

PROBER = Ed25519PrivateKey.generate()
OWNER = Ed25519PrivateKey.generate()
SEED = bytes(range(32))
SAMPLE_NONCE = bytes([7]) * 32
DIGEST = bytes([3]) * 32


def _hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _table(**changes):
    table = {
        "schema": pricing.SCHEMA,
        "currency": "usd",
        "rates": {
            "tee": {"vcpu_hour": 30_000, "gib_hour": 4_000},
            "bare_metal": {"vcpu_hour": 18_000, "gib_hour": 2_500},
        },
        "consumer_profiles": {"sn120": {"min_vcpus": 2, "min_memory_gib": 1}},
        "effective_from": "2026-09-28T00:00:00Z",
        "key_id": "owner-1",
        "sequence": 3,
    }
    table.update(changes)
    return pricing.sign_price_table(table, OWNER)


def _policy_doc(**changes):
    document = {
        "schema": cs.POLICY_SCHEMA,
        "mode": "shadow",
        "receipts_url": URL,
        "prober_keys": {"prober-1": _hex(PROBER)},
        "price_keys": {"owner-1": _hex(OWNER)},
        "price_table": _table(),
        "recheck_max_mib": 0,
    }
    document.update(changes)
    return document


def _policy(**changes):
    return cs.parse_capacity_policy(
        json.dumps(_policy_doc(**changes)).encode(), now=NOW
    )


def _receipt(
    *,
    box_id="box-1",
    hotkey=HOTKEY_A,
    hardware="f0" * 32,
    kind="bare_metal",
    vcpus=6,
    memory_gib=24,
    nonce=NONCE,
    round_=7,
    real_outputs=False,
    key=PROBER,
    key_id="prober-1",
):
    spec = ch.spec_for(SEED, vcpus=vcpus, memory_gib=memory_gib)
    lanes = ch.sample_lanes(spec, DIGEST, SAMPLE_NONCE, ch.MIN_SAMPLES)
    outputs = {
        lane: ch.lane_output(spec, lane) if real_outputs else bytes([lane % 256]) * 32
        for lane in lanes
    }
    body = receipt.make_body(
        netuid=94,
        round=round_,
        validator_nonce=nonce,
        box_id=box_id,
        miner_hotkey=hotkey,
        kind=kind,
        hardware_id=hardware,
        hardware_id_kind="probe_fingerprint" if kind == "bare_metal" else "ppid",
        vcpus=vcpus,
        memory_gib=memory_gib,
        challenge=spec,
        result_digest=DIGEST,
        sample_nonce=SAMPLE_NONCE,
        sampled_outputs=outputs,
        deadline_ms=60_000,
        timings_ms={"create": 900, "exec": 40_000, "delete": 300},
        issued_at=NOW,
        valid_for=timedelta(minutes=30),
        prober_key_id=key_id,
    )
    return receipt.sign_receipt(body, key)


def _score(receipts, policy=None, uids=None):
    return cs.score_receipts(
        receipts,
        policy=policy or _policy(),
        netuid=94,
        nonce=NONCE,
        round_=7,
        hotkey_to_uid=uids if uids is not None else {HOTKEY_A: 3, HOTKEY_B: 5},
        now=NOW + timedelta(minutes=1),
    )


def test_a_policy_loads_and_pins_its_digest() -> None:
    raw = json.dumps(_policy_doc()).encode()
    policy = cs.parse_capacity_policy(raw, now=NOW)
    assert policy.mode == "shadow" and policy.receipts_url == URL
    assert set(policy.prober_keys) == {"prober-1"}
    assert policy.price_table.sequence == 3
    assert policy.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"mode": "enforce"}, "mode must be shadow"),
        ({"receipts_url": "http://receipts.example/x"}, "https"),
        ({"receipts_url": URL + "/"}, "must not end with /"),
        ({"receipts_url": URL + "?a=1"}, "query"),
        ({"prober_keys": {}}, "1 to 16"),
        ({"prober_keys": {"prober-1": "AB" * 32}}, "64 lowercase hex"),
        ({"prober_keys": {"bad id": "ab" * 32}}, "malformed key id"),
        ({"price_keys": {"owner-2": "ab" * 32}}, "unknown key"),
        ({"recheck_max_mib": -1}, "recheck_max_mib"),
        ({"recheck_max_mib": True}, "recheck_max_mib"),
        ({"recheck_max_mib": 65}, "recheck_max_mib"),
        ({"inventory_path": "relative.json"}, "inventory_path"),
        ({"inventory_path": "/var/lib/x/inventory.txt"}, "inventory_path"),
        ({"inventory_path": "/var/lib/../etc/inventory.json"}, "inventory_path"),
        ({"inventory_path": 7}, "inventory_path"),
        ({"schema": "other"}, "schema"),
        ({"extra": 1}, "exactly"),
    ],
)
def test_bad_policies_are_refused(changes, message) -> None:
    with pytest.raises(cs.CapacityPolicyError, match=message):
        _policy(**changes)


def test_a_tampered_or_future_price_table_is_refused() -> None:
    tampered = _table()
    tampered["rates"]["bare_metal"]["vcpu_hour"] = 99_000
    with pytest.raises(cs.CapacityPolicyError, match="price_table"):
        _policy(price_table=tampered)
    with pytest.raises(cs.CapacityPolicyError, match="not effective yet"):
        _policy(price_table=_table(effective_from="2026-10-01T00:00:00Z"))


def test_the_policy_file_is_read_safely(tmp_path) -> None:
    path = tmp_path / "capacity.json"
    path.write_text(json.dumps(_policy_doc()))
    os.chmod(path, 0o640)
    assert cs.load_capacity_policy(path, now=NOW).mode == "shadow"
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(cs.CapacityPolicyError, match="unreadable"):
        cs.load_capacity_policy(link, now=NOW)
    os.chmod(path, 0o646)
    with pytest.raises(cs.CapacityPolicyError, match="world-writable"):
        cs.load_capacity_policy(path, now=NOW)
    with pytest.raises(cs.CapacityPolicyError, match="absolute"):
        cs.load_capacity_policy("capacity.json", now=NOW)
    with pytest.raises(cs.CapacityPolicyError, match="regular file"):
        cs.load_capacity_policy(tmp_path, now=NOW)


def test_verified_boxes_are_valued_at_market_price_per_uid() -> None:
    scored = _score(
        [
            _receipt(),
            _receipt(box_id="box-2", hardware="f1" * 32, vcpus=8, memory_gib=32),
            _receipt(box_id="box-3", hotkey=HOTKEY_B, hardware="aa" * 32, kind="tee"),
        ]
    )
    bare_small = 6 * 18_000 + 24 * 2_500
    bare_large = 8 * 18_000 + 32 * 2_500
    tee = 6 * 30_000 + 24 * 4_000
    assert scored["accepted"] == 3 and scored["refused"] == {}
    assert scored["units"] == [[3, bare_small + bare_large], [5, tee]]


def test_receipts_for_another_validator_round_or_key_are_refused() -> None:
    stranger = Ed25519PrivateKey.generate()
    scored = _score(
        [
            _receipt(nonce="cd" * 32),
            _receipt(round_=6),
            _receipt(key=stranger),
            _receipt(key=stranger, key_id="prober-2"),
            {"not": "a receipt"},
        ]
    )
    assert scored["accepted"] == 0 and scored["units"] == []
    assert sum(scored["refused"].values()) == 5
    assert "receipt answers another validator's nonce" in scored["refused"]
    assert "receipt is from another round" in scored["refused"]
    assert "receipt signature does not verify" in scored["refused"]
    assert "receipt is signed by an unknown prober key" in scored["refused"]


def test_hardware_claimed_under_two_hotkeys_earns_nothing_for_either() -> None:
    scored = _score(
        [
            _receipt(),
            _receipt(box_id="box-2", hotkey=HOTKEY_B),
            _receipt(box_id="box-3", hotkey=HOTKEY_B, hardware="f1" * 32),
        ]
    )
    assert scored["refused"] == {"this hardware is claimed under several hotkeys": 2}
    assert [
        row["box_id"] for row in scored["rows"] if row["verdict"] == cs.ACCEPTED
    ] == ["box-3"]


def test_one_hotkeys_boxes_on_the_same_hardware_count_once_at_the_higher_value() -> (
    None
):
    scored = _score(
        [
            _receipt(box_id="box-small"),
            _receipt(box_id="box-large", vcpus=8, memory_gib=32),
        ]
    )
    assert scored["units"] == [[3, 8 * 18_000 + 32 * 2_500]]
    assert scored["refused"] == {"another box of this hotkey has the same hardware": 1}


def test_a_repeated_box_an_unknown_hotkey_and_a_small_box_are_refused() -> None:
    policy = _policy(
        price_table=_table(
            consumer_profiles={"sn81": {"min_vcpus": 8, "min_memory_gib": 32}}
        )
    )
    scored = _score(
        [
            _receipt(box_id="twice", hardware="01" * 32, vcpus=8, memory_gib=32),
            _receipt(box_id="twice", hardware="02" * 32, vcpus=8, memory_gib=32),
            _receipt(box_id="stranger", hotkey=HOTKEY_B, hardware="03" * 32),
            _receipt(box_id="small", hardware="04" * 32),
        ],
        policy=policy,
        uids={HOTKEY_A: 3},
    )
    assert scored["units"] == []
    assert scored["refused"] == {
        "the feed carries this box more than once": 2,
        "the hotkey is not a serving miner on this netuid": 1,
        "below every consumer profile's minimum shape": 1,
    }


def test_a_sampled_lane_is_recomputed_within_the_memory_budget() -> None:
    # 512 lanes over 1 GiB keeps each lane about 1.6 MiB, small enough to recompute.
    honest = _receipt(box_id="honest", vcpus=512, memory_gib=1, real_outputs=True)
    forged = _receipt(box_id="forged", hardware="f1" * 32, vcpus=512, memory_gib=1)
    scored = _score([honest, forged], policy=_policy(recheck_max_mib=2))
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["honest"]["recheck"] == "passed"
    assert rows["honest"]["verdict"] == cs.ACCEPTED
    assert rows["forged"]["recheck"] == "failed"
    assert rows["forged"]["reason"] == "a sampled challenge lane does not recompute"
    assert scored["recheck_failures"] == 1
    too_big = _score([forged], policy=_policy(recheck_max_mib=1))
    assert too_big["rows"][0]["recheck"] == "skipped"
    off = _score([forged])
    assert off["rows"][0]["recheck"] == "off" and off["accepted"] == 1


def test_the_recheck_stops_at_its_time_budget() -> None:
    forged = _receipt(vcpus=512, memory_gib=1)
    ticks = iter([0.0, cs.RECHECK_BUDGET_SECONDS + 1])
    scored = cs.score_receipts(
        [forged],
        policy=_policy(recheck_max_mib=2),
        netuid=94,
        nonce=NONCE,
        round_=7,
        hotkey_to_uid={HOTKEY_A: 3},
        now=NOW + timedelta(minutes=1),
        clock=lambda: next(ticks),
    )
    assert scored["rows"][0]["recheck"] == "skipped"


def _feed(url_seen, receipts_for, **changes):
    def fetch(url):
        url_seen.append(url)
        netuid, nonce = url.rsplit("/", 2)[1:]
        document = {
            "schema": cs.FEED_SCHEMA,
            "netuid": int(netuid),
            "round": 7,
            "validator_nonce": nonce,
            "receipts": receipts_for(nonce),
        }
        document.update(changes)
        return json.dumps(document).encode()

    return fetch


def test_each_cycle_fetches_its_own_receipts_with_a_fresh_nonce() -> None:
    urls: list[str] = []
    fetch = _feed(urls, lambda nonce: [_receipt(nonce=nonce)])
    shadow = cs.CapacityShadow(
        _policy(), fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    )
    first = shadow.record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    second = shadow.record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert first["status"] == second["status"] == "RECORDED"
    assert first["units"] == [[3, 6 * 18_000 + 24 * 2_500]]
    assert first["round"] == 7 and first["price_table_sequence"] == 3
    assert urls[0].startswith(URL + "/94/") and urls[0] != urls[1]


@pytest.mark.parametrize(
    "changes",
    [{"netuid": 39}, {"validator_nonce": "cd" * 32}, {"schema": "x"}, {"round": -1}],
)
def test_a_feed_for_another_audience_is_recorded_as_failed(changes) -> None:
    fetch = _feed([], lambda nonce: [], **changes)
    record = cs.CapacityShadow(_policy(), fetch=fetch).record(
        netuid=94, hotkey_to_uid={}
    )
    assert record["status"] == "FAILED"


def test_a_fetch_error_is_recorded_never_raised() -> None:
    def fetch(_url):
        raise OSError("unreachable")

    record = cs.CapacityShadow(_policy(), fetch=fetch).record(
        netuid=94, hotkey_to_uid={}
    )
    assert record["status"] == "FAILED" and "unreachable" in record["error"]


def test_the_record_keeps_a_bounded_number_of_rows() -> None:
    count = cs.MAX_EVENT_ROWS + 5
    fetch = _feed(
        [],
        lambda nonce: [
            _receipt(box_id=f"box-{i}", hardware=f"{i:064x}", nonce=nonce)
            for i in range(count)
        ],
    )
    record = cs.CapacityShadow(
        _policy(), fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert record["receipts"] == record["accepted"] == count
    assert len(record["rows"]) == cs.MAX_EVENT_ROWS and record["rows_omitted"] == 5
    assert record["units"] == [[3, count * (6 * 18_000 + 24 * 2_500)]]
    assert len(json.dumps(record)) < 24_000


@pytest.mark.parametrize("raw", [b"[" * 100_000, b'{"schema": ' + b"9" * 5000 + b"}"])
def test_a_hostile_policy_file_is_a_policy_error(raw) -> None:
    with pytest.raises(cs.CapacityPolicyError):
        cs.parse_capacity_policy(raw, now=NOW)


def test_each_record_updates_the_inventory_file(tmp_path) -> None:
    path = tmp_path / "capacity-inventory.json"
    policy = _policy(inventory_path=str(path))
    count = cs.MAX_EVENT_ROWS + 3
    fetch = _feed(
        [],
        lambda nonce: [
            _receipt(box_id=f"box-{i}", hardware=f"{i:064x}", nonce=nonce)
            for i in range(count)
        ],
    )
    shadow = cs.CapacityShadow(
        policy, fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    )
    record = shadow.record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert record["inventory"]["status"] == "WRITTEN"
    assert record["inventory"]["aggregate"]["boxes"]["healthy"] == count
    stored = json.loads(path.read_text())
    assert len(stored["boxes"]) == count  # every box, not only the logged rows
    assert stored["netuid"] == 94 and stored["round"] == 7


def test_an_inventory_write_failure_is_recorded_not_raised(tmp_path) -> None:
    policy = _policy(inventory_path=str(tmp_path / "absent-dir" / "inventory.json"))
    fetch = _feed([], lambda nonce: [_receipt(nonce=nonce)])
    shadow = cs.CapacityShadow(
        policy, fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    )
    record = shadow.record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert record["status"] == "RECORDED" and record["accepted"] == 1
    assert record["inventory"]["status"] == "FAILED"
