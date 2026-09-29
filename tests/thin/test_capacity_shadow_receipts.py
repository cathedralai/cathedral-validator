"""Shadow scoring of SN94 prober capacity receipts against cathedral-sandbox's
``cathedral.capacity`` library. Skipped where the installed sandbox predates it."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral_thin.independent_runtime import capacity_inventory as inv
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
TEE_6_24 = 6 * 30_000 + 24 * 4_000
BARE_6_24 = 6 * 18_000 + 24 * 2_500
TDX_MEASUREMENT = "tdx-measurement-sha256:" + "a1" * 32
TDX_OTHER = "tdx-measurement-sha256:" + "b2" * 32
SNP_MEASUREMENT = "c3" * 48
VERIFIER = "sha256:" + "5e" * 32
ATTESTED_AT = "2026-09-28T11:50:00Z"  # the prober verified the quote before NOW
_DEFAULT = object()


def _evidence(tee_kind, measurement=None, **changes):
    """A v2 receipt's evidence for a TEE box, as the prober records it."""

    evidence = {
        "evidence_kind": tee_kind,
        "evidence_sha256": hashlib.sha256(tee_kind.encode()).hexdigest(),
        "measurement": measurement
        or (TDX_MEASUREMENT if tee_kind == "tdx" else SNP_MEASUREMENT),
        "verifier_digest": VERIFIER,
        "tls_spki_sha256": "7a" * 32,
        "attestation_nonce": "9c" * 32,
        "attested_at": ATTESTED_AT,
    }
    evidence.update(changes)
    return evidence


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
    kind="tee",
    tee_kind=_DEFAULT,
    vcpus=6,
    memory_gib=24,
    nonce=NONCE,
    round_=7,
    real_outputs=False,
    key=PROBER,
    key_id="prober-1",
    sample_count=None,
    hardware_id_kind=None,
    evidence=_DEFAULT,
    measurement=None,
    sign_by_hand=False,
):
    if tee_kind is _DEFAULT:
        tee_kind = "tdx" if kind == "tee" else None
    if evidence is _DEFAULT:
        # Receipt v2: evidence for a TEE box, null for bare metal.
        evidence = _evidence(tee_kind, measurement) if tee_kind is not None else None
    forged = sign_by_hand or hardware_id_kind is not None
    if tee_kind == "tdx":
        # A TDX box's hardware id comes from the digest in the strict
        # verifier's stable_platform_id, as the prober derives it.
        hardware = receipt.tdx_hardware_id(f"tdx-platform-sha256:{hardware}")
    spec = ch.spec_for(SEED, vcpus=vcpus, memory_gib=memory_gib)
    deadline_ms = min(60_000, ch.max_deadline_ms(spec))
    count = sample_count or ch.required_samples(spec.lanes)
    lanes = ch.sample_lanes(spec, DIGEST, SAMPLE_NONCE, count)
    outputs = {lane: bytes([lane % 256]) * 32 for lane in lanes}
    if real_outputs:
        # Only the one lane the validator's recheck picks (as score_receipts
        # does) is computed for real: every sampled lane would take too long.
        pick = hashlib.sha256(bytes.fromhex(nonce) + box_id.encode()).digest()
        lane = lanes[int.from_bytes(pick[:8], "big") % len(lanes)]
        outputs[lane] = ch.lane_output(spec, lane)
    body = receipt.make_body(
        netuid=94,
        round=round_,
        validator_nonce=nonce,
        box_id=box_id,
        miner_hotkey=hotkey,
        kind=kind,
        tee_kind=tee_kind,
        hardware_id=hardware,
        vcpus=vcpus,
        memory_gib=memory_gib,
        challenge=spec,
        result_digest=DIGEST,
        sample_nonce=SAMPLE_NONCE,
        sample_count=count,
        sampled_outputs=outputs,
        deadline_ms=deadline_ms,
        timings_ms={"create": 900, "exec": deadline_ms * 2 // 3, "delete": 300},
        issued_at=NOW,
        valid_for=timedelta(minutes=30),
        prober_key_id=key_id,
        evidence=evidence,
    )
    if forged:
        # sign_receipt refuses a body of the wrong kind, or a TEE body without
        # evidence, so a forged one is signed by hand: only the validator's
        # verification may reject it.
        if hardware_id_kind is not None:
            body["box"]["hardware_id_kind"] = hardware_id_kind
        signature = key.sign(receipt.canonical_bytes(body))
        return {**body, "signature": base64.b64encode(signature).decode()}
    # The prober signs bare metal only when told to; whether it earns is the
    # validator's admit_bare_metal.
    return receipt.sign_receipt(body, key, allow_bare_metal=kind == "bare_metal")


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
    assert policy.admit_bare_metal is False
    assert policy.minimum_price_table_sequence == 1
    assert policy.price_table_digest is None
    assert policy.max_evidence_age == timedelta(
        seconds=cs.DEFAULT_MAX_EVIDENCE_AGE_SECONDS
    )


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
        ({"admit_bare_metal": 1}, "admit_bare_metal must be true or false"),
        ({"admit_bare_metal": "yes"}, "admit_bare_metal must be true or false"),
        ({"admit_bare_metal": None}, "admit_bare_metal must be true or false"),
        ({"minimum_price_table_sequence": 0}, "minimum_price_table_sequence"),
        ({"minimum_price_table_sequence": True}, "minimum_price_table_sequence"),
        ({"minimum_price_table_sequence": "3"}, "minimum_price_table_sequence"),
        ({"minimum_price_table_sequence": 2**63}, "minimum_price_table_sequence"),
        ({"price_table_digest": "AB" * 32}, "price_table_digest"),
        ({"price_table_digest": "ab" * 31}, "price_table_digest"),
        ({"price_table_digest": 7}, "price_table_digest"),
        ({"max_evidence_age_seconds": 0}, "max_evidence_age_seconds"),
        ({"max_evidence_age_seconds": -1}, "max_evidence_age_seconds"),
        ({"max_evidence_age_seconds": True}, "max_evidence_age_seconds"),
        ({"max_evidence_age_seconds": 60.0}, "max_evidence_age_seconds"),
        ({"max_evidence_age_seconds": None}, "max_evidence_age_seconds"),
        (
            {"max_evidence_age_seconds": cs.MAX_EVIDENCE_AGE_SECONDS + 1},
            "max_evidence_age_seconds",
        ),
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


def test_the_price_table_cannot_be_rolled_back_or_swapped() -> None:
    table = _table()
    digest = pricing.table_digest(table)
    policy = _policy(minimum_price_table_sequence=3, price_table_digest=digest)
    assert policy.minimum_price_table_sequence == 3
    assert policy.price_table_digest == digest
    assert policy.price_table.digest == digest
    with pytest.raises(cs.CapacityPolicyError, match="older than one already verified"):
        _policy(minimum_price_table_sequence=4)
    other = _table(currency="eur")
    with pytest.raises(cs.CapacityPolicyError, match="differs from the one pinned"):
        _policy(
            price_table=other, minimum_price_table_sequence=3, price_table_digest=digest
        )
    # The pin names the table at the minimum sequence; a newer table replaces it.
    newer = _table(sequence=4)
    assert (
        _policy(
            price_table=newer, minimum_price_table_sequence=3, price_table_digest=digest
        ).price_table.sequence
        == 4
    )


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


def _mixed_round():
    return [
        _receipt(kind="bare_metal"),
        _receipt(
            box_id="box-2",
            hardware="f1" * 32,
            vcpus=8,
            memory_gib=32,
            kind="bare_metal",
        ),
        _receipt(box_id="box-3", hotkey=HOTKEY_B, hardware="aa" * 32),
        _receipt(
            box_id="box-4", hotkey=HOTKEY_B, hardware="ab" * 32, tee_kind="sev_snp"
        ),
    ]


def test_with_admit_bare_metal_on_every_verified_box_is_valued_per_uid() -> None:
    scored = _score(_mixed_round(), policy=_policy(admit_bare_metal=True))
    bare_large = 8 * 18_000 + 32 * 2_500
    assert scored["accepted"] == 4 and scored["refused"] == {}
    assert scored["units"] == [[3, BARE_6_24 + bare_large], [5, 2 * TEE_6_24]]
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert [rows[b]["tee_kind"] for b in ("box-1", "box-3", "box-4")] == [
        None,
        "tdx",
        "sev_snp",
    ]
    assert rows["box-4"]["hardware_id_kind"] == "chip_id"
    assert rows["box-3"]["hardware_id_kind"] == "tdx_platform"
    assert rows["box-3"]["hardware_id"] == receipt.tdx_hardware_id(
        "tdx-platform-sha256:" + "aa" * 32
    )


def test_a_tdx_receipt_keyed_by_ppid_is_refused() -> None:
    scored = _score([_receipt(hardware_id_kind="ppid"), _receipt(box_id="box-2")])
    assert scored["accepted"] == 1 and scored["units"] == [[3, TEE_6_24]]
    assert list(scored["refused"]) == [
        "hardware_id_kind must be tdx_platform for tdx, chip_id for sev_snp and"
        " probe_fingerprint for bare metal"
    ]


def test_bare_metal_is_refused_by_default_and_tee_still_earns() -> None:
    scored = _score(_mixed_round())
    assert scored["accepted"] == 2
    assert scored["refused"] == {cs.BARE_METAL_REFUSED: 2}
    assert cs.BARE_METAL_REFUSED == (
        "bare-metal boxes are not admitted (admit_bare_metal is off)"
    )
    assert scored["units"] == [[5, 2 * TEE_6_24]]
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["box-1"]["verdict"] == "REFUSED" and rows["box-1"]["recheck"] == "off"
    assert rows["box-1"]["kind"] == "bare_metal" and rows["box-1"]["tee_kind"] is None
    # It still shows in the inventory, as unhealthy with that reason.
    doc = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    assert doc["boxes"]["box-1"]["status"] == inv.UNHEALTHY
    assert doc["boxes"]["box-1"]["reason"] == cs.BARE_METAL_REFUSED
    assert doc["boxes"]["box-3"]["status"] == inv.HEALTHY
    assert doc["boxes"]["box-4"]["tee_kind"] == "sev_snp"
    assert doc["aggregate"]["healthy_by_kind"] == {
        "tee": {"boxes": 2, "vcpus": 12, "memory_gib": 48, "value": 2 * TEE_6_24}
    }


def test_a_refused_bare_metal_receipt_cannot_knock_out_a_tee_box_with_its_id() -> None:
    # Review of T1: a cheap bare-metal receipt reusing a TEE box's id used to
    # make both "carried more than once", zeroing the TEE box.
    scored = _score(
        [
            _receipt(box_id="victim", kind="bare_metal", hardware="b0" * 32),
            _receipt(box_id="victim", hotkey=HOTKEY_B, hardware="aa" * 32),
        ]
    )
    assert scored["units"] == [[5, TEE_6_24]]
    assert scored["refused"] == {cs.BARE_METAL_REFUSED: 1}
    doc = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    assert doc["boxes"]["victim"]["status"] == inv.HEALTHY
    assert doc["boxes"]["victim"]["kind"] == "tee"


def test_a_refused_tee_box_keeps_its_own_reason_over_a_bare_metal_one() -> None:
    # Review of #265: the not-admitted bare-metal row came first, the TEE row
    # with the same id was refused for another reason, and the inventory kept
    # the bare-metal row, hiding the TEE box's real reason.
    scored = _score(
        [
            _receipt(box_id="x", kind="bare_metal", hardware="b0" * 32),
            _receipt(box_id="x", hotkey=HOTKEY_B, hardware="aa" * 32),
        ],
        uids={HOTKEY_A: 3},
    )
    assert scored["accepted"] == 0
    doc = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    box = doc["boxes"]["x"]
    assert box["kind"] == "tee" and box["miner_hotkey"] == HOTKEY_B
    assert box["status"] == inv.UNHEALTHY
    assert box["reason"] == "the hotkey is not a serving miner on this netuid"


def test_one_receipt_that_breaks_verification_or_valuation_is_contained(
    monkeypatch,
) -> None:
    real_verify = receipt.verify_receipt

    def verify(item, **kwargs):
        if item.get("box", {}).get("box_id") == "boom":
            raise RuntimeError("library bug")
        return real_verify(item, **kwargs)

    monkeypatch.setattr(receipt, "verify_receipt", verify)
    scored = _score(
        [
            _receipt(),
            _receipt(box_id="boom", hardware="f1" * 32),
            _receipt(box_id="b3", hardware="f2" * 32),
        ]
    )
    assert scored["accepted"] == 2 and scored["refused"] == {
        "RuntimeError: library bug": 1
    }
    assert scored["units"] == [[3, 2 * TEE_6_24]]
    monkeypatch.setattr(receipt, "verify_receipt", real_verify)

    class Table:
        sequence, currency = 3, "usd"

        def value(self, *, kind, vcpus, memory_gib):
            if vcpus == 8:
                raise pricing.PriceTableError("vcpus must be a positive integer")
            return 1

    policy = dataclasses.replace(_policy(), price_table=Table())
    scored = _score(
        [_receipt(), _receipt(box_id="b2", hardware="f1" * 32, vcpus=8, memory_gib=32)],
        policy=policy,
    )
    assert scored["accepted"] == 1 and scored["refused"] == {
        "PriceTableError: vcpus must be a positive integer": 1
    }
    assert scored["units"] == [[3, 1]]


@pytest.mark.parametrize("stop", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_an_interpreter_stop_while_verifying_is_never_contained(
    monkeypatch, stop
) -> None:
    # Only Exception is contained per receipt: a stop request must still stop.
    real_verify = receipt.verify_receipt

    def verify(item, **kwargs):
        if item.get("box", {}).get("box_id") == "stop":
            raise stop
        return real_verify(item, **kwargs)

    monkeypatch.setattr(receipt, "verify_receipt", verify)
    with pytest.raises(stop):
        _score([_receipt(), _receipt(box_id="stop", hardware="f1" * 32)])


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
    assert scored["units"] == [[3, 8 * 30_000 + 32 * 4_000]]
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


def test_no_real_lane_fits_the_recheck_budget() -> None:
    # The library refuses any claim with less than MIN_LANE_BYTES of lane per
    # vCPU, and the pure-Python recheck is capped below that, so every receipt a
    # prober can issue today is skipped: the recheck is off until a native
    # checker exists. Raising the cap past the floor must revisit that decision
    # (docs/CAPACITY_RECEIPTS.md, recheck_max_mib).
    assert cs.MAX_RECHECK_MIB << 20 < ch.MIN_LANE_BYTES
    # 8 vCPUs over 5 GiB is the floor exactly: one 512 MiB lane per vCPU.
    spec = ch.spec_for(SEED, vcpus=8, memory_gib=5)
    assert spec.blocks * ch.BLOCK_BYTES == ch.MIN_LANE_BYTES
    smallest = _receipt(vcpus=8, memory_gib=5)
    scored = _score([smallest], policy=_policy(recheck_max_mib=cs.MAX_RECHECK_MIB))
    assert scored["rows"][0]["recheck"] == "skipped"
    assert scored["rows"][0]["verdict"] == cs.ACCEPTED
    assert scored["recheck_failures"] == 0


@pytest.fixture
def small_lanes(monkeypatch):
    """Lower the library's lane floor so a test lane is small enough to
    recompute. This exercises the recheck machinery, kept for a native checker;
    no real receipt has lanes this small."""

    monkeypatch.setattr(ch, "MIN_LANE_BYTES", 1 << 20)


def test_a_sampled_lane_is_recomputed_within_the_memory_budget(small_lanes) -> None:
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


def test_a_recheck_that_raises_refuses_only_that_receipt(
    small_lanes, monkeypatch
) -> None:
    def lane_output(spec, lane):
        raise MemoryError

    monkeypatch.setattr(ch, "lane_output", lane_output)
    small = _receipt(
        box_id="small", hardware="f1" * 32
    )  # its lane is too big to recheck
    scored = _score(
        [_receipt(vcpus=512, memory_gib=1), small], policy=_policy(recheck_max_mib=2)
    )
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["box-1"]["recheck"] == "error"
    assert rows["box-1"]["reason"] == "MemoryError"
    assert rows["small"]["recheck"] == "skipped"
    assert scored["units"] == [[3, TEE_6_24]]


@pytest.mark.parametrize("stop", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_an_interpreter_stop_during_the_recheck_is_never_contained(
    small_lanes, monkeypatch, stop
) -> None:
    calls: list[int] = []

    def lane_output(spec, lane):
        calls.append(lane)
        raise stop

    monkeypatch.setattr(ch, "lane_output", lane_output)
    with pytest.raises(stop):
        _score([_receipt(vcpus=512, memory_gib=1)], policy=_policy(recheck_max_mib=2))
    assert len(calls) == 1


def test_the_recheck_stops_at_its_time_budget(small_lanes) -> None:
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
    assert first["units"] == [[3, TEE_6_24]]
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
            # the longest box ids the library accepts, each with v2 evidence
            _receipt(box_id=f"{i:0128d}", hardware=f"{i + 1:064x}", nonce=nonce)
            for i in range(count)
        ],
    )
    record = cs.CapacityShadow(
        _policy(), fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert record["receipts"] == record["accepted"] == count
    assert len(record["rows"]) == cs.MAX_EVENT_ROWS and record["rows_omitted"] == 5
    assert record["units"] == [[3, count * TEE_6_24]]
    assert all(
        row["evidence"]["measurement"] == TDX_MEASUREMENT for row in record["rows"]
    )
    # One journal line, well under journald's default 48 KiB LineMax, even with
    # every row carrying its evidence.
    line = json.dumps({"anchor_block": 1, "capacity_shadow": record}, sort_keys=True)
    assert len(line) < cs.MAX_EVENT_LINE_BYTES


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
            _receipt(box_id=f"box-{i}", hardware=f"{i + 1:064x}", nonce=nonce)
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


# Receipt v2: TEE evidence, and the optional measurement allowlist.


@pytest.mark.parametrize(
    "evidence, reason",
    [
        (None, "a tee receipt's evidence must have exactly"),
        (_evidence("sev_snp"), "evidence_kind must equal the box's tee_kind"),
        (
            _evidence("tdx", measurement="tdx-measurement-sha256:" + "00" * 32),
            "all zeros",
        ),
    ],
)
def test_a_tee_receipt_with_missing_or_bad_evidence_is_refused_alone(
    evidence, reason
) -> None:
    # The prober's sign_receipt refuses such a body, so only a forged or buggy
    # prober could sign it: the validator's verification must still refuse it.
    with pytest.raises(receipt.ReceiptError):
        _receipt(box_id="bad", hardware="f1" * 32, evidence=evidence)
    bad = _receipt(
        box_id="bad", hardware="f1" * 32, evidence=evidence, sign_by_hand=True
    )
    scored = _score([_receipt(), bad])
    assert scored["accepted"] == 1 and scored["units"] == [[3, TEE_6_24]]
    [refused] = [row for row in scored["rows"] if row["verdict"] != cs.ACCEPTED]
    assert reason in refused["reason"]
    assert "box_id" not in refused  # an unverified receipt names no box
    doc = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    assert list(doc["boxes"]) == ["box-1"]


def test_tee_evidence_is_recorded_in_rows_and_the_inventory() -> None:
    scored = _score(_mixed_round(), policy=_policy(admit_bare_metal=True))
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["box-3"]["evidence"] == _evidence("tdx")
    assert rows["box-4"]["evidence"] == _evidence("sev_snp")
    assert rows["box-1"]["evidence"] is None  # bare metal carries none
    assert {row["measurement_allowed"] for row in scored["rows"]} == {None}
    first = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    assert first["boxes"]["box-3"]["evidence"] == _evidence("tdx")
    assert first["boxes"]["box-1"]["evidence"] is None
    # The inventory keeps the evidence of the box's latest receipt.
    later = _score(
        [
            _receipt(
                box_id="box-3",
                hotkey=HOTKEY_B,
                hardware="aa" * 32,
                measurement=TDX_OTHER,
            )
        ]
    )
    second = inv.update_inventory(
        first, later["rows"], netuid=94, round_=8, now=NOW + timedelta(minutes=25)
    )
    assert second["boxes"]["box-3"]["evidence"]["measurement"] == TDX_OTHER
    assert second["boxes"]["box-3"]["streak"] == 2
    # A box gone quiet keeps its last-seen evidence.
    assert second["boxes"]["box-4"]["status"] == inv.MISSING
    assert second["boxes"]["box-4"]["evidence"] == _evidence("sev_snp")


def test_the_default_evidence_age_follows_the_validator_round() -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    assert cs.ROUND_SECONDS == runtime.DEFAULT_INTERVAL_SECONDS
    assert cs.DEFAULT_MAX_EVIDENCE_AGE_SECONDS == 4 * cs.ROUND_SECONDS


def test_tee_evidence_older_than_the_policy_allows_is_refused_alone() -> None:
    # _score checks at NOW + 1 minute, 11 minutes after ATTESTED_AT.
    fresh = _receipt()
    stale = _receipt(
        box_id="stale",
        hardware="f1" * 32,
        evidence=_evidence("tdx", attested_at="2026-09-28T10:00:00Z"),
    )
    bare = _receipt(box_id="bare", hardware="f2" * 32, kind="bare_metal")
    scored = _score([fresh, stale, bare], policy=_policy(admit_bare_metal=True))
    rows = {row.get("box_id", "refused"): row for row in scored["rows"]}
    # 121 minutes is past the default of four rounds (100 minutes).
    assert rows["refused"]["reason"] == (
        "the receipt's evidence is older than max_evidence_age"
    )
    assert rows["box-1"]["verdict"] == rows["bare"]["verdict"] == cs.ACCEPTED
    # The bound is the policy's: a tighter one refuses the fresh receipt too,
    # and bare metal, which has no evidence, is never refused for age.
    tight = _score(
        [fresh, stale, bare],
        policy=_policy(admit_bare_metal=True, max_evidence_age_seconds=600),
    )
    assert tight["accepted"] == 1
    assert tight["refused"] == {
        "the receipt's evidence is older than max_evidence_age": 2
    }
    loose = _score([stale], policy=_policy(max_evidence_age_seconds=3 * 3600))
    assert loose["accepted"] == 1


def _measurement_policy(tmp_path, name, *, schema, mode, allowed):
    path = tmp_path / name
    path.write_text(
        json.dumps({"schema": schema, "mode": mode, "allowed_measurements": allowed})
    )
    os.chmod(path, 0o640)
    return str(path)


TDX_SCHEMA = "cathedral_tdx_measurement_policy_v1"
SNP_SCHEMA = "cathedral_snp_measurement_policy_v1"


def test_an_enforced_measurement_allowlist_refuses_unlisted_tee_images(
    tmp_path,
) -> None:
    pytest.importorskip("cathedral.capacity.admission")
    tdx = _measurement_policy(
        tmp_path,
        "tdx.json",
        schema=TDX_SCHEMA,
        mode="enforce",
        allowed=[TDX_MEASUREMENT],
    )
    policy = _policy(measurement_policies=[tdx])
    assert set(policy.measurement_policies) == {"tdx"}
    scored = _score(
        [
            _receipt(box_id="listed"),
            _receipt(
                box_id="unlisted",
                hotkey=HOTKEY_B,
                hardware="aa" * 32,
                measurement=TDX_OTHER,
            ),
            # no SEV-SNP policy: its measurement is recorded, never checked
            _receipt(
                box_id="snp", hotkey=HOTKEY_B, hardware="ab" * 32, tee_kind="sev_snp"
            ),
        ],
        policy=policy,
    )
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["listed"]["verdict"] == cs.ACCEPTED
    assert rows["listed"]["measurement_allowed"] is True
    assert rows["unlisted"]["verdict"] == "REFUSED"
    assert rows["unlisted"]["reason"] == cs.MEASUREMENT_REFUSED
    assert rows["unlisted"]["measurement_allowed"] is False
    assert rows["unlisted"]["evidence"]["measurement"] == TDX_OTHER
    assert rows["snp"]["verdict"] == cs.ACCEPTED
    assert rows["snp"]["measurement_allowed"] is None
    assert scored["refused"] == {cs.MEASUREMENT_REFUSED: 1}
    assert scored["units"] == [[3, TEE_6_24], [5, TEE_6_24]]
    doc = inv.update_inventory(None, scored["rows"], netuid=94, round_=7, now=NOW)
    assert doc["boxes"]["unlisted"]["status"] == inv.UNHEALTHY
    assert doc["boxes"]["unlisted"]["measurement_allowed"] is False


def test_an_unlisted_image_cannot_knock_out_an_admitted_box(tmp_path) -> None:
    pytest.importorskip("cathedral.capacity.admission")
    tdx = _measurement_policy(
        tmp_path,
        "tdx.json",
        schema=TDX_SCHEMA,
        mode="enforce",
        allowed=[TDX_MEASUREMENT],
    )
    scored = _score(
        [
            _receipt(box_id="victim"),
            _receipt(box_id="victim", hotkey=HOTKEY_B, measurement=TDX_OTHER),
        ],
        policy=_policy(measurement_policies=[tdx]),
    )
    assert scored["units"] == [[3, TEE_6_24]]
    assert scored["refused"] == {cs.MEASUREMENT_REFUSED: 1}


def test_a_shadow_measurement_policy_only_records(tmp_path) -> None:
    pytest.importorskip("cathedral.capacity.admission")
    tdx = _measurement_policy(
        tmp_path, "tdx.json", schema=TDX_SCHEMA, mode="shadow", allowed=[]
    )
    snp = _measurement_policy(
        tmp_path,
        "snp.json",
        schema=SNP_SCHEMA,
        mode="enforce",
        allowed=[SNP_MEASUREMENT],
    )
    policy = _policy(measurement_policies=[tdx, snp])
    scored = _score(
        [
            _receipt(),
            _receipt(
                box_id="snp", hotkey=HOTKEY_B, hardware="ab" * 32, tee_kind="sev_snp"
            ),
        ],
        policy=policy,
    )
    assert scored["accepted"] == 2 and scored["refused"] == {}
    rows = {row["box_id"]: row for row in scored["rows"]}
    assert rows["box-1"]["measurement_allowed"] is False
    assert rows["snp"]["measurement_allowed"] is True
    fetch = _feed([], lambda nonce: [_receipt(nonce=nonce)])
    record = cs.CapacityShadow(
        policy, fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})
    assert record["measurement_policies"] == {
        "sev_snp": {
            "mode": "enforce",
            "digest": policy.measurement_policies["sev_snp"].digest,
        },
        "tdx": {"mode": "shadow", "digest": policy.measurement_policies["tdx"].digest},
    }
    assert "measurement_policies" not in cs.CapacityShadow(
        _policy(), fetch=fetch, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY_A: 3})


def test_bad_measurement_policies_are_refused(tmp_path) -> None:
    pytest.importorskip("cathedral.capacity.admission")
    tdx = _measurement_policy(
        tmp_path,
        "tdx.json",
        schema=TDX_SCHEMA,
        mode="enforce",
        allowed=[TDX_MEASUREMENT],
    )
    again = _measurement_policy(
        tmp_path, "tdx2.json", schema=TDX_SCHEMA, mode="shadow", allowed=[]
    )
    empty = _measurement_policy(
        tmp_path, "empty.json", schema=TDX_SCHEMA, mode="enforce", allowed=[]
    )
    cases = [
        ([], "one or two"),
        ([tdx, again, tdx], "one or two"),
        (tdx, "one or two"),
        ([7], "one or two"),
        ([tdx, again], "two tdx policies"),
        ([empty], "at least one measurement"),
        ([str(tmp_path / "absent.json")], "unreadable"),
        (["relative.json"], "absolute"),
    ]
    for value, message in cases:
        with pytest.raises(cs.CapacityPolicyError, match=message):
            _policy(measurement_policies=value)
    os.chmod(tdx, 0o646)
    with pytest.raises(cs.CapacityPolicyError, match="world-writable"):
        _policy(measurement_policies=[tdx])


def test_measurement_policies_need_the_admission_module(tmp_path, monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def without_admission(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "cathedral.capacity" and "admission" in (fromlist or ()):
            raise ImportError("no admission module")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", without_admission)
    tdx = _measurement_policy(
        tmp_path, "tdx.json", schema=TDX_SCHEMA, mode="shadow", allowed=[]
    )
    with pytest.raises(cs.CapacityPolicyError, match="cathedral.capacity.admission"):
        _policy(measurement_policies=[tdx])
    assert _policy().measurement_policies == {}  # without the key nothing is needed
