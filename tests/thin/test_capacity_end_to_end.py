"""End to end: a TDX box is admitted, the prober signs a v2 receipt with the
admission's evidence, and the validator's shadow scoring values the box.

It runs the real cathedral-sandbox libraries (``cathedral.capacity.admission``,
``receipt``, ``pricing`` and ``cathedral.common.report_data_v2``). Only the
quote verification is faked: ``VerifiedAttestation`` holds what the pinned
verifier would have established. Skipped where the installed sandbox has no
admission module.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from cathedral_thin.independent_runtime import capacity_shadow as cs

admission = pytest.importorskip("cathedral.capacity.admission")
from cathedral.capacity import challenge as ch  # noqa: E402
from cathedral.capacity import pricing, receipt  # noqa: E402
from cathedral.channel import tls_spki_binding  # noqa: E402
from cathedral.common import report_data_v2  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
URL = "https://receipts.example/v1/capacity/receipts"
HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
MEASUREMENT = "tdx-measurement-sha256:" + "a1" * 32
VERIFIER = "sha256:" + "5e" * 32
PPID = bytes.fromhex("0123456789abcdef0123456789abcdef")
PROBER = Ed25519PrivateKey.generate()
OWNER = Ed25519PrivateKey.generate()
VCPUS, MEMORY_GIB = 8, 32
TEE_VALUE = VCPUS * 30_000 + MEMORY_GIB * 4_000


def _raw(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _certificate() -> bytes:
    """The box's TLS certificate, as the prober sees it in its own handshake."""

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "box.example")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def _stable_platform_id(ppid: bytes) -> str:
    # cmd/cathedral-tdx-verifier stablePlatformID: the verifier never emits the PPID.
    digest = hashlib.sha256(b"cathedral-tdx-platform-v1\x00" + ppid.hex().encode())
    return "tdx-platform-sha256:" + digest.hexdigest()


def _attestation(*, nonce: bytes, hotkey: str, certificate: bytes, quote: bytes):
    """What the prober's strict TDX verifier run established about one quote,
    whose REPORT_DATA binds the prober's nonce, the hotkey and the TLS key."""

    return admission.VerifiedAttestation(
        kind="tdx",
        measurement=MEASUREMENT,
        verifier_digest=VERIFIER,
        evidence_sha256=hashlib.sha256(quote).hexdigest(),
        report_data=report_data_v2(nonce, hotkey, tls_spki_binding(certificate)),
        stable_platform_id=_stable_platform_id(PPID),
    )


def _measurement_policy_file(tmp_path) -> str:
    # cathedral-validator #256's file format; the prober and validator share it.
    path = tmp_path / "tdx-measurement-policy.json"
    path.write_text(
        json.dumps(
            {
                "schema": "cathedral_tdx_measurement_policy_v1",
                "mode": "enforce",
                "allowed_measurements": [MEASUREMENT],
            }
        )
    )
    os.chmod(path, 0o640)
    return str(path)


def _prober_receipt(admitted, *, validator_nonce: str, round_: int) -> dict:
    """The prober's side: run the challenge (its outputs are stand-ins here)
    and sign a v2 receipt carrying the admission's evidence and hardware id."""

    seed = hashlib.sha256(b"round-seed").digest()
    spec = ch.spec_for(seed, vcpus=VCPUS, memory_gib=MEMORY_GIB)
    digest, sample_nonce = bytes([3]) * 32, bytes([7]) * 32
    count = ch.required_samples(spec.lanes)
    lanes = ch.sample_lanes(spec, digest, sample_nonce, count)
    deadline_ms = min(60_000, ch.max_deadline_ms(spec))
    evidence = admitted.evidence
    body = receipt.make_body(
        netuid=94,
        round=round_,
        validator_nonce=validator_nonce,
        box_id=admitted.box_id,
        miner_hotkey=admitted.miner_hotkey,
        kind="tee",
        tee_kind="tdx",
        hardware_id=admitted.hardware_id,
        vcpus=VCPUS,
        memory_gib=MEMORY_GIB,
        challenge=spec,
        result_digest=digest,
        sample_nonce=sample_nonce,
        sample_count=count,
        sampled_outputs={lane: bytes([lane % 256]) * 32 for lane in lanes},
        deadline_ms=deadline_ms,
        timings_ms={"create": 900, "exec": deadline_ms // 2, "delete": 300},
        issued_at=NOW,
        valid_for=timedelta(minutes=30),
        prober_key_id="sn94-prober-1",
        evidence=None if evidence is None else dataclasses.asdict(evidence),
    )
    return receipt.sign_receipt(body, PROBER)


def _capacity_policy(tmp_path, measurement_policy: str) -> cs.CapacityPolicy:
    table = pricing.sign_price_table(
        {
            "schema": pricing.SCHEMA,
            "currency": "usd",
            "rates": {
                "tee": {"vcpu_hour": 30_000, "gib_hour": 4_000},
                "bare_metal": {"vcpu_hour": 18_000, "gib_hour": 2_500},
            },
            "consumer_profiles": {"sn120": {"min_vcpus": 2, "min_memory_gib": 1}},
            "effective_from": "2026-09-28T00:00:00Z",
            "key_id": "sn94-owner-1",
            "sequence": 1,
        },
        OWNER,
    )
    document = {
        "schema": cs.POLICY_SCHEMA,
        "mode": "shadow",
        "receipts_url": URL,
        "prober_keys": {"sn94-prober-1": _raw(PROBER)},
        "price_keys": {"sn94-owner-1": _raw(OWNER)},
        "price_table": table,
        "recheck_max_mib": 0,
        "inventory_path": str(tmp_path / "capacity-inventory.json"),
        "measurement_policies": [measurement_policy],
    }
    return cs.parse_capacity_policy(json.dumps(document).encode(), now=NOW)


def test_an_admitted_tdx_box_is_valued_with_its_evidence(tmp_path) -> None:
    policy_file = _measurement_policy_file(tmp_path)
    with open(policy_file, "rb") as handle:
        measurement_policy = admission.parse_policy(handle.read())

    # 1. Admission: the prober verified the box's quote on the TLS connection
    #    that serves the sandbox API, for its own fresh nonce.
    certificate = _certificate()
    nonce = os.urandom(32)
    registry: dict[str, admission.AdmittedBox] = {}
    admitted = admission.admit(
        _attestation(
            nonce=nonce, hotkey=HOTKEY, certificate=certificate, quote=b"quote-1"
        ),
        box_id="tdx-box-1",
        miner_hotkey=HOTKEY,
        nonce=nonce,
        policy=measurement_policy,
        admitted=registry,
        tls_certificate_der=certificate,
    )
    assert admitted.admitted and admitted.reasons == ()
    assert admitted.hardware_id_kind == "tdx_platform"
    assert admitted.hardware_id == receipt.tdx_hardware_id(_stable_platform_id(PPID))
    evidence = dataclasses.asdict(admitted.evidence)
    assert evidence == {
        "evidence_kind": "tdx",
        "evidence_sha256": hashlib.sha256(b"quote-1").hexdigest(),
        "measurement": MEASUREMENT,
        "verifier_digest": VERIFIER,
        "tls_spki_sha256": tls_spki_binding(certificate).digest.hex(),
    }
    registry[admitted.hardware_id] = admission.AdmittedBox("tdx-box-1", HOTKEY)

    # 2. The prober serves this validator's receipts through the feed, each
    #    signed for the nonce the validator put in its request.
    urls: list[str] = []

    def feed(url: str) -> bytes:
        urls.append(url)
        netuid, validator_nonce = url.rsplit("/", 2)[1:]
        return json.dumps(
            {
                "schema": cs.FEED_SCHEMA,
                "netuid": int(netuid),
                "round": 11,
                "validator_nonce": validator_nonce,
                "receipts": [
                    _prober_receipt(
                        admitted, validator_nonce=validator_nonce, round_=11
                    )
                ],
            }
        ).encode()

    # 3. The validator scores it: valued at the TEE rate, evidence recorded.
    policy = _capacity_policy(tmp_path, policy_file)
    record = cs.CapacityShadow(
        policy, fetch=feed, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY: 3})
    assert record["status"] == "RECORDED", record
    assert urls[0].startswith(URL + "/94/")
    assert record["accepted"] == 1 and record["refused"] == {}
    assert record["units"] == [[3, TEE_VALUE]]
    [row] = record["rows"]
    assert (
        row["box_id"] == "tdx-box-1"
        and row["kind"] == "tee"
        and row["tee_kind"] == "tdx"
    )
    assert row["hardware_id"] == admitted.hardware_id
    assert row["value"] == TEE_VALUE
    assert row["evidence"] == evidence
    assert row["measurement_allowed"] is True
    assert record["measurement_policies"] == {
        "tdx": {"mode": "enforce", "digest": measurement_policy.digest}
    }
    assert record["inventory"]["status"] == "WRITTEN"
    stored = json.loads((tmp_path / "capacity-inventory.json").read_text())
    assert stored["boxes"]["tdx-box-1"]["status"] == "healthy"
    assert stored["boxes"]["tdx-box-1"]["evidence"] == evidence

    # 4. The same host presented as another box (another hotkey, its own TLS
    #    key and a correctly bound quote) is refused at admission, so it gets
    #    no evidence and the prober cannot sign a receipt for it.
    other_certificate = _certificate()
    other_nonce = os.urandom(32)
    second = admission.admit(
        _attestation(
            nonce=other_nonce,
            hotkey=OTHER_HOTKEY,
            certificate=other_certificate,
            quote=b"quote-2",
        ),
        box_id="tdx-box-2",
        miner_hotkey=OTHER_HOTKEY,
        nonce=other_nonce,
        policy=measurement_policy,
        admitted=registry,
        tls_certificate_der=other_certificate,
    )
    assert not second.admitted
    assert second.reasons == (admission.HARDWARE_ID_CLAIMED,)
    assert second.hardware_id == admitted.hardware_id and second.evidence is None
    with pytest.raises(receipt.ReceiptError, match="evidence must have exactly"):
        _prober_receipt(second, validator_nonce="cd" * 32, round_=11)

    # A quote made for the first box does not admit it under another hotkey either.
    replay = admission.admit(
        _attestation(
            nonce=nonce, hotkey=HOTKEY, certificate=certificate, quote=b"quote-1"
        ),
        box_id="tdx-box-1",
        miner_hotkey=OTHER_HOTKEY,
        nonce=nonce,
        policy=measurement_policy,
        admitted={},
        tls_certificate_der=certificate,
    )
    assert admission.REPORT_DATA_MISMATCH in replay.reasons and replay.evidence is None
