"""End to end: a TDX box is admitted, the prober signs a v2 receipt with the
admission's evidence, and the validator's shadow scoring values the box.

It runs the real cathedral-sandbox libraries (``cathedral.capacity.admission``,
``receipt``, ``pricing``, ``cathedral.common.report_data_v2`` and the TDX quote
parser). Only the quote's signature check is skipped: the quote is laid out as
a real TDX v4 quote, and ``Attested`` is the verdict the pinned strict verifier
would return for it. Admission reads REPORT_DATA and the measurement from the
quote bytes itself. Skipped where the installed sandbox has no admission module
taking the verifier's verdict.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import inspect
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
if "attested" not in inspect.signature(admission.admit).parameters:
    pytest.skip(
        "the installed cathedral-sandbox admission predates the verifier verdict API",
        allow_module_level=True,
    )
from cathedral.capacity import challenge as ch  # noqa: E402
from cathedral.capacity import pricing, receipt  # noqa: E402
from cathedral.channel import tls_spki_binding  # noqa: E402
from cathedral.common import Attested, Tier, report_data_v2  # noqa: E402
from cathedral.verify.tdx_quote import parse_tdx_quote  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
ATTESTED_AT = NOW - timedelta(minutes=5)  # admission, before the round's receipt
URL = "https://receipts.example/v1/capacity/receipts"
HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
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


def _tdx_quote(report_data: bytes, mr_td: bytes = b"M" * 48) -> bytes:
    """A TDX v4 quote laid out as the pinned verifier's parser reads it
    (cathedral-sandbox tests/tdx_quote_fixtures.py, synthetic_tdx_quote),
    with a PCK chain placeholder in place of a real signature. Debug is off."""

    header = bytearray(48)
    header[0:2] = (4).to_bytes(2, "little")  # version 4
    header[2:4] = (2).to_bytes(2, "little")  # ECDSA-256 attestation key
    header[4:8] = (0x81).to_bytes(4, "little")  # TDX
    header[8:12] = (1).to_bytes(2, "little") + (2).to_bytes(2, "little")
    header[12:48] = b"VENDOR-ID-123456" + b"cathedral-user-data!"
    body = bytearray(584)  # the TD report body
    body[0:16] = bytes(range(16))  # TEE_TCB_SVN
    body[16:112] = b"S" * 48 + b"s" * 48  # MRSEAM, MRSIGNERSEAM
    body[112:136] = b"A" * 8 + b"T" * 8 + b"X" * 8  # SEAM and TD attributes, XFAM
    body[136:184] = mr_td
    # MRCONFIGID, MROWNER, MROWNERCONFIG, RTMR0-3
    body[184:520] = b"".join(bytes([char]) * 48 for char in b"COo0123")
    body[520:584] = report_data
    pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(b"synthetic-pck-leaf-cert")
        + b"\n-----END CERTIFICATE-----\n"
    )
    certification = b"prefix" + pem + b"suffix"
    signature = (
        b"Q" * 64  # the quote signature
        + hashlib.sha512(b"cathedral-ak").digest()  # the attestation key
        + (6).to_bytes(2, "little")  # PCK certificate chain
        + len(certification).to_bytes(4, "little")
        + certification
    )
    return bytes(header + body) + len(signature).to_bytes(4, "little") + signature


def _quote(*, nonce: bytes, hotkey: str, certificate: bytes, **changes) -> bytes:
    """The box's quote, whose REPORT_DATA binds the prober's nonce, the hotkey
    and the TLS key (report_data_v2)."""

    report_data = report_data_v2(nonce, hotkey, tls_spki_binding(certificate))
    return _tdx_quote(report_data, **changes)


MEASUREMENT = parse_tdx_quote(_tdx_quote(bytes(64))).measurement


def _verdict(quote: bytes, **changes) -> Attested:
    """The pinned strict TDX verifier's verdict for ``quote``, as
    cathedral.verify returns it: fully verified, with the platform's
    stable_platform_id as its chip_id."""

    verdict = Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=_stable_platform_id(PPID),
        measurement=parse_tdx_quote(quote).measurement,
        tcb=0,
        verification_status="VERIFIED",
        chain_verified=True,
        tcb_status="UpToDate",
        debug_enabled=False,
        collateral_current=True,
        platform_identity_kind="stable",
        policy_mode="strict",
    )
    return dataclasses.replace(verdict, **changes)


def _admit(quote: bytes, verdict: Attested | None = None, **arguments):
    return admission.admit(
        _verdict(quote) if verdict is None else verdict,
        quote,
        verifier_digest=VERIFIER,
        attested_at=ATTESTED_AT,
        **arguments,
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


def _capacity_policy(tmp_path, measurement_policy: str, **changes) -> cs.CapacityPolicy:
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
        **changes,
    }
    return cs.parse_capacity_policy(json.dumps(document).encode(), now=NOW)


def test_an_admitted_tdx_box_is_valued_with_its_evidence(tmp_path) -> None:
    policy_file = _measurement_policy_file(tmp_path)
    with open(policy_file, "rb") as handle:
        measurement_policy = admission.parse_policy(handle.read())

    # 1. Admission: the prober verified the box's quote on the TLS connection
    #    that serves the sandbox API, for its own fresh nonce, and hands
    #    admission the verifier's verdict with the quote bytes.
    certificate = _certificate()
    nonce = os.urandom(32)
    quote = _quote(nonce=nonce, hotkey=HOTKEY, certificate=certificate)
    registry: dict[str, admission.AdmittedBox] = {}
    arguments = {
        "box_id": "tdx-box-1",
        "miner_hotkey": HOTKEY,
        "nonce": nonce,
        "policy": measurement_policy,
        "admitted": registry,
        "tls_certificate_der": certificate,
    }
    admitted = _admit(quote, **arguments)
    assert admitted.admitted and admitted.reasons == ()
    assert admitted.hardware_id_kind == "tdx_platform"
    assert admitted.hardware_id == receipt.tdx_hardware_id(_stable_platform_id(PPID))
    evidence = dataclasses.asdict(admitted.evidence)
    assert evidence == {
        "evidence_kind": "tdx",
        "evidence_sha256": hashlib.sha256(quote).hexdigest(),
        "measurement": MEASUREMENT,
        "verifier_digest": VERIFIER,
        "tls_spki_sha256": tls_spki_binding(certificate).digest.hex(),
        "attestation_nonce": nonce.hex(),
        "attested_at": "2026-09-28T11:55:00Z",
    }
    # A partial verification of the same quote gets no evidence.
    for partial in (
        _verdict(quote, chain_verified=False),
        _verdict(quote, policy_mode="compatibility"),
        _verdict(quote, verification_status="STRUCTURE_OK_CHAIN_UNVERIFIED"),
    ):
        refused = _admit(quote, partial, **arguments)
        assert refused.reasons == (admission.VERIFICATION_INCOMPLETE,)
        assert refused.evidence is None
    registry[admitted.hardware_id] = admission.AdmittedBox("tdx-box-1", HOTKEY)

    # 2. The prober serves this validator's receipts through the feed, each
    #    signed for the nonce the validator put in its request.
    urls: list[str] = []
    signed: list[dict] = []

    def feed(url: str) -> bytes:
        urls.append(url)
        netuid, validator_nonce = url.rsplit("/", 2)[1:]
        signed.append(
            _prober_receipt(admitted, validator_nonce=validator_nonce, round_=11)
        )
        return json.dumps(
            {
                "schema": cs.FEED_SCHEMA,
                "netuid": int(netuid),
                "round": 11,
                "validator_nonce": validator_nonce,
                "receipts": [signed[-1]],
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

    # An auditor holding the archived quote ties the receipt to it end to end.
    verified = receipt.verify_receipt(
        signed[0],
        prober_keys=policy.prober_keys,
        netuid=94,
        validator_nonce=urls[0].rsplit("/", 1)[1],
        now=NOW + timedelta(minutes=1),
        expected_round=11,
    )
    assert hashlib.sha256(quote).hexdigest() == verified.evidence.evidence_sha256
    assert receipt.expected_report_data(verified) == parse_tdx_quote(quote).report_data

    # A validator bounding evidence age tighter than the six minutes since
    # admission refuses the same receipt.
    strict = _capacity_policy(tmp_path, policy_file, max_evidence_age_seconds=300)
    record = cs.CapacityShadow(
        strict, fetch=feed, now=lambda: NOW + timedelta(minutes=1)
    ).record(netuid=94, hotkey_to_uid={HOTKEY: 3})
    assert record["accepted"] == 0
    assert record["refused"] == {
        "the receipt's evidence is older than max_evidence_age": 1
    }

    # 4. The same host presented as another box (another hotkey, its own TLS
    #    key and a correctly bound quote) is refused at admission, so it gets
    #    no evidence and the prober cannot sign a receipt for it.
    other_certificate = _certificate()
    other_nonce = os.urandom(32)
    second = _admit(
        _quote(nonce=other_nonce, hotkey=OTHER_HOTKEY, certificate=other_certificate),
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
    replay = _admit(
        quote, **{**arguments, "miner_hotkey": OTHER_HOTKEY, "admitted": {}}
    )
    assert admission.REPORT_DATA_MISMATCH in replay.reasons and replay.evidence is None

    # A shadow admission policy records a box running an unlisted image but
    # gives it no evidence, so it is never paid.
    shadow_policy = admission.parse_policy(
        json.dumps(
            {
                "schema": "cathedral_tdx_measurement_policy_v1",
                "mode": "shadow",
                "allowed_measurements": [MEASUREMENT],
            }
        ).encode()
    )
    unlisted = _admit(
        _quote(nonce=nonce, hotkey=HOTKEY, certificate=certificate, mr_td=b"N" * 48),
        **{**arguments, "policy": shadow_policy, "admitted": {}},
    )
    assert unlisted.admitted and unlisted.measurement_allowed is False
    assert unlisted.evidence is None
