"""Synthetic evidence/CUDA only; real worker TLS and direct-validator HTTP transport."""
# Optional GPU dependency must be present before importing its protocol.
# ruff: noqa: E402
import pytest
pytest.importorskip("cathedral.gpu_work")

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import socket
import threading
import ssl
import ipaddress
from bittensor_wallet import Keypair
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from cathedral.channel import tls_spki_binding
from cathedral.policy_registry import canonical_json

import cathedral.validator_access as access
from cathedral.common import ChannelBinding, ChannelBindingType, Evidence, EvidenceKind
from cathedral.gpu_work import CudaWorkExecutor, expected_output_digest, parse_composite
from cathedral.validator_access import (ValidatorAccessState, ValidatorRequestAuthorizer, load_sr25519_verifier,
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA, sign_validator_access_snapshot, verify_validator_access_snapshot)
from cathedral.worker import WorkerServer
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.gpu_qualification import GpuPrelaunchConfig, qualify_gpu_round, direct_gpu_plan
import cathedral_thin.independent_runtime.validator_request as validator_request
import cathedral_thin.independent.fetch_policy as fetch_policy


ALICE = Keypair.create_from_uri("//Alice")
BOB = Keypair.create_from_uri("//Bob")


def tls_context(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256()))
    certificate_path, private_path = tmp_path / "worker.crt", tmp_path / "worker.key"
    certificate_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, private_path)
    return context, tls_spki_binding(cert.public_bytes(serialization.Encoding.DER))


def access_snapshot(now):
    seed = b"s" * 32
    document = {"schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA, "network": "test", "netuid": 123,
        "block": 123, "block_hash": "0x" + "a" * 64, "block_is_finalized": True,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": 1000, "validators": [{"hotkey": ALICE.ss58_address,
            "uid": 30, "validator_permit": True, "stake_rao": 2000}],
        "signing_key_id": "test-access"}
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return verify_validator_access_snapshot(canonical_json(sign_validator_access_snapshot(document, seed)),
        {"test-access": public}, network="test", netuid=123, required_minimum_stake_rao=1000, now=now)


def test_crossrepo_signed_gpu_over_real_tls(tmp_path, monkeypatch):
    monkeypatch.setattr(access, "is_globally_routable", lambda _a: True)
    monkeypatch.setattr(fetch_policy, "is_globally_routable_address", lambda _a: True)
    monkeypatch.setattr(validator_request, "is_globally_routable_address", lambda _a: True)
    tls, binding = tls_context(tmp_path)
    now = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        access_snapshot(now),
        worker_hotkey=BOB.ss58_address, channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    executor = CudaWorkExecutor("test-h100", ("GPU-11111111-1111-4111-8111-111111111111",))
    monkeypatch.setattr(executor, "execute", expected_output_digest)
    def collector(nonce, hotkey, **kwargs):
        return tuple(Evidence(kind=k, quote=b"SYNTHETIC-NOT-HARDWARE", nonce=nonce,
                              miner_hotkey=hotkey, report_data_version=2,
                              channel_binding=kwargs["channel_binding"])
                     for k in (EvidenceKind.TDX, EvidenceKind.GPU_CC))
    class Verifier:
        profiles = {"test-h100": SimpleNamespace(expected_device_identity_digests=executor.device_identity_digests)}
        registry_digest = "sha256:" + "f" * 64
        nonces = []
        def verify(self, components, nonce, hotkey, binding, profile_id):
            parse_composite(components, nonce, hotkey, ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, binding))
            self.nonces.append(nonce)
            return {"device_identity_digests": executor.device_identity_digests,
                    "machine_id": "SYNTHETIC-ONLY", "component_digest": "sha256:" + "e" * 64}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with WorkerServer(port=port, configured_hotkey=BOB.ss58_address, channel_binding=binding,
        tls_context=tls, validator_authorizer=authorizer, fleet_endpoints=(f"https://127.0.0.1:{port}",),
        gpu_executor=executor, gpu_evidence_collector=collector) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        config = GpuPrelaunchConfig("test", 123, ALICE.ss58_address, 1,
            str(tmp_path / "registry.json"), {}, 1, str(tmp_path / "registry.sqlite"), ("test-h100",))
        signer = SimpleNamespace(ss58_address=ALICE.ss58_address,
                                 sign=ALICE.sign)
        verifier = Verifier()
        miners = [ServingAxon(1, BOB.ss58_address, "127.0.0.1", port)]
        result = qualify_gpu_round(miners, config=config, keypair=signer, verifier=verifier)
        assert result.rows[0]["eligible"] is True, result.rows
        assert len(verifier.nonces) == 2 and verifier.nonces[0] != verifier.nonces[1]
        plan = direct_gpu_plan(result, config, miners)
        assert plan["raw_scores"] == [[1, 1]]
        assert plan["chain_write"] is False
