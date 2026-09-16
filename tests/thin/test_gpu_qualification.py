"""Protocol tests use explicit hardware-free doubles, never hardware proof."""

# Optional GPU dependency is checked before importing its protocol.
# ruff: noqa: E402
from __future__ import annotations
import base64
from dataclasses import replace
import json
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest

pytest.importorskip("cathedral.gpu_work")
from bittensor_wallet import Keypair
from cathedral_thin.independent.collect import ChannelBinding
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.gpu_qualification import (
    AccessRequestSigner,
    GpuPrelaunchConfig,
    GpuRound,
    ProductionGpuVerifier,
    atomic_json,
    direct_gpu_plan,
    provider_directory,
    qualify_gpu_round,
)
from cathedral.gpu_work import expected_output_digest, request_digest, completion_nonce

DEVICE = "sha256:" + "1" * 64
ALICE = Keypair.create_from_uri("//Alice")
BOB = Keypair.create_from_uri("//Bob")
CHARLIE = Keypair.create_from_uri("//Charlie")


@pytest.fixture
def config(tmp_path):
    return GpuPrelaunchConfig(
        "test",
        123,
        ALICE.ss58_address,
        2,
        str(tmp_path / "registry.json"),
        {"root": b"r" * 32},
        1,
        str(tmp_path / "registry.sqlite"),
        ("test-profile",),
    )


class HardwareFreeVerifier:
    registry_digest = "sha256:" + "b" * 64
    profiles = {
        "test-profile": SimpleNamespace(
            profile_id="test-profile",
            expected_device_identity_digests={DEVICE},
            allowed_models={"test-device"},
        )
    }

    def __init__(self, change_completion=False):
        self.nonces = []
        self.change_completion = change_completion

    def verify(self, components, nonce, hotkey, binding, profile_id):
        # Double checks protocol freshness/binding. No cryptographic verification.
        assert components == [
            {"nonce": nonce.hex(), "hotkey": hotkey, "binding": binding.hex()}
        ]
        self.nonces.append(nonce)
        return {
            "device_identity_digests": (DEVICE,),
            "machine_id": "changed"
            if self.change_completion and len(self.nonces) > 1
            else "machine",
            "component_digest": "sha256:" + "a" * 64,
        }


class HardwareFreeHttps(HttpsEvidenceTransport):
    calls = []
    wrong_output = False

    def observe_binding(self, url):
        self.last_spki = bytes([1 if "1.1.1.1" in url else 2]) * 32
        return ChannelBinding("tls_spki_sha256", self.last_spki)

    def post_authorized(self, url, body, authorization):
        self.observe_binding(url)
        auth = json.loads(base64.b64decode(authorization))
        assert auth["network"] == "test" and auth["netuid"] == 123
        assert auth["path"] == urlsplit(url).path
        self.calls.append(auth["path"])
        hotkey = auth["worker_hotkey"]

        def evidence(nonce):
            return [{"nonce": nonce, "hotkey": hotkey, "binding": self.last_spki.hex()}]

        path = auth["path"]
        if path == "/v1/fleet":
            answer = {
                "schema": "cathedral_worker_fleet_v1",
                "worker_hotkey": hotkey,
                "endpoints": [url.rsplit("/", 2)[0]],
            }
        elif path == "/v1/gpu-capabilities":
            answer = {
                "schema": "cathedral_gpu_capability_v1",
                "profile_id": "test-profile",
                "device_identity_digests": [DEVICE],
                "workload_id": "cuda_i32_vector_v1",
                "elements": 4096,
                "status": "registered",
                "verified": False,
            }
        elif path == "/v1/gpu-evidence":
            answer = {
                "schema": "cathedral_gpu_evidence_v1",
                "evidence": evidence(body["nonce_hex"]),
            }
        else:
            output = expected_output_digest(body)
            answer = {
                "schema": "cathedral_gpu_result_v1",
                "request_digest": request_digest(body),
                "output_digest": "sha256:" + "f" * 64 if self.wrong_output else output,
                "device_identity_digests": [DEVICE],
                "completion_evidence": evidence(completion_nonce(body, output).hex()),
            }
        return 200, json.dumps(answer).encode()


@pytest.fixture
def miner():
    return ServingAxon(1, BOB.ss58_address, "1.1.1.1", 443)


@pytest.fixture(autouse=True)
def reset_double():
    HardwareFreeHttps.calls = []
    HardwareFreeHttps.wrong_output = False


def qualify(config, miners, verifier=None):
    return qualify_gpu_round(
        miners,
        config=config,
        keypair=ALICE,
        verifier=verifier or HardwareFreeVerifier(),
        transport_factory=HardwareFreeHttps,
    )


def test_fresh_completion_signed_access_and_explicit_test_plan(config, miner):
    verifier = HardwareFreeVerifier()
    result = qualify(config, [miner], verifier)
    assert result.rows[0]["eligible"] is True
    assert len(verifier.nonces) == 2 and verifier.nonces[0] != verifier.nonces[1]
    assert HardwareFreeHttps.calls == [
        "/v1/fleet",
        "/v1/gpu-capabilities",
        "/v1/gpu-evidence",
        "/v1/gpu-work",
    ]
    plan = direct_gpu_plan(result, config, [miner])
    assert plan["raw_scores"] == [[1, 2]] and plan["weights"] == [65535]
    assert plan["chain_write"] is False and plan["prelaunch_only"] is True
    assert "kwargs" not in plan and "call" not in plan
    directory = provider_directory(result, config, verifier)
    assert directory["providers"][0]["eligible"] is False
    assert directory["providers"][0]["reason"] == "verified_work_prelaunch"
    text = json.dumps(directory)
    assert "1.1.1.1" not in text and "channel_id" not in text and DEVICE not in text


def test_same_gpu_under_two_hotkeys_zeros_both_before_work(config, miner):
    other = ServingAxon(2, CHARLIE.ss58_address, "8.8.8.8", 443)
    result = qualify(config, [miner, other])
    assert len(result.rows) == 2
    assert all(
        row["eligible"] is False and row["reason"] == "duplicate_gpu_or_channel"
        for row in result.rows
    )
    assert "/v1/gpu-work" not in HardwareFreeHttps.calls
    assert direct_gpu_plan(result, config, [miner, other])["uids"] == []


@pytest.mark.parametrize("failure", ["output", "identity"])
def test_no_positive_units_for_bad_work_or_changed_completion(config, miner, failure):
    HardwareFreeHttps.wrong_output = failure == "output"
    result = qualify(
        config, [miner], HardwareFreeVerifier(change_completion=failure == "identity")
    )
    assert result.rows[0]["verified"] is True and result.rows[0]["eligible"] is False
    assert direct_gpu_plan(result, config, [miner])["weights"] == []


def test_duplicate_positive_rows_cannot_enter_plan(config, miner):
    result = qualify(config, [miner])
    with pytest.raises(IndependentLiveError, match="invalid identity"):
        direct_gpu_plan(
            replace(result, rows=result.rows + result.rows), config, [miner]
        )


def test_no_backend_cannot_be_qualified(config):
    with pytest.raises(FileNotFoundError):
        ProductionGpuVerifier(config)


def test_request_signer_refuses_chain_payload_without_invoking_executable(config):
    signer = AccessRequestSigner("/usr/bin/false", config)
    with pytest.raises(Exception):
        signer.sign(b'{"call":"set_weights"}')


def test_config_requires_explicit_enabled_and_conversion(config, tmp_path):
    path = tmp_path / "config.json"
    data = {
        "schema": "cathedral_gpu_prelaunch_v1",
        "enabled": True,
        "network": "test",
        "netuid": 123,
        "validator_hotkey": ALICE.ss58_address,
        "units_per_device": 1,
        "registry_path": config.registry_path,
        "trusted_keys_hex": {"root": "72" * 32},
        "minimum_registry_release": 1,
        "registry_state_path": config.registry_state_path,
        "profile_ids": ["test-profile"],
    }
    path.write_text(json.dumps(data))
    assert GpuPrelaunchConfig.load(path).units_per_device == 1
    for key, value in [
        ("enabled", False),
        ("units_per_device", True),
        ("netuid", True),
    ]:
        path.write_text(json.dumps({**data, key: value}))
        with pytest.raises(IndependentLiveError):
            GpuPrelaunchConfig.load(path)


def test_atomic_directory_replacement(tmp_path):
    path = tmp_path / "directory.json"
    atomic_json(path, {"old": True})
    atomic_json(path, {"new": True})
    assert json.loads(path.read_text()) == {"new": True}
    assert list(tmp_path.iterdir()) == [path]


def test_listing_aggregates_workers_and_keeps_admission_proof_on_work_failure(
    config, miner
):
    HardwareFreeHttps.wrong_output = True
    verifier = HardwareFreeVerifier()
    result = qualify(config, [miner], verifier)
    directory = provider_directory(
        replace(result, rows=result.rows + result.rows), config, verifier
    )
    assert len(directory["providers"]) == 1
    provider = directory["providers"][0]
    assert provider["verified"] is True and provider["eligible"] is False
    assert provider["evidence_digest"].startswith("sha256:") and provider["verified_at"]
    assert provider["reason"] == "verified_admission_work_failed"


def test_unknown_fleet_cannot_publish_empty_inventory(config):
    result = GpuRound(
        ({"uid": 9, "profile_id": None, "reason": "fleet_unavailable"},),
        "now",
        "sha256:" + "b" * 64,
    )
    document = provider_directory(result, config, HardwareFreeVerifier())
    assert document["schema"] == "cathedral.gpu.providers.v1"
    assert document["discovery"] == {"complete": False, "failed_miners": 1}
    assert document["providers"] == []


def g4_rows(miner, count=8):
    from cathedral_thin.independent_runtime.gpu_qualification import (
        G4_WORKER_PROFILE_ID,
    )

    return [
        {
            "uid": miner.uid,
            "hotkey": miner.hotkey,
            "profile_id": G4_WORKER_PROFILE_ID,
            "verified": True,
            "eligible": True,
            "reason": "verified_work",
            "gpu_count": 1,
            "device_identity_digests": (f"sha256:{index:064x}",),
            "declared_device_identity_digests": (f"sha256:{index:064x}",),
            "provider_instance_id": f"project/zone/{index}",
            "worker_key_digest": f"sha256:{index:064x}",
            "endpoint": f"https://8.8.8.{index}:443",
            "channel_id": f"{index:064x}",
            "evidence_digest": "sha256:" + "e" * 64,
            "admission_digest": "sha256:" + "a" * 64,
            "verified_at": "2026-09-16T00:00:00Z",
        }
        for index in range(1, count + 1)
    ]


@pytest.mark.parametrize("count,expected", [(7, []), (8, [[1, 16]]), (9, [])])
def test_g4_requires_exactly_eight_independent_devices(config, miner, count, expected):
    result = GpuRound(tuple(g4_rows(miner, count)), "now", "sha256:" + "a" * 64)
    plan = direct_gpu_plan(result, config, [miner])
    assert [row for row in plan["raw_scores"] if row[1]] == expected


def test_g4_repeated_instance_and_mixed_hotkeys_do_not_form_bundle(config, miner):
    rows = g4_rows(miner)
    rows[-1]["provider_instance_id"] = rows[0]["provider_instance_id"]
    result = GpuRound(tuple(rows), "now", "sha256:" + "a" * 64)
    assert direct_gpu_plan(result, config, [miner])["weights"] == []
    rows = g4_rows(miner)
    other = ServingAxon(2, CHARLIE.ss58_address, "8.8.8.8", 443)
    rows[-1].update(uid=other.uid, hotkey=other.hotkey)
    assert (
        direct_gpu_plan(replace(result, rows=tuple(rows)), config, [miner, other])[
            "weights"
        ]
        == []
    )


def test_g4_public_directory_reports_partial_without_host_attestation_claim(
    config, miner
):
    from cathedral_thin.independent_runtime.gpu_qualification import (
        G4_WORKER_PROFILE_ID,
        G4_BUNDLE_PROFILE_ID,
    )

    verifier = SimpleNamespace(
        profiles={
            G4_WORKER_PROFILE_ID: SimpleNamespace(
                profile_id=G4_WORKER_PROFILE_ID,
                expected_device_identity_digests=(),
                allowed_models={"NVIDIA RTX PRO 6000 Blackwell Server Edition"},
            )
        }
    )
    result = GpuRound(tuple(g4_rows(miner, 7)), "now", "sha256:" + "a" * 64)
    directory = provider_directory(result, config, verifier)
    assert directory["profiles"][0]["id"] == G4_BUNDLE_PROFILE_ID
    assert directory["profiles"][0]["gpu_count"] == 8
    assert directory["profiles"][0]["cpu_tee"] == "amd_sev"
    assert directory["providers"][0]["gpu_count"] == 7
    assert directory["providers"][0]["verified"] is False
    assert directory["providers"][0]["eligible"] is False


def test_g4_config_embeds_explicit_operator_roots_and_cannot_select_tdx_verifier(
    tmp_path,
):
    path = tmp_path / "g4.json"
    path.write_text(
        json.dumps(
            {
                "schema": "cathedral_gpu_g4_prelaunch_v1",
                "enabled": True,
                "network": "test",
                "netuid": 123,
                "validator_hotkey": ALICE.ss58_address,
                "units_per_device": 1,
                "trusted_operators_hex": {"operator": "72" * 32},
            }
        )
    )
    config = GpuPrelaunchConfig.load(path)
    assert config.trusted_operators == {"operator": b"r" * 32}
    with pytest.raises(IndependentLiveError, match="distinct"):
        ProductionGpuVerifier(config)


def test_g4_requires_eight_distinct_worker_signing_keys(config, miner):
    rows = g4_rows(miner)
    rows[-1]["worker_key_digest"] = rows[0]["worker_key_digest"]
    result = GpuRound(tuple(rows), "now", "sha256:" + "a" * 64)
    assert direct_gpu_plan(result, config, [miner])["weights"] == []


def test_real_g4_signatures_bind_eight_instance_work_bundle(config, miner):
    """Real Ed25519 verification; synthetic local NVIDIA log and CUDA output."""
    import hashlib
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cathedral.gpu import gpu_identity_policy_digest
    from cathedral.gpu_work import canonical
    from cathedral.gpu_provider import (
        G4ProviderVerifier,
        G4_WORKER_PROFILE_ID,
        ENDORSEMENT_SCHEMA,
        STATEMENT_SCHEMA,
        MODEL,
        sign_endorsement,
    )

    operator = Ed25519PrivateKey.generate()
    public = operator.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    config = replace(
        config,
        trusted_operators={"approved": public},
        profile_ids=(G4_WORKER_PROFILE_ID,),
    )
    miner = replace(miner, ip="8.8.8.1")
    endpoints = [f"https://8.8.8.{i}:443" for i in range(1, 9)]
    private = {endpoint: Ed25519PrivateKey.generate() for endpoint in endpoints}
    uuids = {
        endpoint: f"GPU-00000000-0000-4000-8000-{i:012x}"
        for i, endpoint in enumerate(endpoints, 1)
    }
    logs = b"SYNTHETIC TEST ONLY: GPU Attestation is Successful."

    class G4Https(HttpsEvidenceTransport):
        def observe_binding(self, url):
            origin = url.rsplit("/", 2)[0]
            self.last_spki = hashlib.sha256(origin.encode()).digest()
            return ChannelBinding("tls_spki_sha256", self.last_spki)

        def post_authorized(self, url, body, authorization):
            self.observe_binding(url)
            origin = url.rsplit("/", 2)[0]
            auth = json.loads(base64.b64decode(authorization))
            assert auth["network"] == "test" and auth["netuid"] == 123
            path = urlsplit(url).path
            if path == "/v1/fleet":
                answer = {
                    "schema": "cathedral_worker_fleet_v1",
                    "worker_hotkey": miner.hotkey,
                    "endpoints": endpoints,
                }
            elif path == "/v1/gpu-capabilities":
                answer = {
                    "schema": "cathedral_gpu_capability_v1",
                    "profile_id": G4_WORKER_PROFILE_ID,
                    "device_identity_digests": [
                        gpu_identity_policy_digest(uuids[origin])
                    ],
                    "workload_id": "cuda_i32_vector_v1",
                    "elements": 4096,
                    "status": "registered",
                    "verified": False,
                }
            else:

                def evidence(nonce):
                    now = int(time.time())
                    claims = {
                        "schema": ENDORSEMENT_SCHEMA,
                        "profile_id": G4_WORKER_PROFILE_ID,
                        "provider_instance_id": f"projects/123/zones/us-central1-a/instances/{endpoints.index(origin) + 1}",
                        "hotkey": miner.hotkey,
                        "machine_type": "g4-standard-48",
                        "provisioning_model": "SPOT",
                        "confidential_compute_type": "SEV",
                        "cpu_attestation": "unattested",
                        "guest_control": "approved_operator",
                        "private_customer_work": False,
                        "image_digest": "sha256:" + "a" * 64,
                        "worker_public_key_hex": private[origin]
                        .public_key()
                        .public_bytes(Encoding.Raw, PublicFormat.Raw)
                        .hex(),
                        "tls_spki_sha256": self.last_spki.hex(),
                        "gpu_uuid": uuids[origin],
                        "issued_at": now - 10,
                        "expires_at": now + 300,
                    }
                    endorsed = sign_endorsement(claims, "approved", operator)
                    statement = {
                        "schema": STATEMENT_SCHEMA,
                        "endorsement_digest": "sha256:"
                        + hashlib.sha256(canonical(endorsed)).hexdigest(),
                        "nonce_hex": nonce.hex(),
                        "hotkey": miner.hotkey,
                        "tls_spki_sha256": self.last_spki.hex(),
                        "issued_at": now,
                        "gpu_uuid": uuids[origin],
                        "gpu_model": MODEL,
                        "cc_mode": "ON",
                        "ready_state": "ready",
                        "verifier": "nv-local-gpu-verifier",
                        "verifier_version": "2.7.3",
                        "verifier_log_b64": base64.b64encode(logs).decode(),
                        "verifier_log_digest": "sha256:"
                        + hashlib.sha256(logs).hexdigest(),
                    }
                    return {
                        "endorsement": endorsed,
                        "statement": statement,
                        "signature_hex": private[origin]
                        .sign(STATEMENT_SCHEMA.encode() + b"\0" + canonical(statement))
                        .hex(),
                    }

                if path == "/v1/gpu-evidence":
                    answer = {
                        "schema": "cathedral_gpu_provider_evidence_v1",
                        "evidence": evidence(bytes.fromhex(body["nonce_hex"])),
                    }
                else:
                    output = expected_output_digest(body)
                    answer = {
                        "schema": "cathedral_gpu_result_v1",
                        "request_digest": request_digest(body),
                        "output_digest": output,
                        "device_identity_digests": body["device_identity_digests"],
                        "completion_evidence": evidence(completion_nonce(body, output)),
                    }
            return 200, json.dumps(answer).encode()

    verifier = G4ProviderVerifier({"approved": public})
    result = qualify_gpu_round(
        [miner],
        config=config,
        keypair=ALICE,
        verifier=verifier,
        transport_factory=G4Https,
    )
    assert len(result.rows) == 8
    assert all(row["eligible"] is True for row in result.rows), result.rows
    plan = direct_gpu_plan(result, config, [miner])
    assert plan["raw_scores"] == [[1, 16]]
    assert plan["trust_model"] == "approved_operator_guest_cpu_unattested"
    assert plan["private_customer_work"] is False and plan["chain_write"] is False
    directory = provider_directory(result, config, verifier)
    assert directory["providers"][0]["verified"] is True
    assert directory["providers"][0]["eligible"] is False
    assert "worker_key_digest" not in json.dumps(directory)
    untrusted = G4ProviderVerifier({"other": public})
    denied = qualify_gpu_round(
        [miner],
        config=config,
        keypair=ALICE,
        verifier=untrusted,
        transport_factory=G4Https,
    )
    assert not any(row["eligible"] for row in denied.rows)
