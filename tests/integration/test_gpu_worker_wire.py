"""Synthetic evidence/CUDA only; real worker TLS and direct-validator HTTP transport."""
import pytest
pytest.importorskip("cathedral.gpu_work")
fixture = pytest.importorskip("test_validator_access")

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import socket
import threading
import sr25519

import cathedral.validator_access as access
from cathedral.common import ChannelBinding, ChannelBindingType, Evidence, EvidenceKind
from cathedral.gpu_work import CudaWorkExecutor, expected_output_digest, parse_composite
from cathedral.validator_access import ValidatorAccessState, ValidatorRequestAuthorizer, load_sr25519_verifier
from cathedral.worker import WorkerServer
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.gpu_qualification import GpuPrelaunchConfig, qualify_gpu_round, direct_gpu_plan
import cathedral_thin.independent_runtime.validator_request as validator_request
import cathedral_thin.independent.fetch_policy as fetch_policy


def test_crossrepo_signed_gpu_over_real_tls(tmp_path, monkeypatch):
    monkeypatch.setattr(access, "is_globally_routable", lambda _a: True)
    monkeypatch.setattr(fetch_policy, "is_globally_routable_address", lambda _a: True)
    monkeypatch.setattr(validator_request, "is_globally_routable_address", lambda _a: True)
    monkeypatch.setattr(fixture, "NETWORK", "test")
    monkeypatch.setattr(fixture, "NETUID", 123)
    tls, _client, binding = fixture._tls_contexts(tmp_path)
    now = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        fixture._snapshot(generated_at=now, expires_at=now + timedelta(minutes=10), verify_at=now),
        worker_hotkey=fixture.WORKER_HOTKEY, channel_binding=binding,
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
    with WorkerServer(port=port, configured_hotkey=fixture.WORKER_HOTKEY, channel_binding=binding,
        tls_context=tls, validator_authorizer=authorizer, fleet_endpoints=(f"https://127.0.0.1:{port}",),
        gpu_executor=executor, gpu_evidence_collector=collector) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        config = GpuPrelaunchConfig("test", 123, fixture.VALIDATOR_HOTKEY, 1,
            str(tmp_path / "registry.json"), {}, 1, str(tmp_path / "registry.sqlite"), ("test-h100",))
        signer = SimpleNamespace(ss58_address=fixture.VALIDATOR_HOTKEY,
                                 sign=lambda m: sr25519.sign(fixture.VALIDATOR_PAIR, m))
        verifier = Verifier()
        miners = [ServingAxon(1, fixture.WORKER_HOTKEY, "127.0.0.1", port)]
        result = qualify_gpu_round(miners, config=config, keypair=signer, verifier=verifier)
        assert result.rows[0]["eligible"] is True, result.rows
        assert len(verifier.nonces) == 2 and verifier.nonces[0] != verifier.nonces[1]
        plan = direct_gpu_plan(result, config, miners)
        assert plan["raw_scores"] == [[1, 1]]
        assert plan["chain_write"] is False
