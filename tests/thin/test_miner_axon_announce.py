from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin.independent.compute import QuoteVerdict
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import miner_axon as axon
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST

SERVICE_IP = "8.8.8.8"


def chain_hash(number: int) -> str:
    return f"0x{number:064x}"


def miner_state(
    *,
    block: int = 100,
    uid: int = 17,
    hotkey: str = axon.MINER_HOTKEY,
    coldkey: str = axon.CATHEDRAL_COLDKEY,
    ip: str = "0.0.0.0",
    port: int = 0,
    serving: bool = False,
) -> axon.FinalizedMinerState:
    return axon.FinalizedMinerState(
        block_number=block,
        block_hash=chain_hash(block),
        uid=uid,
        hotkey=hotkey,
        coldkey=coldkey,
        ip=ip,
        port=port,
        is_serving=serving,
    )


def endpoint_proof(**overrides) -> axon.EndpointProof:
    values = {
        "hotkey": axon.MINER_HOTKEY,
        "validator_hotkey": axon.VALIDATOR_HOTKEY,
        "ip": SERVICE_IP,
        "port": axon.SN39_HTTPS_PORT,
        "qvl": "PASS",
        "qvl_digest": LAUNCH_QVL_DIGEST,
        "sat_units": 20,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "tls_spki_sha256": "11" * 32,
        "nonce_sha256": "22" * 32,
        "quote_sha256": "33" * 32,
        "report_data_sha256": "44" * 32,
        "anchor_number": 90,
        "anchor_hash": chain_hash(90),
    }
    values.update(overrides)
    return axon.EndpointProof(**values)


def wallet(
    *,
    hotkey: str = axon.MINER_HOTKEY,
    coldkey: str = axon.CATHEDRAL_COLDKEY,
):
    return SimpleNamespace(
        hotkey=SimpleNamespace(ss58_address=hotkey),
        coldkeypub=SimpleNamespace(ss58_address=coldkey),
    )


class FakeAxon:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


FakeBt = SimpleNamespace(Axon=FakeAxon)


class FakeSubstrate:
    def get_block_hash(self, number):
        if number == 0:
            return FINNEY_GENESIS_HASH
        return chain_hash(number)


class FakeSubtensor:
    def __init__(self) -> None:
        self.substrate = FakeSubstrate()


class StateSequence:
    def __init__(self, *states: axon.FinalizedMinerState) -> None:
        self.states = list(states)
        self.calls = 0

    def __call__(self, _subtensor):
        index = min(self.calls, len(self.states) - 1)
        self.calls += 1
        return self.states[index]


class FakeReceipt:
    extrinsic_hash = "0x" + "ab" * 32
    block_hash = chain_hash(101)
    block_number = 101


class FakeResponse:
    success = True
    extrinsic_receipt = FakeReceipt()


def write_review(
    tmp_path: Path,
    *,
    state: axon.FinalizedMinerState | None = None,
    proof: axon.EndpointProof | None = None,
) -> tuple[Path, str, dict]:
    document = axon.build_preview(
        state=state or miner_state(),
        proof=proof or endpoint_proof(),
        runtime_root=tmp_path,
        created_at="2026-08-28T12:00:00Z",
    )
    path, _, digest = axon.write_preview(document, tmp_path / "preview.json")
    return path, digest, document


def announce(
    tmp_path: Path,
    monkeypatch,
    *,
    preview_path: Path,
    digest: str,
    state_loader,
    proof_loader=lambda *_args, **_kwargs: endpoint_proof(),
    serve_call=None,
    selected_wallet=None,
    confirm=True,
    exclusive=True,
):
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    return axon.announce_reviewed_preview(
        bt_module=FakeBt,
        subtensor=FakeSubtensor(),
        wallet=selected_wallet or wallet(),
        preview_path=preview_path,
        reviewed_sha256=digest,
        qvl_path="/reviewed/qvl",
        confirm=confirm,
        exclusive_announcer_asserted=exclusive,
        state_loader=state_loader,
        proof_loader=proof_loader,
        serve_call=serve_call,
        runtime_root=tmp_path,
    )


def test_preview_is_owner_only_canonical_and_proves_no_chain_write(tmp_path):
    path, digest, document = write_review(tmp_path)

    assert document["status"] == axon.PREVIEW_READY
    assert document["chain_action"] == {
        "call": "SubtensorModule.serve_axon",
        "period_blocks": axon.ANNOUNCEMENT_PERIOD_BLOCKS,
        "would_replace_current": True,
        "extrinsic_built": False,
        "signed": False,
        "serve_axon_called": False,
        "submitted": False,
        "finalized_readback": None,
        "rent_called": False,
        "registration_called": False,
        "registration_burn_tao": "0.0",
        "weights_called": False,
        "maximum_serve_axon_attempts": 1,
        "transaction_fee": "NOT_ESTIMATED_BY_THIS_ARTIFACT",
    }
    assert (
        document["trust_boundary"]["tls_authentication"]
        == "tdx_report_data_binds_observed_spki"
    )
    assert document["trust_boundary"]["ip_literal_ca_hostname_validation"] == "NOT_USED"
    assert (
        document["trust_boundary"]["ordinary_remote_miner_ca_path"]
        == "OUT_OF_SCOPE_INCOMPATIBLE"
    )
    assert path.stat().st_mode & 0o777 == 0o600
    detached = path.with_suffix(".json.sha256")
    assert detached.stat().st_mode & 0o777 == 0o600
    assert detached.read_text() == digest + "\n"
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    assert raw == axon._canonical_json_bytes(json.loads(raw))


def test_preview_identity_check_uses_public_hotkey_without_signing_key_access():
    class PublicOnlyWallet:
        hotkeypub = SimpleNamespace(ss58_address=axon.MINER_HOTKEY)
        coldkeypub = SimpleNamespace(ss58_address=axon.CATHEDRAL_COLDKEY)

        @property
        def hotkey(self):
            raise AssertionError("preview must not load the signing hotkey")

    assert axon._wallet_public_identity(PublicOnlyWallet()) == (
        axon.MINER_HOTKEY,
        axon.CATHEDRAL_COLDKEY,
    )


@pytest.mark.parametrize(
    "state",
    [
        miner_state(hotkey=axon.VALIDATOR_HOTKEY),
        miner_state(coldkey=axon.VALIDATOR_HOTKEY),
    ],
)
def test_preview_refuses_wrong_miner_or_coldkey(state, tmp_path):
    with pytest.raises(axon.MinerAxonError, match="identity"):
        axon.build_preview(
            state=state,
            proof=endpoint_proof(),
            runtime_root=tmp_path,
        )


@pytest.mark.parametrize(
    "proof",
    [
        endpoint_proof(qvl="FAIL"),
        endpoint_proof(qvl_digest="00" * 32),
        endpoint_proof(sat_units=0),
        endpoint_proof(sat_rule="self_reported_units"),
        endpoint_proof(tls_spki_sha256="bad"),
        endpoint_proof(hotkey=axon.VALIDATOR_HOTKEY),
        endpoint_proof(validator_hotkey=axon.MINER_HOTKEY),
    ],
)
def test_preview_refuses_unproven_or_misbound_endpoint(proof, tmp_path):
    with pytest.raises(axon.MinerAxonError):
        axon.build_preview(
            state=miner_state(),
            proof=proof,
            runtime_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("ip", "port"),
    [
        ("127.0.0.1", axon.SN39_HTTPS_PORT),
        ("8.8.8.8", 8443),
        ("2001:4860:4860::8888", axon.SN39_HTTPS_PORT),
    ],
)
def test_preview_refuses_nonpublic_ipv4_or_wrong_port(ip, port, tmp_path):
    with pytest.raises(axon.MinerAxonError):
        axon.build_preview(
            state=miner_state(),
            proof=endpoint_proof(ip=ip, port=port),
            runtime_root=tmp_path,
        )


def test_load_requires_exact_reviewed_and_detached_digest(tmp_path):
    path, digest, _ = write_review(tmp_path)
    loaded, observed = axon.load_reviewed_preview(
        path, reviewed_sha256="sha256:" + digest
    )
    assert loaded["schema"] == axon.PREVIEW_SCHEMA
    assert observed == digest

    with pytest.raises(axon.MinerAxonError, match="does not match"):
        axon.load_reviewed_preview(path, reviewed_sha256="00" * 32)
    path.with_suffix(".json.sha256").write_text("11" * 32 + "\n")
    with pytest.raises(axon.MinerAxonError, match="detached"):
        axon.load_reviewed_preview(path, reviewed_sha256=digest)


def test_preview_schema_refuses_unknown_nested_chain_fields(tmp_path):
    document = axon.build_preview(
        state=miner_state(),
        proof=endpoint_proof(),
        runtime_root=tmp_path,
    )
    document["chain_at_preview"]["unreviewed"] = True
    with pytest.raises(axon.MinerAxonError, match="fields"):
        axon.validate_preview(document)


def test_load_refuses_non_owner_only_preview(tmp_path):
    path, digest, _ = write_review(tmp_path)
    path.chmod(0o644)
    with pytest.raises(axon.MinerAxonError, match="0600"):
        axon.load_reviewed_preview(path, reviewed_sha256=digest)


def test_preview_refuses_symlinked_artifact_directory(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    document = axon.build_preview(
        state=miner_state(),
        proof=endpoint_proof(),
        runtime_root=tmp_path,
    )
    with pytest.raises(axon.MinerAxonError, match="directory"):
        axon.write_preview(document, linked / "preview.json")


@pytest.mark.parametrize(
    ("confirm", "exclusive", "message"),
    [
        (False, True, "confirm-miner-announce"),
        (True, False, "assert-exclusive-announcer"),
    ],
)
def test_announcement_requires_confirmation_and_remote_exclusivity(
    tmp_path, monkeypatch, confirm, exclusive, message
):
    path, digest, _ = write_review(tmp_path)
    calls = []

    with pytest.raises(axon.MinerAxonError, match=message):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state()),
            serve_call=lambda **kwargs: calls.append(kwargs),
            confirm=confirm,
            exclusive=exclusive,
        )

    assert calls == []
    assert not (tmp_path / axon.JOURNAL_NAME).exists()


@pytest.mark.parametrize(
    "bad_wallet",
    [
        wallet(hotkey=axon.VALIDATOR_HOTKEY),
        wallet(coldkey=axon.VALIDATOR_HOTKEY),
    ],
)
def test_announcement_refuses_wrong_wallet_before_chain_call(
    tmp_path, monkeypatch, bad_wallet
):
    path, digest, _ = write_review(tmp_path)
    calls = []
    with pytest.raises(axon.MinerAxonError, match="wallet"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state()),
            selected_wallet=bad_wallet,
            serve_call=lambda **kwargs: calls.append(kwargs),
        )
    assert calls == []


def test_announcement_refuses_chain_drift_before_fresh_evidence(tmp_path, monkeypatch):
    path, digest, _ = write_review(tmp_path)
    calls = []
    with pytest.raises(axon.MinerAxonError, match="axon changed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(
                miner_state(ip="1.1.1.1", port=8081, serving=True)
            ),
            serve_call=lambda **kwargs: calls.append(kwargs),
        )
    assert calls == []


def test_announcement_refuses_finalized_head_older_than_preview(tmp_path, monkeypatch):
    path, digest, _ = write_review(tmp_path)
    calls = []
    with pytest.raises(axon.MinerAxonError, match="older"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(block=99)),
            serve_call=lambda **kwargs: calls.append(kwargs),
        )
    assert calls == []


def test_announcement_refuses_fresh_tls_spki_drift(tmp_path, monkeypatch):
    path, digest, _ = write_review(tmp_path)
    calls = []
    with pytest.raises(axon.MinerAxonError, match="tls_spki"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(), miner_state(block=101)),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **kwargs: calls.append(kwargs),
        )
    assert calls == []
    assert not (tmp_path / axon.JOURNAL_NAME).exists()


def test_digest_authorized_announcement_calls_only_serve_axon_and_reads_back(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    served = miner_state(
        block=102,
        ip=SERVICE_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    states = StateSequence(
        unserved,
        replace(unserved, block_number=101, block_hash=chain_hash(101)),
        served,
    )
    calls = []

    def serve_call(**kwargs):
        calls.append(kwargs)
        return FakeResponse()

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=states,
        serve_call=serve_call,
    )

    assert result["status"] == "finalized_proven"
    assert result["retry_allowed"] is False
    assert result["readback"]["axon"] == {
        "ip": SERVICE_IP,
        "port": axon.SN39_HTTPS_PORT,
        "is_serving": True,
    }
    assert len(calls) == 1
    call = calls[0]
    assert set(call) == {
        "netuid",
        "axon",
        "mev_protection",
        "period",
        "raise_error",
        "wait_for_inclusion",
        "wait_for_finalization",
    }
    assert call["netuid"] == 39
    assert call["period"] == axon.ANNOUNCEMENT_PERIOD_BLOCKS
    assert call["wait_for_finalization"] is True
    assert call["axon"].external_ip == SERVICE_IP
    assert call["axon"].external_port == 8081
    assert not hasattr(call["axon"], "start")
    journal = json.loads((tmp_path / axon.JOURNAL_NAME).read_text())
    assert journal["status"] == "finalized_proven"
    assert journal["remote_exclusive_announcer_asserted"] is True
    assert journal["identity"]["preview_sha256"] == "sha256:" + digest
    assert (tmp_path / axon.JOURNAL_NAME).stat().st_mode & 0o777 == 0o600


def test_exact_endpoint_before_submission_is_a_no_write_result(tmp_path, monkeypatch):
    path, digest, _ = write_review(tmp_path)
    calls = []
    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(
            miner_state(
                block=101,
                ip=SERVICE_IP,
                port=8081,
                serving=True,
            )
        ),
        proof_loader=lambda *_args, **_kwargs: pytest.fail(
            "fresh evidence is not needed for a no-write exact readback"
        ),
        serve_call=lambda **kwargs: calls.append(kwargs),
    )
    assert result["status"] == "already_announced_no_write"
    assert result["serve_axon_called"] is False
    assert calls == []
    assert not (tmp_path / axon.JOURNAL_NAME).exists()


def test_incompatible_sdk_signature_refuses_before_no_retry_journal(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    calls = []

    def incompatible_serve_call(
        *, netuid, axon, wait_for_inclusion, wait_for_finalization
    ):
        calls.append((netuid, axon, wait_for_inclusion, wait_for_finalization))

    with pytest.raises(axon.MinerAxonError, match="incompatible before submission"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(), miner_state(block=101)),
            serve_call=incompatible_serve_call,
        )

    assert calls == []
    assert not (tmp_path / axon.JOURNAL_NAME).exists()


def test_installed_bittensor_serve_axon_accepts_the_exact_launch_contract():
    import bittensor as bt
    from bittensor.core.types import ExtrinsicResponse

    bound = bt.Subtensor.serve_axon.__get__(object(), bt.Subtensor)
    advertisement = object()
    kwargs = axon._validated_serve_axon_call(
        bound,
        advertisement=advertisement,
    )

    assert kwargs == {
        "netuid": axon.NETUID,
        "axon": advertisement,
        "mev_protection": False,
        "period": axon.ANNOUNCEMENT_PERIOD_BLOCKS,
        "raise_error": True,
        "wait_for_inclusion": True,
        "wait_for_finalization": True,
    }
    assert bt.__version__ == "10.5.0"
    response = ExtrinsicResponse(success=True)
    assert response.success is True
    assert response.extrinsic_receipt is None


def test_local_duplicate_writer_lock_refuses_before_chain_call(tmp_path, monkeypatch):
    path, digest, _ = write_review(tmp_path)
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    calls = []

    with axon._announcement_lock(tmp_path):
        with pytest.raises(axon.MinerAxonError, match="another local"):
            axon.announce_reviewed_preview(
                bt_module=FakeBt,
                subtensor=FakeSubtensor(),
                wallet=wallet(),
                preview_path=path,
                reviewed_sha256=digest,
                qvl_path="/reviewed/qvl",
                confirm=True,
                exclusive_announcer_asserted=True,
                state_loader=StateSequence(miner_state()),
                proof_loader=lambda *_args, **_kwargs: endpoint_proof(),
                serve_call=lambda **kwargs: calls.append(kwargs),
                runtime_root=tmp_path,
            )

    assert calls == []


def test_sdk_exception_leaves_durable_ambiguity_and_second_run_never_retries(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    calls = []

    def explode(**kwargs):
        calls.append(kwargs)
        raise TimeoutError("receipt stream closed")

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved, unserved, unserved),
            serve_call=explode,
        )
    assert len(calls) == 1
    journal_path = tmp_path / axon.JOURNAL_NAME
    journal = json.loads(journal_path.read_text())
    assert journal["status"] == "submission_ambiguous"
    assert journal["retry_allowed"] is False

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved),
            serve_call=explode,
        )
    assert len(calls) == 1


def test_sdk_exception_with_exact_finalized_readback_recovers_without_retry(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    served = miner_state(block=102, ip=SERVICE_IP, port=8081, serving=True)
    calls = []

    def explode(**kwargs):
        calls.append(kwargs)
        raise TimeoutError("final receipt response lost")

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(unserved, unserved, served),
        serve_call=explode,
    )
    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert len(calls) == 1


@pytest.mark.parametrize("unreadable_field", ("extrinsic_receipt", "success"))
def test_sdk_response_inspection_failure_is_ambiguous_and_never_retried(
    tmp_path, monkeypatch, unreadable_field
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    calls = []

    class UnreadableResponse:
        @property
        def extrinsic_receipt(self):
            if unreadable_field == "extrinsic_receipt":
                raise ValueError("malformed SDK receipt")
            return FakeReceipt()

        @property
        def success(self):
            if unreadable_field == "success":
                raise ValueError("malformed SDK success flag")
            return True

    def serve_call(**kwargs):
        calls.append(kwargs)
        return UnreadableResponse()

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved, unserved, unserved),
            serve_call=serve_call,
        )

    journal = json.loads((tmp_path / axon.JOURNAL_NAME).read_text())
    assert journal["status"] == "submission_ambiguous"
    assert journal["serve_axon_outcome"] == "SDK_RESPONSE_UNPROVEN"
    assert journal["receipt"] is None
    assert journal["retry_allowed"] is False

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved),
            serve_call=serve_call,
        )
    assert len(calls) == 1


def test_success_without_exact_readback_is_ambiguous_and_not_retried(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved, unserved, unserved, unserved),
            serve_call=lambda **_kwargs: FakeResponse(),
        )
    journal = json.loads((tmp_path / axon.JOURNAL_NAME).read_text())
    assert journal["status"] == "submission_ambiguous"
    assert journal["receipt"]["success"] is True


def test_recovery_promotes_ambiguous_journal_from_finalized_readback(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    with pytest.raises(axon.MinerAxonAmbiguous):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(unserved, unserved, unserved),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(TimeoutError()),
        )

    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    recovered = axon.recover_ambiguous_preview(
        subtensor=FakeSubtensor(),
        preview_path=path,
        reviewed_sha256=digest,
        state_loader=StateSequence(
            miner_state(block=105, ip=SERVICE_IP, port=8081, serving=True)
        ),
        runtime_root=tmp_path,
    )
    assert recovered["status"] == "finalized_recovered"
    assert recovered["retry_allowed"] is False


def test_finalized_journal_is_idempotent_and_does_not_call_serve_again(
    tmp_path, monkeypatch
):
    path, digest, _ = write_review(tmp_path)
    unserved = miner_state()
    served = miner_state(block=102, ip=SERVICE_IP, port=8081, serving=True)
    calls = []

    def serve_call(**kwargs):
        calls.append(kwargs)
        return FakeResponse()

    first = announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(unserved, unserved, served),
        serve_call=serve_call,
    )
    second = announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(served),
        serve_call=serve_call,
    )
    assert first["status"] == "finalized_proven"
    assert second["status"] == "finalized_proven"
    assert len(calls) == 1


class FakeAxonInfo:
    def __init__(self, *, ip="0.0.0.0", port=0, serving=False) -> None:
        self.ip = ip
        self.port = port
        self.is_serving = serving


class FakeMetagraph:
    def __init__(
        self,
        *,
        hotkey=axon.MINER_HOTKEY,
        coldkey=axon.CATHEDRAL_COLDKEY,
        row=None,
    ) -> None:
        self.uids = [17]
        self.hotkeys = [hotkey]
        self.coldkeys = [coldkey]
        self.axons = [row or FakeAxonInfo()]


class FinalizedSubstrate(FakeSubstrate):
    def get_chain_finalised_head(self):
        return chain_hash(100)

    def get_block_number(self, block_hash):
        return int(block_hash, 16)


class FinalizedSubtensor:
    def __init__(self, metagraph) -> None:
        self.substrate = FinalizedSubstrate()
        self.row = metagraph
        self.calls = []

    def metagraph(self, netuid, *, lite, block):
        self.calls.append((netuid, lite, block))
        return self.row


def test_finalized_state_requires_exact_registered_coldkey_and_strict_axon():
    good = FinalizedSubtensor(FakeMetagraph())
    state = axon.finalized_miner_state(good)
    assert state.uid == 17
    assert good.calls == [(39, True, 100)]

    with pytest.raises(axon.MinerAxonError, match="registered exactly once"):
        axon.finalized_miner_state(
            FinalizedSubtensor(FakeMetagraph(hotkey=axon.VALIDATOR_HOTKEY))
        )
    with pytest.raises(axon.MinerAxonError, match="owned"):
        axon.finalized_miner_state(
            FinalizedSubtensor(FakeMetagraph(coldkey=axon.VALIDATOR_HOTKEY))
        )
    malformed = FakeAxonInfo()
    malformed.is_serving = "yes"
    with pytest.raises(axon.MinerAxonError, match="serving flag"):
        axon.finalized_miner_state(FinalizedSubtensor(FakeMetagraph(row=malformed)))


def test_collect_proof_uses_uid30_nonce_qvl_pin_and_canonical_sat(
    monkeypatch,
):
    collected = SimpleNamespace(
        assigned_hotkey=axon.MINER_HOTKEY,
        quote=b"fresh-tdx-quote",
        report_data=b"r" * 64,
        nonce=b"n" * 32,
        channel_binding=SimpleNamespace(digest=bytes.fromhex("11" * 32)),
    )
    anchor = SimpleNamespace(anchor_number=90, anchor_hash=chain_hash(90))
    captured = {}

    def fake_collect(url, hotkey, validator_hotkey, sat_url):
        captured["collect"] = (url, hotkey, validator_hotkey, sat_url)
        return {"collected": collected}

    class FakeVerifier:
        digest = LAUNCH_QVL_DIGEST

        def verify(self, quote, *, expected_report_data):
            captured["qvl"] = (quote, expected_report_data)
            return QuoteVerdict.PASS

    def fake_units(*, anchor_hash, collected, sat_url):
        captured["sat"] = (anchor_hash, collected, sat_url)
        return 20

    monkeypatch.setattr(
        axon, "snapshot_epoch", lambda _subtensor: SimpleNamespace(anchor=anchor)
    )
    monkeypatch.setattr(axon, "_try_collect", fake_collect)
    monkeypatch.setattr(axon, "load_verifier", lambda _path: FakeVerifier())
    monkeypatch.setattr(axon, "_units_after_quote", fake_units)

    proof = axon.collect_endpoint_proof(
        FakeSubtensor(),
        qvl_path="/reviewed/qvl",
        ip=SERVICE_IP,
        port=8081,
    )

    assert proof.qvl_digest == LAUNCH_QVL_DIGEST
    assert proof.sat_rule == SAT_WORK_UNIT_RULE
    assert proof.sat_units == 20
    assert captured["collect"][1:3] == (
        axon.MINER_HOTKEY,
        axon.VALIDATOR_HOTKEY,
    )
    assert captured["qvl"] == (collected.quote, collected.report_data)
    assert captured["sat"][0] == chain_hash(90)
    assert captured["sat"][1] is collected
    assert captured["collect"][3] == captured["sat"][2]


def test_collect_proof_refuses_nonpassing_qvl_before_sat(monkeypatch):
    collected = SimpleNamespace(
        assigned_hotkey=axon.MINER_HOTKEY,
        quote=b"fresh-tdx-quote",
        report_data=b"r" * 64,
        nonce=b"n" * 32,
        channel_binding=SimpleNamespace(digest=bytes.fromhex("11" * 32)),
    )

    class RejectingVerifier:
        digest = LAUNCH_QVL_DIGEST

        def verify(self, quote, *, expected_report_data):
            del quote, expected_report_data
            return QuoteVerdict.FAIL

    monkeypatch.setattr(
        axon,
        "snapshot_epoch",
        lambda _subtensor: SimpleNamespace(
            anchor=SimpleNamespace(anchor_number=90, anchor_hash=chain_hash(90))
        ),
    )
    monkeypatch.setattr(axon, "_try_collect", lambda *_args: {"collected": collected})
    monkeypatch.setattr(axon, "load_verifier", lambda _path: RejectingVerifier())
    monkeypatch.setattr(
        axon,
        "_units_after_quote",
        lambda **_kwargs: pytest.fail("SAT must not run after QVL refusal"),
    )

    with pytest.raises(axon.MinerAxonError, match="did not pass"):
        axon.collect_endpoint_proof(
            FakeSubtensor(),
            qvl_path="/reviewed/qvl",
            ip=SERVICE_IP,
            port=8081,
        )
