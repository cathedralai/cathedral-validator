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
from cathedral_thin.independent_runtime import miner_axon_cli as axon_cli
from cathedral_thin.independent_runtime import uid124_axon_generation2_cli as gen2_cli
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST

SERVICE_IP = "8.8.8.8"
SUCCESSOR_IP = "1.1.1.1"


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


def response_at(block: int | None):
    hash_number = 232 if block is None else block
    return SimpleNamespace(
        success=True,
        extrinsic_receipt=SimpleNamespace(
            extrinsic_hash="0x" + "cd" * 32,
            block_hash=chain_hash(hash_number),
            block_number=block,
        ),
    )


def write_review(
    tmp_path: Path,
    *,
    state: axon.FinalizedMinerState | None = None,
    proof: axon.EndpointProof | None = None,
    name: str = "preview.json",
    contract: axon.MinerAxonContract = axon.UID124_AXON_CONTRACT,
) -> tuple[Path, str, dict]:
    document = axon.build_preview(
        state=state or miner_state(),
        proof=proof or endpoint_proof(),
        runtime_root=tmp_path,
        created_at="2026-08-28T12:00:00Z",
        contract=contract,
    )
    path, _, digest = axon.write_preview(document, tmp_path / name, contract=contract)
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
    allow_finalized_successor=False,
    predecessor_preview_path=None,
    predecessor_reviewed_sha256=None,
    contract: axon.MinerAxonContract = axon.UID124_AXON_CONTRACT,
):
    if contract is axon.UID124_AXON_CONTRACT:
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
        allow_finalized_successor=allow_finalized_successor,
        predecessor_preview_path=predecessor_preview_path,
        predecessor_reviewed_sha256=predecessor_reviewed_sha256,
        contract=contract,
    )


def finalized_predecessor(tmp_path: Path, monkeypatch):
    """Create the exact first-generation FINAL journal used by successor tests."""

    initial = miner_state(uid=axon.FINALIZED_SUCCESSOR_UID)
    path, digest, _ = write_review(
        tmp_path,
        state=initial,
        name="predecessor-preview.json",
    )
    served = miner_state(
        block=102,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SERVICE_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    announce(
        tmp_path,
        monkeypatch,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(
            initial,
            replace(initial, block_number=101, block_hash=chain_hash(101)),
            served,
        ),
        serve_call=lambda **_kwargs: FakeResponse(),
    )
    journal_path = tmp_path / axon.JOURNAL_NAME
    return path, digest, served, journal_path, journal_path.read_bytes()


def successor_review(tmp_path: Path, *, block: int = 230, ip: str = SUCCESSOR_IP):
    current = miner_state(
        block=block,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SERVICE_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    proof = endpoint_proof(
        ip=ip,
        tls_spki_sha256="55" * 32,
        nonce_sha256="66" * 32,
        quote_sha256="77" * 32,
        report_data_sha256="88" * 32,
        anchor_number=block - 10,
        anchor_hash=chain_hash(block - 10),
    )
    return (
        *write_review(
            tmp_path,
            state=current,
            proof=proof,
            name=f"successor-{block}-{ip.replace('.', '-')}.json",
        ),
        current,
        proof,
    )


def persisted_started_successor(tmp_path: Path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )
    return (
        predecessor_path,
        predecessor_digest,
        predecessor_bytes,
        successor_path,
        successor_digest,
        current,
        journal_path,
        json.loads(journal_path.read_text()),
    )


def persisted_finalized_successor(tmp_path: Path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=lambda **_kwargs: response_at(232),
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )
    return (
        predecessor_path,
        predecessor_digest,
        successor_path,
        successor_digest,
        current,
        target,
        journal_path,
        result,
    )


def generation2_review(tmp_path: Path, monkeypatch):
    """Create a reviewed generation-2 target over an exact generation-1 journal."""

    (
        _,
        _,
        predecessor_preview_path,
        predecessor_preview_digest,
        _,
        generation1_readback,
        journal_path,
        generation1_journal,
    ) = persisted_finalized_successor(tmp_path, monkeypatch)
    predecessor_bytes = journal_path.read_bytes()
    contract = replace(
        axon.UID124_GENERATION2_AXON_CONTRACT,
        runtime_root=tmp_path,
        predecessor_preview_name=predecessor_preview_path.name,
        predecessor_preview_sha256=predecessor_preview_digest,
        predecessor_journal_sha256=hashlib.sha256(predecessor_bytes).hexdigest(),
    )
    current = replace(
        generation1_readback,
        block_number=400,
        block_hash=chain_hash(400),
    )
    proof = endpoint_proof(
        ip=axon.UID124_GENERATION2_ENDPOINT_IP,
        tls_spki_sha256="99" * 32,
        nonce_sha256="aa" * 32,
        quote_sha256="bb" * 32,
        report_data_sha256="cc" * 32,
        anchor_number=390,
        anchor_hash=chain_hash(390),
    )
    preview_path, preview_digest, preview = write_review(
        tmp_path,
        state=current,
        proof=proof,
        name=contract.preview_name,
        contract=contract,
    )
    return {
        "contract": contract,
        "predecessor_preview_path": predecessor_preview_path,
        "predecessor_preview_digest": predecessor_preview_digest,
        "predecessor_bytes": predecessor_bytes,
        "generation1_journal": generation1_journal,
        "journal_path": journal_path,
        "current": current,
        "proof": proof,
        "preview_path": preview_path,
        "preview_digest": preview_digest,
        "preview": preview,
    }


class UnlockTrapWallet:
    hotkeypub = SimpleNamespace(ss58_address=axon.MINER_HOTKEY)
    coldkeypub = SimpleNamespace(ss58_address=axon.CATHEDRAL_COLDKEY)

    def __init__(self) -> None:
        self.hotkey_accesses = 0

    @property
    def hotkey(self):
        self.hotkey_accesses += 1
        raise AssertionError("successor refusal reached signing-hotkey access")


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
    assert result["schema"] == axon.JOURNAL_SCHEMA
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
    import inspect
    from dataclasses import fields
    from typing import get_type_hints

    import bittensor as bt
    from async_substrate_interface import ExtrinsicReceipt
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
    assert get_type_hints(bt.Subtensor.serve_axon)["return"] is ExtrinsicResponse
    assert {"success", "extrinsic_receipt"} <= {
        field.name for field in fields(ExtrinsicResponse)
    }
    assert {"extrinsic_hash", "block_hash", "block_number"} <= set(
        inspect.signature(ExtrinsicReceipt).parameters
    )
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


def test_existing_baseline_recovery_never_accesses_signing_hotkey(
    tmp_path, monkeypatch
):
    preview_path, digest, served, _, _ = finalized_predecessor(tmp_path, monkeypatch)
    trapped = UnlockTrapWallet()
    calls = []

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=preview_path,
        digest=digest,
        state_loader=StateSequence(served),
        selected_wallet=trapped,
        serve_call=lambda **kwargs: calls.append(kwargs),
    )

    assert result["status"] == "finalized_proven"
    assert trapped.hotkey_accesses == 0
    assert calls == []


def test_existing_final_successor_default_recovery_never_accesses_signing_hotkey(
    tmp_path, monkeypatch
):
    (
        _,
        _,
        successor_path,
        successor_digest,
        _,
        target,
        _,
        _,
    ) = persisted_finalized_successor(tmp_path, monkeypatch)
    trapped = UnlockTrapWallet()
    calls = []

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(target),
        selected_wallet=trapped,
        serve_call=lambda **kwargs: calls.append(kwargs),
    )

    assert result["status"] == "finalized_proven"
    assert trapped.hotkey_accesses == 0
    assert calls == []


def test_existing_corrupt_successor_default_refusal_never_accesses_signing_hotkey(
    tmp_path, monkeypatch
):
    (
        _,
        _,
        _,
        successor_path,
        successor_digest,
        _,
        journal_path,
        started,
    ) = persisted_started_successor(tmp_path, monkeypatch)
    started["status"] = "corrupt"
    journal_path.write_bytes(axon._canonical_json_bytes(started))
    before = journal_path.read_bytes()
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=lambda _subtensor: (_ for _ in ()).throw(
                AssertionError("corrupt successor reached chain state")
            ),
            selected_wallet=trapped,
            serve_call=lambda **kwargs: calls.append(kwargs),
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_one_finalized_successor_preserves_exact_predecessor_lineage(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    states = StateSequence(
        current,
        replace(current, block_number=231, block_hash=chain_hash(231)),
        miner_state(
            block=232,
            uid=axon.FINALIZED_SUCCESSOR_UID,
            ip=SUCCESSOR_IP,
            port=axon.SN39_HTTPS_PORT,
            serving=True,
        ),
    )
    calls = []

    def serve_call(**kwargs):
        calls.append(kwargs)
        return response_at(232)

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=states,
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP,
            tls_spki_sha256="55" * 32,
        ),
        serve_call=serve_call,
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )

    assert result["status"] == "finalized_proven"
    assert result["schema"] == axon.SUCCESSOR_JOURNAL_SCHEMA
    assert result["journal_kind"] == axon.SUCCESSOR_JOURNAL_KIND
    assert result["journal_generation"] == 1
    assert result["attempt_id"].startswith("successor-sha256:")
    assert len(calls) == 1
    assert calls[0]["axon"].external_ip == SUCCESSOR_IP
    lineage = result["predecessor_lineage"]
    assert lineage["generation"] == 1
    assert (
        lineage["journal_sha256"]
        == "sha256:" + hashlib.sha256(predecessor_bytes).hexdigest()
    )
    assert axon._canonical_json_bytes(lineage["journal"]) == predecessor_bytes
    assert lineage["journal"]["status"] == "finalized_proven"
    assert lineage["journal"]["readback"]["axon"]["ip"] == SERVICE_IP
    assert json.loads(journal_path.read_text()) == result
    assert (tmp_path / axon.LOCK_NAME).exists()


def test_final_successor_recovery_accepts_receipt_at_stored_final_block(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    calls = []

    def serve_call(**kwargs):
        calls.append(kwargs)
        return response_at(232)

    first = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=serve_call,
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )
    second = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(target),
        serve_call=serve_call,
    )

    assert first == second
    assert (
        first["receipt"]["block_number"] == first["readback"]["finalized_block_number"]
    )
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["stale_current", "forked_stored_final"])
def test_final_successor_recovery_rejects_stale_or_forked_stored_final(
    tmp_path, monkeypatch, failure
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=lambda **_kwargs: response_at(232),
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )
    journal = json.loads(journal_path.read_text())
    if failure == "forked_stored_final":
        journal["readback"]["finalized_block_hash"] = chain_hash(999)
        journal_path.write_bytes(axon._canonical_json_bytes(journal))
        current_readback = replace(target, block_number=233, block_hash=chain_hash(233))
    else:
        current_readback = replace(target, block_number=231, block_hash=chain_hash(231))
    before = journal_path.read_bytes()

    with pytest.raises(axon.MinerAxonAmbiguous):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current_readback),
        )

    assert journal_path.read_bytes() == before


def test_successor_target_readback_must_strictly_postdate_preflight(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    preflight = replace(current, block_number=231, block_hash=chain_hash(231))
    target_at_preflight = replace(preflight, ip=SUCCESSOR_IP)

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                preflight,
                target_at_preflight,
                target_at_preflight,
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: response_at(231),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert json.loads(journal_path.read_text())["status"] == "submission_ambiguous"


def test_predecessor_readback_must_strictly_postdate_its_preflight_before_unlock(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    predecessor = json.loads(journal_path.read_text())
    predecessor["readback"]["finalized_block_number"] = predecessor["preflight"][
        "finalized_block_number"
    ]
    predecessor["readback"]["finalized_block_hash"] = predecessor["preflight"][
        "finalized_block_hash"
    ]
    journal_path.write_bytes(axon._canonical_json_bytes(predecessor))
    before = journal_path.read_bytes()
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="postdate"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            selected_wallet=trapped,
            serve_call=lambda **kwargs: calls.append(kwargs),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_successor_refuses_ambiguous_predecessor_before_unlock_or_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    predecessor = json.loads(journal_path.read_text())
    predecessor["status"] = "submission_ambiguous"
    journal_path.write_bytes(axon._canonical_json_bytes(predecessor))
    before = journal_path.read_bytes()
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="not finalized"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_successor_refuses_current_axon_mismatch_before_unlock_or_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    mismatched = replace(current, ip="9.9.9.9")
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="axon changed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(mismatched),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_requires_distinct_reviewed_digest_before_unlock_or_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="distinct reviewed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=predecessor_path,
            digest=predecessor_digest,
            state_loader=StateSequence(miner_state()),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_requires_distinct_endpoint_without_consuming_transition(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, served, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    same_path, same_digest, _ = write_review(
        tmp_path,
        state=replace(served, block_number=230, block_hash=chain_hash(230)),
        proof=endpoint_proof(nonce_sha256="99" * 32),
        name="same-endpoint-new-review.json",
    )
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="endpoint must differ"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=same_path,
            digest=same_digest,
            state_loader=StateSequence(served),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_refuses_before_128_finalized_blocks(tmp_path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(
        tmp_path, block=229
    )
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="127 < 128"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


@pytest.mark.parametrize(
    "corruption",
    [
        {"finalized_block_number": 1},
        {"finalized_block_hash": chain_hash(999)},
        {"finalized_block_number": 999, "finalized_block_hash": chain_hash(999)},
    ],
)
def test_successor_refuses_unreliable_predecessor_block(
    tmp_path, monkeypatch, corruption
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    predecessor = json.loads(journal_path.read_text())
    predecessor["readback"].update(corruption)
    journal_path.write_bytes(axon._canonical_json_bytes(predecessor))
    before = journal_path.read_bytes()
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_successor_incompatible_sdk_refuses_before_unlock_and_preserves_final(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    def incompatible(*, netuid, axon, wait_for_finalization):
        calls.append((netuid, axon, wait_for_finalization))

    with pytest.raises(axon.MinerAxonError, match="incompatible before submission"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=incompatible,
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_is_single_use_and_cannot_cycle(tmp_path, monkeypatch):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    served_successor = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            served_successor,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=lambda **_kwargs: response_at(232),
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )
    third_ip = "9.9.9.9"
    third_state = replace(
        served_successor,
        block_number=400,
        block_hash=chain_hash(400),
    )
    third_path, third_digest, _ = write_review(
        tmp_path,
        state=third_state,
        proof=endpoint_proof(ip=third_ip, tls_spki_sha256="aa" * 32),
        name="third-preview.json",
    )
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="already consumed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=third_path,
            digest=third_digest,
            state_loader=StateSequence(third_state),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=successor_path,
            predecessor_reviewed_sha256=successor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []


def test_successor_lagging_target_readback_stays_ambiguous(tmp_path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    lagging_target = miner_state(
        block=229,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
                lagging_target,
                lagging_target,
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: FakeResponse(),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    journal = json.loads(journal_path.read_text())
    assert journal["status"] == "submission_ambiguous"
    assert journal["retry_allowed"] is False
    assert journal["predecessor_lineage"]["generation"] == 1


def test_successor_null_receipt_block_accepts_later_canonical_readback_and_is_idempotent(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    calls = []

    def serve_call(**kwargs):
        calls.append(kwargs)
        return response_at(None)

    first = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=serve_call,
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )
    second = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            replace(target, block_number=233, block_hash=chain_hash(233))
        ),
        serve_call=serve_call,
    )

    assert first["status"] == "finalized_proven"
    assert first["receipt"]["block_number"] is None
    assert second["status"] == "finalized_proven"
    assert len(calls) == 1


@pytest.mark.parametrize("receipt_block", [101, 231])
def test_successor_stale_success_receipt_is_recovered_only_by_exact_readback(
    tmp_path, monkeypatch, receipt_block
):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=lambda **_kwargs: response_at(receipt_block),
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )

    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert result["receipt"] is None


def test_successor_numbered_receipt_without_hash_recovers_by_exact_readback(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    response = SimpleNamespace(
        success=True,
        extrinsic_receipt=SimpleNamespace(
            extrinsic_hash="0x" + "cd" * 32,
            block_hash=None,
            block_number=232,
        ),
    )

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=successor_path,
        digest=successor_digest,
        state_loader=StateSequence(
            current,
            replace(current, block_number=231, block_hash=chain_hash(231)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(
            ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
        ),
        serve_call=lambda **_kwargs: response,
        allow_finalized_successor=True,
        predecessor_preview_path=predecessor_path,
        predecessor_reviewed_sha256=predecessor_digest,
    )

    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert result["receipt"] is None


def test_successor_atomic_replace_failure_preserves_predecessor_final(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    original_write = axon._write_state
    calls = []

    def fail_successor_intent(path, document, *, exclusive):
        if document.get("predecessor_lineage") is not None:
            raise OSError("simulated atomic replacement failure")
        return original_write(path, document, exclusive=exclusive)

    monkeypatch.setattr(axon, "_write_state", fail_successor_intent)
    with pytest.raises(axon.MinerAxonError, match="predecessor remains exact"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **kwargs: calls.append(kwargs),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_post_replace_directory_fsync_failure_is_ambiguous_no_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    original_fsync = axon.os.fsync
    fsync_calls = {"count": 0}
    calls = []

    def fail_directory_fsync(descriptor):
        fsync_calls["count"] += 1
        if fsync_calls["count"] == 2:
            raise OSError("simulated post-replace directory fsync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(axon.os, "fsync", fail_directory_fsync)
    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **kwargs: calls.append(kwargs),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    installed = json.loads(journal_path.read_text())
    assert installed["schema"] == axon.SUCCESSOR_JOURNAL_SCHEMA
    assert installed["status"] == "submission_started"
    assert installed["predecessor_lineage"]["journal_sha256"] == (
        "sha256:" + hashlib.sha256(predecessor_bytes).hexdigest()
    )
    assert calls == []


def test_successor_crash_after_replace_leaves_recoverable_linked_intent(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    started = json.loads(journal_path.read_text())
    assert started["status"] == "submission_started"
    assert started["retry_allowed"] is False
    assert (
        axon._canonical_json_bytes(started["predecessor_lineage"]["journal"])
        == predecessor_bytes
    )
    trapped = UnlockTrapWallet()
    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=successor_path,
            predecessor_reviewed_sha256=successor_digest,
        )
    assert trapped.hotkey_accesses == 0
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    recovered = axon.recover_ambiguous_preview(
        subtensor=FakeSubtensor(),
        preview_path=successor_path,
        reviewed_sha256=successor_digest,
        state_loader=StateSequence(
            miner_state(
                block=233,
                uid=axon.FINALIZED_SUCCESSOR_UID,
                ip=SUCCESSOR_IP,
                port=axon.SN39_HTTPS_PORT,
                serving=True,
            )
        ),
        runtime_root=tmp_path,
    )
    assert recovered["status"] == "finalized_recovered"
    assert recovered["predecessor_lineage"] == started["predecessor_lineage"]


@pytest.mark.parametrize(
    "corruption", ["lineage_digest", "lineage_generation", "lineage_null", "status"]
)
def test_corrupted_persisted_successor_intent_is_ambiguous_never_no_write(
    tmp_path, monkeypatch, corruption
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    corrupted = json.loads(journal_path.read_text())
    if corruption == "lineage_digest":
        corrupted["predecessor_lineage"]["journal_sha256"] = "sha256:" + "00" * 32
    elif corruption == "lineage_generation":
        corrupted["predecessor_lineage"]["generation"] = 2
    elif corruption == "lineage_null":
        corrupted["predecessor_lineage"] = None
    else:
        corrupted["status"] = "corrupt"
    journal_path.write_bytes(axon._canonical_json_bytes(corrupted))
    before = journal_path.read_bytes()
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        axon.recover_ambiguous_preview(
            subtensor=FakeSubtensor(),
            preview_path=successor_path,
            reviewed_sha256=successor_digest,
            state_loader=StateSequence(
                miner_state(
                    block=233,
                    uid=axon.FINALIZED_SUCCESSOR_UID,
                    ip=SUCCESSOR_IP,
                    port=axon.SN39_HTTPS_PORT,
                    serving=True,
                )
            ),
            runtime_root=tmp_path,
        )

    assert journal_path.read_bytes() == before


def test_uid124_generation2_contract_pins_exact_live_predecessor_and_target():
    contract = axon.UID124_GENERATION2_AXON_CONTRACT

    assert contract.successor_generation == 2
    assert contract.fixed_uid == 124
    assert contract.miner_hotkey == axon.MINER_HOTKEY
    assert contract.endpoint_ip == "35.222.166.235"
    assert contract.endpoint_port == 8081
    assert contract.journal_name == axon.JOURNAL_NAME
    assert contract.lock_name == axon.LOCK_NAME
    assert contract.predecessor_preview_name == (
        "miner-axon-preview-r2-20260828T1940Z.json"
    )
    assert contract.predecessor_preview_sha256 == (
        "27ef74f1f1f9b2cecf762dd850ebe81aa8d0ab03e42c1dc9023961cc7a89ee29"
    )
    assert contract.predecessor_journal_sha256 == (
        "b5b401ad8a1610471b15f2a75546f1ecba19c160d9cc35a361995a5274e48c8f"
    )
    assert contract.require_proven_success_receipt is True
    assert gen2_cli.WALLET_HOTKEY == "serge_sat_test"


def test_generation2_cli_injects_pinned_predecessor_without_generic_switches(
    tmp_path, monkeypatch, capsys
):
    contract = replace(
        axon.UID124_GENERATION2_AXON_CONTRACT,
        runtime_root=tmp_path,
    )
    parser = axon_cli._parser(prog="generation2-test", contract=contract)
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "announce",
                "--reviewed-sha256",
                "11" * 32,
                "--qvl",
                "/reviewed/qvl",
                "--allow-finalized-successor",
            ]
        )
    assert "unrecognized arguments" in capsys.readouterr().err

    captured = {}
    monkeypatch.setattr(axon_cli, "make_subtensor", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(axon_cli, "_wallet", lambda *_args, **_kwargs: object())

    def capture_announce(**kwargs):
        captured.update(kwargs)
        return {"status": "CAPTURED_NO_CHAIN_WRITE"}

    monkeypatch.setattr(axon_cli, "announce_reviewed_preview", capture_announce)
    status = axon_cli.run_contract_cli(
        [
            "announce",
            "--preview",
            str(tmp_path / contract.preview_name),
            "--reviewed-sha256",
            "22" * 32,
            "--qvl",
            "/reviewed/qvl",
            "--confirm-miner-announce",
            "--assert-exclusive-announcer",
        ],
        prog="generation2-test",
        wallet_hotkey=gen2_cli.WALLET_HOTKEY,
        contract=contract,
    )

    assert status == 0
    assert captured["allow_finalized_successor"] is True
    assert captured["predecessor_preview_path"] == (
        tmp_path / axon.UID124_GENERATION1_PREVIEW_NAME
    )
    assert (
        captured["predecessor_reviewed_sha256"]
        == axon.UID124_GENERATION1_PREVIEW_SHA256
    )
    assert captured["contract"] == contract


def test_generation2_preview_exposes_exact_lineage_and_no_unrelated_write(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    contract = setup["contract"]
    preview = setup["preview"]

    assert preview["schema"] == contract.preview_schema
    assert preview["miner"] == {
        "uid": 124,
        "hotkey": axon.MINER_HOTKEY,
        "coldkey": axon.CATHEDRAL_COLDKEY,
    }
    assert preview["requested_endpoint"] == {
        "ip": axon.UID124_GENERATION2_ENDPOINT_IP,
        "port": 8081,
        "protocol": "https",
    }
    assert preview["successor_contract"] == {
        "journal_generation": 2,
        "predecessor_preview": str(setup["predecessor_preview_path"]),
        "predecessor_preview_sha256": "sha256:" + setup["predecessor_preview_digest"],
        "predecessor_journal": str(setup["journal_path"]),
        "predecessor_journal_sha256": "sha256:"
        + hashlib.sha256(setup["predecessor_bytes"]).hexdigest(),
        "replacement_limit": "exactly_one_generation_2_attempt",
    }
    assert preview["chain_action"]["serve_axon_called"] is False
    assert preview["chain_action"]["registration_called"] is False
    assert preview["chain_action"]["weights_called"] is False


def test_generation2_preserves_baseline_to_generation1_to_generation2_lineage(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    contract = setup["contract"]
    current = setup["current"]
    target = replace(
        current,
        block_number=402,
        block_hash=chain_hash(402),
        ip=axon.UID124_GENERATION2_ENDPOINT_IP,
        port=axon.SN39_HTTPS_PORT,
        is_serving=True,
    )
    calls = []

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=setup["preview_path"],
        digest=setup["preview_digest"],
        state_loader=StateSequence(
            current,
            replace(current, block_number=401, block_hash=chain_hash(401)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: setup["proof"],
        serve_call=lambda **kwargs: (calls.append(kwargs), response_at(402))[1],
        allow_finalized_successor=True,
        predecessor_preview_path=setup["predecessor_preview_path"],
        predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
        contract=contract,
    )

    assert result["status"] == "finalized_proven"
    assert result["journal_generation"] == 2
    assert result["predecessor_lineage"]["generation"] == 2
    assert (
        axon._canonical_json_bytes(result["predecessor_lineage"]["journal"])
        == setup["predecessor_bytes"]
    )
    generation1 = result["predecessor_lineage"]["journal"]
    assert generation1["journal_generation"] == 1
    assert generation1["predecessor_lineage"]["generation"] == 1
    baseline = generation1["predecessor_lineage"]["journal"]
    assert baseline["schema"] == axon.JOURNAL_SCHEMA
    assert "journal_generation" not in baseline
    assert result["readback"]["axon"] == {
        "ip": axon.UID124_GENERATION2_ENDPOINT_IP,
        "port": 8081,
        "is_serving": True,
    }
    assert len(calls) == 1
    assert calls[0]["axon"].external_ip == axon.UID124_GENERATION2_ENDPOINT_IP
    assert "weights" not in result
    assert "registration" not in result

    recovered = axon.recover_ambiguous_preview(
        subtensor=FakeSubtensor(),
        preview_path=setup["preview_path"],
        reviewed_sha256=setup["preview_digest"],
        state_loader=StateSequence(
            replace(target, block_number=403, block_hash=chain_hash(403))
        ),
        runtime_root=tmp_path,
        contract=contract,
    )
    assert recovered == result

    trapped = UnlockTrapWallet()
    replay = announce(
        tmp_path,
        monkeypatch,
        preview_path=setup["preview_path"],
        digest=setup["preview_digest"],
        state_loader=StateSequence(
            replace(target, block_number=404, block_hash=chain_hash(404))
        ),
        selected_wallet=trapped,
        serve_call=lambda **_kwargs: pytest.fail(
            "consumed generation-2 contract called serve_axon"
        ),
        allow_finalized_successor=True,
        predecessor_preview_path=setup["predecessor_preview_path"],
        predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
        contract=contract,
    )
    assert replay == result
    assert trapped.hotkey_accesses == 0
    assert len(calls) == 1


@pytest.mark.parametrize("generation", [1, 3])
def test_generation2_rejects_swapped_lineage_marker(tmp_path, monkeypatch, generation):
    setup = generation2_review(tmp_path, monkeypatch)
    current = setup["current"]
    lineage = {
        "generation": 2,
        "journal_sha256": "sha256:"
        + hashlib.sha256(setup["predecessor_bytes"]).hexdigest(),
        "journal": setup["generation1_journal"],
    }
    journal = axon._journal_for_attempt(
        preview=setup["preview"],
        preview_sha256=setup["preview_digest"],
        fresh=setup["proof"],
        state=current,
        predecessor_lineage=lineage,
        successor_generation=2,
        contract=setup["contract"],
    )
    journal["predecessor_lineage"]["generation"] = generation

    with pytest.raises(axon.MinerAxonError, match="generation"):
        axon._validated_successor_journal(journal)


def test_generation2_rejects_an_embedded_generation2_predecessor(tmp_path, monkeypatch):
    setup = generation2_review(tmp_path, monkeypatch)
    current = setup["current"]
    nested_generation2 = axon._journal_for_attempt(
        preview=setup["preview"],
        preview_sha256=setup["preview_digest"],
        fresh=setup["proof"],
        state=current,
        predecessor_lineage={
            "generation": 2,
            "journal_sha256": "sha256:"
            + hashlib.sha256(setup["predecessor_bytes"]).hexdigest(),
            "journal": setup["generation1_journal"],
        },
        successor_generation=2,
        contract=setup["contract"],
    )
    nested_bytes = axon._canonical_json_bytes(nested_generation2)
    outer = axon._journal_for_attempt(
        preview=setup["preview"],
        preview_sha256=setup["preview_digest"],
        fresh=setup["proof"],
        state=current,
        predecessor_lineage={
            "generation": 2,
            "journal_sha256": "sha256:" + hashlib.sha256(nested_bytes).hexdigest(),
            "journal": nested_generation2,
        },
        successor_generation=2,
        contract=setup["contract"],
    )

    with pytest.raises(axon.MinerAxonError, match="generation-1 journal"):
        axon._validated_successor_journal(outer)


def test_generation2_refuses_wrong_exact_journal_pin_before_signing_or_chain(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    bad_contract = replace(setup["contract"], predecessor_journal_sha256="00" * 32)
    bad_path, bad_digest, _ = write_review(
        tmp_path,
        state=setup["current"],
        proof=setup["proof"],
        name="bad-pin-generation2.json",
        contract=bad_contract,
    )
    before = setup["journal_path"].read_bytes()
    trapped = UnlockTrapWallet()

    with pytest.raises(axon.MinerAxonError, match="journal differs"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=bad_path,
            digest=bad_digest,
            state_loader=lambda _subtensor: pytest.fail(
                "bad journal pin reached chain state"
            ),
            selected_wallet=trapped,
            serve_call=lambda **_kwargs: pytest.fail("bad journal pin called serve"),
            allow_finalized_successor=True,
            predecessor_preview_path=setup["predecessor_preview_path"],
            predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
            contract=bad_contract,
        )

    assert trapped.hotkey_accesses == 0
    assert setup["journal_path"].read_bytes() == before


def test_generation2_incomplete_success_receipt_is_recovered_not_proven(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    current = setup["current"]
    target = replace(
        current,
        block_number=402,
        block_hash=chain_hash(402),
        ip=axon.UID124_GENERATION2_ENDPOINT_IP,
        port=8081,
        is_serving=True,
    )

    result = announce(
        tmp_path,
        monkeypatch,
        preview_path=setup["preview_path"],
        digest=setup["preview_digest"],
        state_loader=StateSequence(
            current,
            replace(current, block_number=401, block_hash=chain_hash(401)),
            target,
        ),
        proof_loader=lambda *_args, **_kwargs: setup["proof"],
        serve_call=lambda **_kwargs: response_at(None),
        allow_finalized_successor=True,
        predecessor_preview_path=setup["predecessor_preview_path"],
        predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
        contract=setup["contract"],
    )

    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert result["receipt"] is None
    assert result["readback"]["finalized_block_number"] == 402
    assert result["retry_allowed"] is False


def test_generation2_refuses_wrong_exact_predecessor_preview_pin_before_signing(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    bad_contract = replace(setup["contract"], predecessor_preview_sha256="00" * 32)
    bad_path, bad_digest, _ = write_review(
        tmp_path,
        state=setup["current"],
        proof=setup["proof"],
        name="bad-preview-pin-generation2.json",
        contract=bad_contract,
    )
    before = setup["journal_path"].read_bytes()
    trapped = UnlockTrapWallet()

    with pytest.raises(axon.MinerAxonError, match="preview digest differs"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=bad_path,
            digest=bad_digest,
            state_loader=lambda _subtensor: pytest.fail(
                "bad predecessor preview pin reached chain state"
            ),
            selected_wallet=trapped,
            serve_call=lambda **_kwargs: pytest.fail(
                "bad predecessor preview pin called serve"
            ),
            allow_finalized_successor=True,
            predecessor_preview_path=setup["predecessor_preview_path"],
            predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
            contract=bad_contract,
        )

    assert trapped.hotkey_accesses == 0
    assert setup["journal_path"].read_bytes() == before


def test_generation2_refuses_wrong_signer_before_journal_replacement_or_call(
    tmp_path, monkeypatch
):
    setup = generation2_review(tmp_path, monkeypatch)
    current = setup["current"]
    before = setup["journal_path"].read_bytes()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="wallet"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=setup["preview_path"],
            digest=setup["preview_digest"],
            state_loader=StateSequence(
                current,
                replace(current, block_number=401, block_hash=chain_hash(401)),
            ),
            proof_loader=lambda *_args, **_kwargs: setup["proof"],
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=wallet(hotkey=axon.VALIDATOR_HOTKEY),
            allow_finalized_successor=True,
            predecessor_preview_path=setup["predecessor_preview_path"],
            predecessor_reviewed_sha256=setup["predecessor_preview_digest"],
            contract=setup["contract"],
        )

    assert calls == []
    assert setup["journal_path"].read_bytes() == before


@pytest.mark.parametrize(
    "corruption",
    [
        "schema",
        "journal_kind",
        "journal_generation",
        "status",
        "attempt_id",
        "identity",
        "preflight",
        "fresh_endpoint_proof",
        "fresh_endpoint_proof_non_mapping",
        "remote_exclusive_announcer_asserted",
        "serve_axon_call_authorized",
        "serve_axon_outcome",
        "receipt",
        "readback",
        "retry_allowed",
        "predecessor_lineage",
        "extra_field",
        "delete_schema",
        "delete_journal_kind",
        "delete_journal_generation",
        "delete_predecessor_lineage",
        "only_attempt_marker",
        "malformed_json",
    ],
)
def test_every_persisted_successor_invariant_corruption_is_ambiguous_no_rewrite(
    tmp_path, monkeypatch, corruption
):
    (
        predecessor_path,
        predecessor_digest,
        _,
        successor_path,
        successor_digest,
        _,
        journal_path,
        started,
    ) = persisted_started_successor(tmp_path, monkeypatch)
    corrupted = json.loads(json.dumps(started))
    if corruption == "schema":
        corrupted["schema"] = axon.JOURNAL_SCHEMA
    elif corruption == "journal_kind":
        corrupted["journal_kind"] = "other"
    elif corruption == "journal_generation":
        corrupted["journal_generation"] = 2
    elif corruption == "status":
        corrupted["status"] = "corrupt"
    elif corruption == "attempt_id":
        corrupted["attempt_id"] = "successor-sha256:" + "00" * 32
    elif corruption == "identity":
        corrupted["identity"]["preview_sha256"] = corrupted["predecessor_lineage"][
            "journal"
        ]["identity"]["preview_sha256"]
    elif corruption == "preflight":
        corrupted["preflight"]["finalized_block_number"] += 1
    elif corruption == "fresh_endpoint_proof":
        corrupted["fresh_endpoint_proof"]["tls_spki_sha256"] = "ff" * 32
    elif corruption == "fresh_endpoint_proof_non_mapping":
        corrupted["fresh_endpoint_proof"] = []
    elif corruption == "remote_exclusive_announcer_asserted":
        corrupted["remote_exclusive_announcer_asserted"] = False
    elif corruption == "serve_axon_call_authorized":
        corrupted["serve_axon_call_authorized"] = False
    elif corruption == "serve_axon_outcome":
        corrupted["serve_axon_outcome"] = "SUCCESS"
    elif corruption == "receipt":
        corrupted["receipt"] = {
            "extrinsic_hash": "0x" + "ab" * 32,
            "block_hash": chain_hash(232),
            "block_number": 232,
            "success": True,
        }
    elif corruption == "readback":
        corrupted["readback"] = miner_state(
            block=232,
            uid=axon.FINALIZED_SUCCESSOR_UID,
            ip=SUCCESSOR_IP,
            port=axon.SN39_HTTPS_PORT,
            serving=True,
        ).artifact()
    elif corruption == "retry_allowed":
        corrupted["retry_allowed"] = True
    elif corruption == "predecessor_lineage":
        corrupted["predecessor_lineage"]["journal_sha256"] = "sha256:" + "00" * 32
    elif corruption == "extra_field":
        corrupted["unreviewed"] = True
    elif corruption == "delete_schema":
        del corrupted["schema"]
    elif corruption == "delete_journal_kind":
        del corrupted["journal_kind"]
    elif corruption == "delete_journal_generation":
        del corrupted["journal_generation"]
    elif corruption == "delete_predecessor_lineage":
        del corrupted["predecessor_lineage"]
    elif corruption == "only_attempt_marker":
        corrupted["schema"] = axon.JOURNAL_SCHEMA
        del corrupted["journal_kind"]
        del corrupted["journal_generation"]
        del corrupted["predecessor_lineage"]

    if corruption == "malformed_json":
        journal_path.write_bytes(b'{"schema":')
    else:
        journal_path.write_bytes(axon._canonical_json_bytes(corrupted))
    before = journal_path.read_bytes()
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=lambda _subtensor: (_ for _ in ()).throw(
                AssertionError("corrupt successor reached chain state")
            ),
            selected_wallet=trapped,
            serve_call=lambda **kwargs: calls.append(kwargs),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


@pytest.mark.parametrize(
    "corruption",
    [
        "proven_outcome",
        "proven_receipt_null",
        "proven_receipt_unsuccessful",
        "proven_readback_null",
        "recovered_outcome",
        "recovered_receipt_malformed",
        "recovered_readback_null",
        "stored_final_equals_preflight",
        "receipt_equals_preflight",
    ],
)
def test_finalized_successor_status_shape_corruption_is_ambiguous_no_rewrite(
    tmp_path, monkeypatch, corruption
):
    (
        predecessor_path,
        predecessor_digest,
        successor_path,
        successor_digest,
        _,
        _,
        journal_path,
        finalized,
    ) = persisted_finalized_successor(tmp_path, monkeypatch)
    corrupted = json.loads(json.dumps(finalized))
    if corruption == "proven_outcome":
        corrupted["serve_axon_outcome"] = "FINALIZED_BY_READBACK"
    elif corruption == "proven_receipt_null":
        corrupted["receipt"] = None
    elif corruption == "proven_receipt_unsuccessful":
        corrupted["receipt"]["success"] = False
    elif corruption == "proven_readback_null":
        corrupted["readback"] = None
    else:
        corrupted["status"] = "finalized_recovered"
        corrupted["serve_axon_outcome"] = "FINALIZED_BY_READBACK"
        corrupted["receipt"] = None
        if corruption == "recovered_outcome":
            corrupted["serve_axon_outcome"] = "SUCCESS"
        elif corruption == "recovered_receipt_malformed":
            corrupted["receipt"] = {"success": True}
        elif corruption == "recovered_readback_null":
            corrupted["readback"] = None
        elif corruption == "stored_final_equals_preflight":
            corrupted["readback"] = json.loads(json.dumps(corrupted["preflight"]))
            corrupted["readback"]["axon"] = {
                "ip": SUCCESSOR_IP,
                "port": axon.SN39_HTTPS_PORT,
                "is_serving": True,
            }
        elif corruption == "receipt_equals_preflight":
            block = corrupted["preflight"]["finalized_block_number"]
            corrupted["receipt"] = {
                "extrinsic_hash": "0x" + "ab" * 32,
                "block_hash": chain_hash(block),
                "block_number": block,
                "success": True,
            }
    journal_path.write_bytes(axon._canonical_json_bytes(corrupted))
    before = journal_path.read_bytes()
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=lambda _subtensor: (_ for _ in ()).throw(
                AssertionError("corrupt final successor reached chain state")
            ),
            selected_wallet=trapped,
            serve_call=lambda **kwargs: calls.append(kwargs),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_successor_recovery_persistence_failure_remains_ambiguous(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    before = journal_path.read_bytes()
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    monkeypatch.setattr(
        axon,
        "_write_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("simulated recovery persistence failure")
        ),
    )
    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        axon.recover_ambiguous_preview(
            subtensor=FakeSubtensor(),
            preview_path=successor_path,
            reviewed_sha256=successor_digest,
            state_loader=StateSequence(
                miner_state(
                    block=233,
                    uid=axon.FINALIZED_SUCCESSOR_UID,
                    ip=SUCCESSOR_IP,
                    port=axon.SN39_HTTPS_PORT,
                    serving=True,
                )
            ),
            runtime_root=tmp_path,
        )

    assert journal_path.read_bytes() == before


def test_successor_final_persistence_failure_recovers_without_second_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, _, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    original_write = axon._write_state
    fail_final = {"enabled": True}
    calls = []

    def persistence_fault(path, document, *, exclusive):
        if (
            fail_final["enabled"]
            and document.get("predecessor_lineage") is not None
            and document.get("status") == "finalized_proven"
        ):
            raise OSError("simulated final persistence failure")
        return original_write(path, document, exclusive=exclusive)

    monkeypatch.setattr(axon, "_write_state", persistence_fault)

    def serve_call(**kwargs):
        calls.append(kwargs)
        return response_at(232)

    with pytest.raises(axon.MinerAxonAmbiguous, match="persistence failed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
                target,
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=serve_call,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    fail_final["enabled"] = False
    monkeypatch.setattr(axon, "DEFAULT_RUNTIME_ROOT", tmp_path)
    recovered = axon.recover_ambiguous_preview(
        subtensor=FakeSubtensor(),
        preview_path=successor_path,
        reviewed_sha256=successor_digest,
        state_loader=StateSequence(
            replace(target, block_number=233, block_hash=chain_hash(233))
        ),
        runtime_root=tmp_path,
    )
    assert recovered["status"] == "finalized_recovered"
    assert len(calls) == 1


def test_successor_external_writer_at_target_is_refused_not_laundered(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    external_target = replace(current, ip=SUCCESSOR_IP)
    trapped = UnlockTrapWallet()

    with pytest.raises(axon.MinerAxonError, match="axon changed"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(external_target),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_receipt_after_predecessor_readback_is_refused(tmp_path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    predecessor = json.loads(journal_path.read_text())
    predecessor["receipt"].update({"block_number": 103, "block_hash": chain_hash(103)})
    journal_path.write_bytes(axon._canonical_json_bytes(predecessor))
    before = journal_path.read_bytes()
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()

    with pytest.raises(axon.MinerAxonError, match="postdates"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert journal_path.read_bytes() == before


def test_successor_partial_opt_in_arguments_refuse_before_preview_or_unlock(
    tmp_path, monkeypatch
):
    trapped = UnlockTrapWallet()
    missing = tmp_path / "missing.json"

    with pytest.raises(axon.MinerAxonError, match="requires the reviewed predecessor"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=missing,
            digest="00" * 32,
            state_loader=StateSequence(miner_state()),
            selected_wallet=trapped,
            allow_finalized_successor=True,
        )
    with pytest.raises(axon.MinerAxonError, match="require --allow"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=missing,
            digest="00" * 32,
            state_loader=StateSequence(miner_state()),
            selected_wallet=trapped,
            predecessor_preview_path=missing,
        )

    assert trapped.hotkey_accesses == 0


@pytest.mark.parametrize(
    "corruption",
    [
        "extra_field",
        "wrong_readback_hotkey",
        "readback_endpoint_mismatch",
        "preflight_already_target",
    ],
)
def test_successor_refuses_malformed_or_wrong_pin_predecessor(
    tmp_path, monkeypatch, corruption
):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    predecessor = json.loads(journal_path.read_text())
    if corruption == "extra_field":
        predecessor["unreviewed"] = True
    elif corruption == "wrong_readback_hotkey":
        predecessor["readback"]["hotkey"] = axon.VALIDATOR_HOTKEY
    elif corruption == "readback_endpoint_mismatch":
        predecessor["readback"]["axon"]["ip"] = SUCCESSOR_IP
    else:
        predecessor["preflight"]["axon"] = {
            "ip": SERVICE_IP,
            "port": axon.SN39_HTTPS_PORT,
            "is_serving": True,
        }
    journal_path.write_bytes(axon._canonical_json_bytes(predecessor))
    before = journal_path.read_bytes()
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == before


def test_finalized_successor_is_pinned_to_uid124_before_unlock_or_call(
    tmp_path, monkeypatch
):
    initial = miner_state(uid=17)
    predecessor_path, predecessor_digest, _ = write_review(
        tmp_path,
        state=initial,
        name="uid17-predecessor.json",
    )
    served = miner_state(
        block=102,
        uid=17,
        ip=SERVICE_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    announce(
        tmp_path,
        monkeypatch,
        preview_path=predecessor_path,
        digest=predecessor_digest,
        state_loader=StateSequence(initial, initial, served),
        serve_call=lambda **_kwargs: FakeResponse(),
    )
    successor_path, successor_digest, _ = write_review(
        tmp_path,
        state=replace(served, block_number=230, block_hash=chain_hash(230)),
        proof=endpoint_proof(ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32),
        name="uid17-successor.json",
    )
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="pinned to miner UID 124"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(served),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []


def test_successor_uses_the_existing_stable_lock_and_preserves_final_on_contention(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, document, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    assert document["local_state"]["announcement_lock"] == str(
        tmp_path / axon.LOCK_NAME
    )
    with axon._announcement_lock(tmp_path):
        with pytest.raises(axon.MinerAxonError, match="another local"):
            announce(
                tmp_path,
                monkeypatch,
                preview_path=successor_path,
                digest=successor_digest,
                state_loader=StateSequence(current),
                serve_call=lambda **kwargs: calls.append(kwargs),
                selected_wallet=trapped,
                allow_finalized_successor=True,
                predecessor_preview_path=predecessor_path,
                predecessor_reviewed_sha256=predecessor_digest,
            )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_fresh_spki_drift_refuses_before_unlock_or_call(
    tmp_path, monkeypatch
):
    predecessor_path, predecessor_digest, _, journal_path, predecessor_bytes = (
        finalized_predecessor(tmp_path, monkeypatch)
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    trapped = UnlockTrapWallet()
    calls = []

    with pytest.raises(axon.MinerAxonError, match="tls_spki"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(current),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="ff" * 32
            ),
            serve_call=lambda **kwargs: calls.append(kwargs),
            selected_wallet=trapped,
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert trapped.hotkey_accesses == 0
    assert calls == []
    assert journal_path.read_bytes() == predecessor_bytes


def test_successor_noncanonical_target_readback_stays_ambiguous(tmp_path, monkeypatch):
    predecessor_path, predecessor_digest, _, journal_path, _ = finalized_predecessor(
        tmp_path, monkeypatch
    )
    successor_path, successor_digest, _, current, _ = successor_review(tmp_path)
    noncanonical_target = miner_state(
        block=232,
        uid=axon.FINALIZED_SUCCESSOR_UID,
        ip=SUCCESSOR_IP,
        port=axon.SN39_HTTPS_PORT,
        serving=True,
    )
    noncanonical_target = replace(noncanonical_target, block_hash=chain_hash(999))

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            tmp_path,
            monkeypatch,
            preview_path=successor_path,
            digest=successor_digest,
            state_loader=StateSequence(
                current,
                replace(current, block_number=231, block_hash=chain_hash(231)),
                noncanonical_target,
                noncanonical_target,
            ),
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                ip=SUCCESSOR_IP, tls_spki_sha256="55" * 32
            ),
            serve_call=lambda **_kwargs: response_at(232),
            allow_finalized_successor=True,
            predecessor_preview_path=predecessor_path,
            predecessor_reviewed_sha256=predecessor_digest,
        )

    assert json.loads(journal_path.read_text())["status"] == "submission_ambiguous"


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
