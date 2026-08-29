from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin.independent.compute import QuoteVerdict
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import miner_axon as axon
from cathedral_thin.independent_runtime import second_miner_axon_cli as cli
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST

SECOND_IP = axon.SECOND_MINER_ENDPOINT_IP
SECOND_UID = 201


def chain_hash(number: int) -> str:
    return f"0x{number:064x}"


def isolated_contract(tmp_path: Path) -> axon.MinerAxonContract:
    return replace(axon.SECOND_MINER_AXON_CONTRACT, runtime_root=tmp_path)


def miner_state(
    *,
    block: int = 100,
    uid: int = SECOND_UID,
    hotkey: str = axon.SECOND_MINER_HOTKEY,
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
        "hotkey": axon.SECOND_MINER_HOTKEY,
        "validator_hotkey": axon.VALIDATOR_HOTKEY,
        "ip": SECOND_IP,
        "port": axon.SN39_HTTPS_PORT,
        "qvl": QuoteVerdict.PASS.value,
        "qvl_digest": LAUNCH_QVL_DIGEST,
        "sat_units": 20,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "tls_spki_sha256": "55" * 32,
        "nonce_sha256": "66" * 32,
        "quote_sha256": "77" * 32,
        "report_data_sha256": "88" * 32,
        "anchor_number": 90,
        "anchor_hash": chain_hash(90),
    }
    values.update(overrides)
    return axon.EndpointProof(**values)


def wallet(*, hotkey: str = axon.SECOND_MINER_HOTKEY):
    return SimpleNamespace(
        hotkey=SimpleNamespace(ss58_address=hotkey),
        coldkeypub=SimpleNamespace(ss58_address=axon.CATHEDRAL_COLDKEY),
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


def write_review(
    tmp_path: Path,
    *,
    contract: axon.MinerAxonContract,
    state: axon.FinalizedMinerState | None = None,
    proof: axon.EndpointProof | None = None,
) -> tuple[Path, str, dict]:
    document = axon.build_preview(
        state=state or miner_state(),
        proof=proof or endpoint_proof(),
        contract=contract,
        created_at="2026-08-28T19:30:00Z",
    )
    path, _, digest = axon.write_preview(
        document, contract.preview_path, contract=contract
    )
    return path, digest, document


def announce(
    *,
    contract: axon.MinerAxonContract,
    preview_path: Path,
    digest: str,
    state_loader,
    serve_call,
    selected_wallet=None,
):
    return axon.announce_reviewed_preview(
        bt_module=FakeBt,
        subtensor=FakeSubtensor(),
        wallet=selected_wallet or wallet(),
        preview_path=preview_path,
        reviewed_sha256=digest,
        qvl_path="/reviewed/qvl",
        confirm=True,
        exclusive_announcer_asserted=True,
        state_loader=state_loader,
        proof_loader=lambda *_args, **_kwargs: endpoint_proof(),
        serve_call=serve_call,
        runtime_root=contract.runtime_root,
        contract=contract,
    )


def response_at(block: int = 102):
    return SimpleNamespace(
        success=True,
        extrinsic_receipt=SimpleNamespace(
            extrinsic_hash="0x" + "ab" * 32,
            block_hash=chain_hash(block),
            block_number=block,
        ),
    )


def test_second_contract_has_distinct_identity_schema_and_local_lineage():
    second = axon.SECOND_MINER_AXON_CONTRACT
    first = axon.UID124_AXON_CONTRACT

    assert second.miner_hotkey == axon.SECOND_MINER_HOTKEY
    assert second.miner_hotkey != first.miner_hotkey
    assert second.runtime_root != first.runtime_root
    assert second.preview_name != first.preview_name
    assert second.journal_name != first.journal_name
    assert second.lock_name != first.lock_name
    assert second.preview_schema != first.preview_schema
    assert second.journal_schema != first.journal_schema
    assert second.supports_legacy_successor is False
    assert second.first_announcement_only is True
    assert second.require_proven_success_receipt is True
    assert second.fixed_uid is None
    assert cli.WALLET_HOTKEY == "serge_sat_test_2"


def test_preview_binds_finalized_dynamic_uid_and_exact_endpoint(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, document = write_review(tmp_path, contract=contract)

    assert document["schema"] == contract.preview_schema
    assert document["miner"] == {
        "uid": SECOND_UID,
        "hotkey": axon.SECOND_MINER_HOTKEY,
        "coldkey": axon.CATHEDRAL_COLDKEY,
    }
    assert document["requested_endpoint"] == {
        "ip": SECOND_IP,
        "port": 8081,
        "protocol": "https",
    }
    assert document["local_state"] == {
        "runtime_root": str(tmp_path),
        "announcement_lock": str(tmp_path / contract.lock_name),
        "ambiguity_journal": str(tmp_path / contract.journal_name),
        "remote_exclusivity": "operator_assertion_required",
    }
    loaded, observed = axon.load_reviewed_preview(
        path, reviewed_sha256=digest, contract=contract
    )
    assert loaded == document
    assert observed == digest


def test_preview_refuses_any_endpoint_other_than_the_bounded_machine(tmp_path):
    contract = isolated_contract(tmp_path)
    with pytest.raises(axon.MinerAxonError, match="bounded"):
        axon.build_preview(
            state=miner_state(),
            proof=endpoint_proof(ip="8.8.8.8"),
            contract=contract,
        )


@pytest.mark.parametrize(
    ("ip", "port", "serving"),
    [
        ("1.1.1.1", 8081, True),
        ("1.1.1.1", 0, False),
        (SECOND_IP, 0, False),
    ],
)
def test_first_time_preview_refuses_every_noncanonical_existing_axon(
    tmp_path, ip, port, serving
):
    contract = isolated_contract(tmp_path)
    with pytest.raises(axon.MinerAxonError, match="successor lineage"):
        axon.build_preview(
            state=miner_state(ip=ip, port=port, serving=serving),
            proof=endpoint_proof(),
            contract=contract,
        )


def test_second_schema_cannot_load_a_uid124_preview(tmp_path):
    first = replace(axon.UID124_AXON_CONTRACT, runtime_root=tmp_path)
    first_preview = axon.build_preview(
        state=replace(miner_state(), hotkey=axon.MINER_HOTKEY),
        proof=replace(
            endpoint_proof(),
            hotkey=axon.MINER_HOTKEY,
            ip="8.8.8.8",
        ),
        runtime_root=tmp_path,
        contract=first,
        created_at="2026-08-28T19:30:00Z",
    )
    path, _, digest = axon.write_preview(
        first_preview, tmp_path / "uid124.json", contract=first
    )

    with pytest.raises(axon.MinerAxonError, match="schema"):
        axon.load_reviewed_preview(
            path,
            reviewed_sha256=digest,
            contract=isolated_contract(tmp_path),
        )


def test_wrong_signing_hotkey_refuses_before_journal_or_serve(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    called = []

    with pytest.raises(axon.MinerAxonError, match="wallet"):
        announce(
            contract=contract,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(), miner_state()),
            serve_call=lambda **kwargs: called.append(kwargs),
            selected_wallet=wallet(hotkey=axon.MINER_HOTKEY),
        )

    assert called == []
    assert not (tmp_path / contract.journal_name).exists()


def test_exact_target_is_a_no_write_result_without_a_journal(tmp_path):
    contract = isolated_contract(tmp_path)
    served = miner_state(ip=SECOND_IP, port=8081, serving=True)
    path, digest, document = write_review(tmp_path, contract=contract, state=served)
    assert document["status"] == axon.PREVIEW_ALREADY

    result = announce(
        contract=contract,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(served),
        serve_call=lambda **_kwargs: pytest.fail("exact target must not resubmit"),
    )

    assert result["status"] == "already_announced_no_write"
    assert result["serve_axon_called"] is False
    assert not (tmp_path / contract.journal_name).exists()


def test_uid_reassignment_after_review_refuses_before_proof_or_serve(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    called = []

    with pytest.raises(axon.MinerAxonError, match="registration changed"):
        announce(
            contract=contract,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(uid=202)),
            serve_call=lambda **kwargs: called.append(kwargs),
        )

    assert called == []
    assert not (tmp_path / contract.journal_name).exists()


def test_fresh_spki_drift_refuses_before_journal_or_serve(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    called = []

    with pytest.raises(axon.MinerAxonError, match="tls_spki"):
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
            proof_loader=lambda *_args, **_kwargs: endpoint_proof(
                tls_spki_sha256="99" * 32
            ),
            serve_call=lambda **kwargs: called.append(kwargs),
            runtime_root=tmp_path,
            contract=contract,
        )

    assert called == []
    assert not (tmp_path / contract.journal_name).exists()


def test_one_attempt_uses_exact_bittensor_10_5_contract_and_finalized_readback(
    tmp_path,
):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    served = miner_state(block=102, ip=SECOND_IP, port=8081, serving=True)
    calls = []

    def serve(
        *,
        netuid,
        axon,
        mev_protection,
        period,
        raise_error,
        wait_for_inclusion,
        wait_for_finalization,
    ):
        calls.append(
            {
                "netuid": netuid,
                "axon": axon,
                "mev_protection": mev_protection,
                "period": period,
                "raise_error": raise_error,
                "wait_for_inclusion": wait_for_inclusion,
                "wait_for_finalization": wait_for_finalization,
            }
        )
        return response_at()

    result = announce(
        contract=contract,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(miner_state(), miner_state(), served),
        serve_call=serve,
    )

    assert result["status"] == "finalized_proven"
    assert result["readback"]["uid"] == SECOND_UID
    assert result["readback"]["hotkey"] == axon.SECOND_MINER_HOTKEY
    assert result["readback"]["axon"] == {
        "ip": SECOND_IP,
        "port": 8081,
        "is_serving": True,
    }
    assert len(calls) == 1
    call = calls[0]
    assert {key: value for key, value in call.items() if key != "axon"} == {
        "netuid": 39,
        "mev_protection": False,
        "period": 128,
        "raise_error": True,
        "wait_for_inclusion": True,
        "wait_for_finalization": True,
    }
    assert call["axon"].external_ip == SECOND_IP
    assert call["axon"].external_port == 8081
    journal = json.loads((tmp_path / contract.journal_name).read_text())
    assert journal["schema"] == contract.journal_schema
    assert journal["identity"]["uid"] == SECOND_UID
    assert journal["identity"]["hotkey"] == axon.SECOND_MINER_HOTKEY
    assert journal["retry_allowed"] is False
    assert not (tmp_path / axon.JOURNAL_NAME).exists()


def test_incomplete_success_receipt_is_recovered_by_readback_not_proven(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    served = miner_state(block=102, ip=SECOND_IP, port=8081, serving=True)
    incomplete = SimpleNamespace(
        success=True,
        extrinsic_receipt=SimpleNamespace(
            extrinsic_hash=None,
            block_hash=None,
            block_number=None,
        ),
    )

    result = announce(
        contract=contract,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(miner_state(), miner_state(), served),
        serve_call=lambda **_kwargs: incomplete,
    )

    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert result["receipt"] is None
    assert result["retry_allowed"] is False


def test_success_receipt_at_preflight_block_is_not_finalized_proof(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    served = miner_state(block=102, ip=SECOND_IP, port=8081, serving=True)

    result = announce(
        contract=contract,
        preview_path=path,
        digest=digest,
        state_loader=StateSequence(miner_state(), miner_state(), served),
        serve_call=lambda **_kwargs: response_at(block=100),
    )

    assert result["status"] == "finalized_recovered"
    assert result["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert result["receipt"] is None


def test_sdk_exception_is_ambiguous_and_persistently_fenced(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("secret backend detail")

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            contract=contract,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(), miner_state(), miner_state()),
            serve_call=fail,
        )

    assert len(calls) == 1
    journal = json.loads((tmp_path / contract.journal_name).read_text())
    assert journal["status"] == "submission_ambiguous"
    assert journal["serve_axon_outcome"] == "SDK_EXCEPTION"
    assert journal["retry_allowed"] is False
    assert "secret backend detail" not in json.dumps(journal)

    with pytest.raises(axon.MinerAxonAmbiguous, match="do not retry"):
        announce(
            contract=contract,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state()),
            serve_call=lambda **_kwargs: pytest.fail("must never retry"),
        )
    assert len(calls) == 1


def test_ambiguous_recovery_reads_finalized_state_without_resubmission(tmp_path):
    contract = isolated_contract(tmp_path)
    path, digest, _ = write_review(tmp_path, contract=contract)

    with pytest.raises(axon.MinerAxonAmbiguous):
        announce(
            contract=contract,
            preview_path=path,
            digest=digest,
            state_loader=StateSequence(miner_state(), miner_state(), miner_state()),
            serve_call=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError()),
        )

    served = miner_state(block=103, ip=SECOND_IP, port=8081, serving=True)
    recovered = axon.recover_ambiguous_preview(
        subtensor=FakeSubtensor(),
        preview_path=path,
        reviewed_sha256=digest,
        state_loader=StateSequence(served),
        runtime_root=tmp_path,
        contract=contract,
    )
    assert recovered["status"] == "finalized_recovered"
    assert recovered["serve_axon_outcome"] == "FINALIZED_BY_READBACK"
    assert recovered["retry_allowed"] is False


def test_unregistered_second_hotkey_has_no_previewable_uid():
    class Substrate(FakeSubstrate):
        def get_chain_finalised_head(self):
            return chain_hash(100)

        def get_block_number(self, block_hash):
            return int(block_hash, 16)

    first_row = SimpleNamespace(ip="0.0.0.0", port=0, is_serving=False)
    metagraph = SimpleNamespace(
        uids=[124],
        hotkeys=[axon.MINER_HOTKEY],
        coldkeys=[axon.CATHEDRAL_COLDKEY],
        axons=[first_row],
    )
    subtensor = SimpleNamespace(
        substrate=Substrate(),
        metagraph=lambda *_args, **_kwargs: metagraph,
    )

    with pytest.raises(axon.MinerAxonError, match="registered exactly once"):
        axon.finalized_miner_state(subtensor, contract=axon.SECOND_MINER_AXON_CONTRACT)


def test_registered_second_hotkey_normalizes_chain_ip_zero_to_canonical_unannounced():
    class Substrate(FakeSubstrate):
        def get_chain_finalised_head(self):
            return chain_hash(100)

        def get_block_number(self, block_hash):
            return int(block_hash, 16)

    metagraph = SimpleNamespace(
        uids=[8],
        hotkeys=[axon.SECOND_MINER_HOTKEY],
        coldkeys=[axon.CATHEDRAL_COLDKEY],
        axons=[SimpleNamespace(ip=0, port=0, is_serving=False)],
    )
    subtensor = SimpleNamespace(
        substrate=Substrate(),
        metagraph=lambda *_args, **_kwargs: metagraph,
    )

    state = axon.finalized_miner_state(
        subtensor, contract=axon.SECOND_MINER_AXON_CONTRACT
    )

    assert state.uid == 8
    assert (state.ip, state.port, state.is_serving) == ("0.0.0.0", 0, False)


def test_second_contract_rejects_legacy_successor_switch_before_loading_files(tmp_path):
    contract = isolated_contract(tmp_path)
    with pytest.raises(axon.MinerAxonError, match="no legacy successor"):
        axon.announce_reviewed_preview(
            bt_module=FakeBt,
            subtensor=FakeSubtensor(),
            wallet=wallet(),
            preview_path=tmp_path / "missing.json",
            reviewed_sha256="00" * 32,
            qvl_path="/reviewed/qvl",
            confirm=True,
            exclusive_announcer_asserted=True,
            allow_finalized_successor=True,
            predecessor_preview_path=tmp_path / "old.json",
            predecessor_reviewed_sha256="11" * 32,
            runtime_root=tmp_path,
            contract=contract,
        )
