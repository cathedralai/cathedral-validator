"""The direct writer's timelocked commit-reveal branch, against a fake chain.

The fake models the storage and events the writer reads, shaped as the pinned
client decodes them on Finney SN94 (runtime spec 470): commits under
``TimelockedWeightCommits[netuid_index][epoch]`` as ``[who, block, "0x..",
round]`` rows, and reveals as ``TimelockedWeightsRevealed`` events with
``[netuid_index, "ss58"]`` attributes in the reveal block. It proves the
writer's own behavior against that model, not the chain's behavior or the
bittensor-drand ciphertext, which only a live chain can.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from async_substrate_interface.errors import SubstrateRequestException
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import MORTAL_PERIOD_BLOCKS, NETUID, W
from cathedral_thin.independent_runtime import commit_reveal as cr
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime import direct_validator as validator_runtime
from cathedral_thin.independent_runtime import telemetry as telemetry_runtime
from cathedral_thin.independent_runtime.direct_contract import (
    DirectSubmissionReceipt,
    DirectValidatorError,
)
from cathedral_thin.independent_runtime.direct_validator import (
    build_direct_plan,
    run_direct_cycle,
)
from cathedral_thin.independent_runtime.direct_writer import (
    STATUS_AWAITING_REVEAL,
    STATUS_COMMITTED,
    STATUS_CONFIRMED,
    STATUS_EXPIRED,
    STATUS_REVEAL_NOT_APPLIED,
    STATUS_REVEAL_NOT_APPLIED_RECORDED,
    STATUS_REVEAL_UNPROVEN,
    STATUS_REVEALED,
    DirectCommitNotRevealed,
    DirectSubmissionAmbiguous,
    DirectWeightWriter,
    FailedWriteRecordRefused,
)
from cathedral_thin.independent_runtime.updater import (
    UpdateRefused,
    require_idle_direct_writer_journal,
)
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.telemetry import (
    PendingTelemetryStore,
    TelemetrySpool,
    applied_reveal_receipt,
    journal_receipt_for_plan,
    latest_telemetry_event,
)
from tests.thin import test_direct_validator as base


@pytest.fixture(autouse=True)
def _configured_netuid(monkeypatch):
    """The unit's direct.env gives every validator process its netuid."""

    monkeypatch.setenv("CATHEDRAL_VALIDATOR_NETUID", str(NETUID))


VALIDATOR = base.VALIDATOR
SIGN_HEAD = base.ANCHOR_NUMBER + 1
INCLUSION = base.ANCHOR_NUMBER + 2
TEMPO = 360
EPOCH = 25_412
# The epoch that is current at the sign head fired at the anchor block, so
# the next one fires a whole tempo later, far outside the signing era.
LAST_EPOCH_BLOCK = base.ANCHOR_NUMBER
NEXT_FIRE = LAST_EPOCH_BLOCK + TEMPO
DRAND_HEAD = 32_620_000
PUBLIC_KEY = bytes(range(32))
CIPHERTEXT = bytes([0x8D]) * 291
REVEAL_BLOCK = NEXT_FIRE + 10
OTHER_VALIDATOR_ROW = ["5OtherValidator", 60, "0x" + "ab" * 40, 32_619_999]


def drand_time(round_number: int) -> float:
    """A wall-clock second inside the given drand round."""

    return cr.DRAND_GENESIS_SECONDS + round_number * cr.DRAND_PERIOD_SECONDS + 1


def expected_round() -> int:
    return DRAND_HEAD + 4 * (NEXT_FIRE + 3 - SIGN_HEAD)


@dataclass
class CommitChain:
    """What finalized storage and events hold, per block, in this model."""

    enabled: bool = True
    reveal_period: int = 1
    version: int = 4
    tempo: int = TEMPO
    last_epoch_block: int = LAST_EPOCH_BLOCK
    drand_head: int = DRAND_HEAD
    commit_hex: str | None = None
    reveal_round: int | None = None
    reveal_block: int | None = None
    reveal_applied: bool = True
    stray_commit: bool = False
    discarded: set[int] = field(default_factory=set)
    raw_reads: list[tuple[str, int]] = field(default_factory=list)


class FakeStorageKey:
    def __init__(self, module: str, function: str, params: list[Any]) -> None:
        self.module = module
        self.function = function
        self.params = params
        self.value_scale_type = function

    def to_hex(self) -> str:
        body = json.dumps([self.module, self.function, self.params])
        return "0x" + body.encode("ascii").hex()


class CommitRevealSubstrate(base.WriterSubstrate):
    def __init__(self) -> None:
        super().__init__()
        self.chain = CommitChain()
        self.commit_calls: list[dict[str, Any]] = []
        self.pending_at_broadcast: dict[str, Any] | None = None
        self.state_path: Path | None = None

    # The fake chain -------------------------------------------------------

    def epoch_at(self, block: int) -> int:
        if block < NEXT_FIRE:
            return EPOCH
        return EPOCH + 1 + (block - NEXT_FIRE) // TEMPO

    def commit_held_at(self, block: int) -> bool:
        return (
            self.included
            and block >= self.inclusion_block
            and (self.chain.reveal_block is None or block < self.chain.reveal_block)
        )

    def storage_at(self, function: str, params: list[Any], block: int) -> Any:
        if function == "SubnetEpochIndex":
            return self.epoch_at(block)
        if function == "TimelockedWeightCommits":
            index, key = params
            assert index == 94
            rows: list[list[Any]] = []
            if key == EPOCH:
                rows.append(list(OTHER_VALIDATOR_ROW))
                if self.commit_held_at(block):
                    rows.append(
                        [
                            VALIDATOR,
                            self.inclusion_block,
                            self.chain.commit_hex,
                            self.chain.reveal_round,
                        ]
                    )
                if self.chain.stray_commit:
                    rows.append([VALIDATOR, 90, "0x" + "cd" * 40, 32_619_000])
            return rows or None
        if function == "LastUpdate":
            (index,) = params
            assert index == 94
            values = [1] * 256
            if self.included and block >= self.inclusion_block:
                values[7] = self.inclusion_block
            return values
        if function == "Keys":
            netuid, uid = params
            assert netuid == 94
            owners = {7: VALIDATOR, 19: base.MINER_ONE, 20: base.MINER_TWO}
            if (
                self.owner.remap_after is not None
                and block >= self.owner.remap_after
                and uid == 19
            ):
                return "5Replacement"
            return owners.get(uid)
        if function == "Weights":
            index, uid = params
            assert (index, uid) == (94, 7)
            if (
                self.chain.reveal_applied
                and self.chain.reveal_block is not None
                and block >= self.chain.reveal_block
            ):
                return [
                    list(row)
                    for row in zip(
                        self.expected_uids,
                        base.pallet_storage_weights(self.expected_weights),
                    )
                ]
            return [[19, W]] if self.expected_uids != [19] else [[20, W]]
        raise AssertionError(f"unexpected raw storage read {function}")

    # The pinned client surface ------------------------------------------

    def create_storage_key(self, module, function, params, *, block_hash):
        self.get_block_number(block_hash)
        return FakeStorageKey(module, function, list(params))

    def rpc_request(self, method: str, params: list[object]) -> dict[str, object]:
        if method != "state_getStorage":
            return super().rpc_request(method, params)
        key_hex, block_hash = params
        module, function, key_params = json.loads(
            bytes.fromhex(str(key_hex)[2:]).decode("ascii")
        )
        block = self.get_block_number(block_hash)
        self.chain.raw_reads.append((function, block))
        if block in self.chain.discarded:
            raise SubstrateRequestException(
                f"Client error: UnknownBlock: State already discarded for {block_hash}"
            )
        assert module == "SubtensorModule"
        value = self.storage_at(function, key_params, block)
        if value is None:
            return {"jsonrpc": "2.0", "result": None}
        return {
            "jsonrpc": "2.0",
            "result": "0x" + json.dumps(value).encode("ascii").hex(),
        }

    def decode_scale(self, type_string: str, data: bytes) -> Any:
        return json.loads(data.decode("ascii"))

    def query(self, *, module, storage_function, params, block_hash):
        values = {
            ("SubtensorModule", "RevealPeriodEpochs"): self.chain.reveal_period,
            ("SubtensorModule", "CommitRevealWeightsVersion"): self.chain.version,
            ("SubtensorModule", "LastEpochBlock"): self.chain.last_epoch_block,
            ("SubtensorModule", "PendingEpochAt"): 0,
            ("SubtensorModule", "SubnetEpochIndex"): EPOCH,
            ("SubtensorModule", "Tempo"): self.chain.tempo,
            ("SubtensorModule", "BlocksSinceLastStep"): self.sign_head
            - self.chain.last_epoch_block,
            ("Drand", "LastStoredRound"): self.chain.drand_head,
        }
        if (module, storage_function) in values:
            assert block_hash == self.block_hash(self.sign_head)
            return values[(module, storage_function)]
        return super().query(
            module=module,
            storage_function=storage_function,
            params=params,
            block_hash=block_hash,
        )

    def build_commit_call(self, document: dict[str, Any]) -> str:
        self.commit_calls.append(dict(document))
        self.chain.commit_hex = document["commit"]
        self.chain.reveal_round = document["reveal_round"]
        return "direct-call"

    def submit_extrinsic(self, signed, *, wait_for_inclusion, wait_for_finalization):
        if self.state_path is not None:
            self.pending_at_broadcast = json.loads(
                self.state_path.read_text(encoding="ascii")
            )["pending"]
        return super().submit_extrinsic(
            signed,
            wait_for_inclusion=wait_for_inclusion,
            wait_for_finalization=wait_for_finalization,
        )

    def get_block(self, *, block_hash: str) -> dict[str, object]:
        block_number = self.get_block_number(block_hash)
        if not self.included or block_number != self.inclusion_block:
            return {"extrinsics": []}
        return {
            "extrinsics": [
                base.Extrinsic(
                    {
                        "address": VALIDATOR,
                        "call": {
                            "call_module": "SubtensorModule",
                            "call_function": "commit_timelocked_mechanism_weights",
                            "call_args": [
                                {"name": "netuid", "value": 94},
                                {"name": "mecid", "value": 0},
                                {"name": "commit", "value": self.chain.commit_hex},
                                {
                                    "name": "reveal_round",
                                    "value": self.chain.reveal_round,
                                },
                                {"name": "commit_reveal_version", "value": 4},
                            ],
                        },
                    },
                    extrinsic_hash=self.included_hash,
                )
            ]
        }

    def get_events(self, *, block_hash: str) -> list[dict[str, Any]]:
        block = self.get_block_number(block_hash)
        events: list[dict[str, Any]] = [
            {
                "phase": "ApplyExtrinsic",
                "extrinsic_idx": 0,
                "event": {
                    "module_id": "System",
                    "event_id": "ExtrinsicSuccess",
                    "attributes": {},
                },
            }
        ]
        if block == self.chain.reveal_block:
            events.append(
                {
                    "phase": "Initialization",
                    "extrinsic_idx": None,
                    "event": {
                        "module_id": "SubtensorModule",
                        "event_id": "TimelockedWeightsRevealed",
                        "attributes": [94, "5OtherValidator"],
                    },
                }
            )
            if self.chain.reveal_applied:
                events.append(
                    {
                        "phase": "Initialization",
                        "extrinsic_idx": None,
                        "event": {
                            "module_id": "SubtensorModule",
                            "event_id": "TimelockedWeightsRevealed",
                            "attributes": [94, VALIDATOR],
                        },
                    }
                )
        return events


class CommitRevealSubtensor(base.WriterSubtensor):
    def __init__(self, *, miners) -> None:
        super().__init__(miners=miners)
        self.substrate = CommitRevealSubstrate()
        self.substrate.owner = self

    def commit_reveal_enabled(self, *, netuid: int, block: int) -> bool:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        return self.substrate.chain.enabled


class Encryptor:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.round_offset = 12

    def __call__(self, **kwargs: Any) -> tuple[bytes, int]:
        self.calls.append(kwargs)
        return CIPHERTEXT, expected_round() + self.round_offset


def cr_writer(
    tmp_path: Path,
    monkeypatch,
    *,
    planned=None,
    opt_in: cr.CommitRevealOptIn | None = cr.CommitRevealOptIn(1),
) -> tuple[DirectWeightWriter, CommitRevealSubtensor, Any, Encryptor]:
    selected = planned or base.plan()
    miners = selected.snapshot.miners
    subtensor = CommitRevealSubtensor(miners=miners)
    substrate = subtensor.substrate
    substrate.expected_uids = list(selected.wire_uids)
    substrate.expected_weights = list(selected.wire_weights)
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    encryptor = Encryptor()
    instance = DirectWeightWriter(
        subtensor=subtensor,
        keypair=base.FakeKeypair(),
        netuid=NETUID,
        snapshot_reader=lambda _subtensor, _keypair: replace(
            base.snapshot(substrate.sign_head, miners=miners),
            block_hash=substrate.block_hash(substrate.sign_head),
        ),
        call_builder=lambda _kwargs: "direct-call",
        commit_reveal=opt_in,
        commit_encryptor=encryptor,
        commit_call_builder=substrate.build_commit_call,
        hotkey_public_key=lambda _keypair: PUBLIC_KEY,
        wall_clock=lambda: drand_time(DRAND_HEAD + 16),
    )
    substrate.state_path = instance.state_path
    return instance, subtensor, selected, encryptor


def journal(instance: DirectWeightWriter) -> dict[str, Any]:
    return json.loads(instance.state_path.read_text(encoding="ascii"))


def commit_once(tmp_path: Path, monkeypatch, **kwargs):
    instance, subtensor, planned, encryptor = cr_writer(tmp_path, monkeypatch, **kwargs)
    receipt = base.submit_before_deadline(instance, planned)
    assert receipt.status == STATUS_COMMITTED
    return instance, subtensor, planned, encryptor


# Pure helpers -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "period"),
    (
        (None, None),
        ("", None),
        ("timelocked-v4-reveal-period-1", 1),
        ("timelocked-v4-reveal-period-100", 100),
    ),
)
def test_opt_in_accepts_only_the_pinned_grammar(value, period) -> None:
    parsed = cr.parse_commit_reveal_opt_in(value)
    assert (None if parsed is None else parsed.reveal_period_epochs) == period


@pytest.mark.parametrize(
    "value",
    (
        "1",
        "true",
        "timelocked-v3-reveal-period-1",
        "timelocked-v4-reveal-period-0",
        "timelocked-v4-reveal-period-01",
        "timelocked-v4-reveal-period-101",
        " timelocked-v4-reveal-period-1",
        "timelocked-v4-reveal-period-1\n",
    ),
)
def test_opt_in_refuses_every_other_value(value) -> None:
    with pytest.raises(DirectValidatorError, match="reveal-period|reveal period"):
        cr.parse_commit_reveal_opt_in(value)


def _schedule(**overrides: int) -> cr.EpochSchedule:
    values = {
        "last_epoch_block": 10,
        "pending_epoch_at": 0,
        "subnet_epoch_index": 0,
        "tempo": 50,
        "blocks_since_last_step": 0,
        "current_block": 10,
    }
    values.update(overrides)
    return cr.EpochSchedule(**values)


def test_reveal_block_prediction_matches_the_bittensor_drand_vectors() -> None:
    # bittensor-drand v2.0.0 src/epoch_schedule_vectors.rs:17-65.
    assert cr.predict_first_reveal_block(_schedule(), 1) == 60
    pending = _schedule(
        last_epoch_block=80, pending_epoch_at=95, tempo=20, current_block=91
    )
    assert cr.predict_first_reveal_block(pending, 1) == 95
    with pytest.raises(DirectValidatorError, match="tempo is zero"):
        cr.predict_first_reveal_block(_schedule(tempo=0), 1)


def test_next_epoch_fire_block_is_the_first_block_that_runs_an_epoch() -> None:
    assert cr.next_epoch_fire_block(_schedule(current_block=40)) == 60
    assert cr.next_epoch_fire_block(_schedule(current_block=59)) == 60
    assert cr.next_epoch_fire_block(_schedule(pending_epoch_at=45)) == 45


def test_drand_round_matches_the_library_formula() -> None:
    # bittensor-drand src/drand.rs:189-193: floor((t - genesis) / 3), at least 1.
    assert cr.drand_round_at(cr.DRAND_GENESIS_SECONDS + 2) == 1
    assert cr.drand_round_at(cr.DRAND_GENESIS_SECONDS + 3 * 1000 + 2) == 1000
    assert cr.drand_round_at(drand_time(DRAND_HEAD)) == DRAND_HEAD


def test_decoded_commit_rows_take_the_client_shape_only() -> None:
    row = [VALIDATOR, 5, "0xAB", 9]
    assert cr.decoded_commit_rows([row]) == [(VALIDATOR, 5, "0xab", 9)]
    assert cr.decoded_commit_rows([]) == []
    assert cr.decoded_commit_rows([[VALIDATOR, 5, "ab", 9]]) is None
    assert cr.decoded_commit_rows([[VALIDATOR, True, "0xab", 9]]) is None
    assert cr.decoded_commit_rows("0xab") is None


# Commit-reveal off: the writer is exactly the plain writer --------------------


def test_chain_off_without_opt_in_writes_the_unchanged_plain_journal(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = base.writer(tmp_path, monkeypatch)

    receipt = base.submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    state = journal(instance)
    assert set(state["last_attempt"]) == {
        "attempt_id",
        "status",
        "identity",
        "intent",
        "receipt",
    }
    assert set(state["last_attempt"]["intent"]) == {
        "extrinsic_hash",
        "validator_hotkey",
        "nonce",
        "era_reference_block",
        "mortal_period_blocks",
        "kwargs",
        "eligibility",
    }
    assert state["last_attempt"]["intent"]["eligibility"]["commit_reveal_enabled"] is (
        False
    )
    # The plain fake answers only chain_getBlockHash: no raw storage read, no
    # drand read and no commit-reveal read happened.
    assert instance.recover() is None
    assert instance.commit_reveal is None


def test_chain_on_without_opt_in_is_refused_exactly_as_before(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, encryptor = cr_writer(
        tmp_path, monkeypatch, opt_in=None
    )

    with pytest.raises(DirectValidatorError) as refused:
        base.submit_before_deadline(instance, planned)

    message = str(refused.value)
    assert message.startswith(f"subnet {NETUID} has commit_reveal_weights_enabled set")
    assert "nothing was signed" in message
    # The owner command names the hyperparameter with `--param`; `--name` is
    # btcli's alias for `--wallet-name`.
    assert (
        f"`btcli sudo set --netuid {NETUID} "
        "--param commit_reveal_weights_enabled --value false`"
    ) in message
    assert "--name" not in message
    assert cr.COMMIT_REVEAL_OPT_IN_ENV in message
    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert encryptor.calls == []
    assert subtensor.substrate.chain.raw_reads == []
    assert not instance.state_path.exists()


def test_opt_in_refuses_a_chain_with_commit_reveal_off(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, encryptor = cr_writer(tmp_path, monkeypatch)
    subtensor.substrate.chain.enabled = False

    with pytest.raises(DirectValidatorError, match="remove CATHEDRAL_VALIDATOR_COMMIT"):
        base.submit_before_deadline(instance, planned)

    assert subtensor.substrate.sign_calls == 0
    assert encryptor.calls == []
    assert not instance.state_path.exists()


# Commit-reveal on and opted in -------------------------------------------------


def test_commit_journals_the_exact_commit_before_broadcast_and_proves_it_stored(
    tmp_path: Path, monkeypatch
) -> None:
    miners = (base.MINER_ONE_AXON, base.MINER_TWO_AXON)
    planned = base.plan(
        miners=miners,
        rows=(
            base.machine_row("1"),
            base.machine_row("2"),
            base.machine_row("3", uid=20, hotkey=base.MINER_TWO),
        ),
    )
    instance, subtensor, planned, encryptor = cr_writer(
        tmp_path, monkeypatch, planned=planned
    )
    substrate = subtensor.substrate

    receipt = base.submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_COMMITTED
    assert receipt.block_number == INCLUSION
    assert [row[0] for row in receipt.confirmation_heads] == [102, 103, 104]
    assert substrate.sign_calls == substrate.submit_calls == 1
    # The ciphertext is built from exactly the plain call's vector and the
    # schedule read at the finalized sign head.
    [call] = encryptor.calls
    assert call == {
        "uids": [19, 20],
        "weights": [43690, 21845],
        "version_key": 10005000,
        "last_epoch_block": LAST_EPOCH_BLOCK,
        "pending_epoch_at": 0,
        "subnet_epoch_index": EPOCH,
        "tempo": TEMPO,
        "blocks_since_last_step": SIGN_HEAD - LAST_EPOCH_BLOCK,
        "current_block": SIGN_HEAD,
        "subnet_reveal_period_epochs": 1,
        "block_time": 12.0,
        "hotkey": PUBLIC_KEY,
    }
    assert substrate.commit_calls == [
        {
            "netuid": 94,
            "mecid": 0,
            "commit": "0x" + CIPHERTEXT.hex(),
            "reveal_round": expected_round() + 12,
            "commit_reveal_version": 4,
        }
    ]
    # Journal before broadcast: the node saw bytes whose intent was on disk.
    pending = substrate.pending_at_broadcast
    assert pending is not None and pending["phase"] == "signed_intent"
    document = pending["intent"]["commit_reveal"]
    assert document["commit"] == "0x" + CIPHERTEXT.hex()
    assert document["reveal_round"] == expected_round() + 12
    assert document["first_reveal_block"] == NEXT_FIRE
    assert document["next_epoch_block"] == NEXT_FIRE
    assert document["expected_reveal_round"] == expected_round()
    assert pending["intent"]["kwargs"]["weights"] == [43690, 21845]
    state = journal(instance)
    assert state["pending"] is None
    last = state["last_attempt"]
    assert last["status"] == STATUS_COMMITTED
    assert last["intent"] == pending["intent"]
    assert last["reveal"] == {
        "commit_epoch": EPOCH,
        "present_through_block": INCLUSION,
        "outcome": None,
    }


def test_reveal_is_awaited_then_proven_applied_without_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = commit_once(tmp_path, monkeypatch)
    substrate = subtensor.substrate

    substrate.finalized_number = 300
    awaiting = instance.recover()
    assert awaiting is not None and awaiting.status == STATUS_AWAITING_REVEAL
    assert journal(instance)["last_attempt"]["reveal"]["present_through_block"] == 300
    with pytest.raises(DirectValidatorError, match="not proven revealed"):
        base.submit_before_deadline(instance, planned)

    substrate.chain.reveal_block = REVEAL_BLOCK
    substrate.finalized_number = REVEAL_BLOCK + 1
    early = instance.recover()
    assert early is not None and early.status == STATUS_AWAITING_REVEAL

    substrate.finalized_number = REVEAL_BLOCK + 30
    revealed = instance.recover()

    assert revealed is not None and revealed.status == STATUS_REVEALED
    assert revealed.block_number == REVEAL_BLOCK
    assert [row[0] for row in revealed.confirmation_heads] == [
        REVEAL_BLOCK,
        REVEAL_BLOCK + 1,
        REVEAL_BLOCK + 2,
    ]
    last = journal(instance)["last_attempt"]
    assert last["status"] == STATUS_REVEALED
    assert last["receipt"]["status"] == STATUS_COMMITTED
    assert last["reveal"]["outcome"]["applied"] is True
    assert last["reveal"]["outcome"]["consumed_block"] == REVEAL_BLOCK
    assert last["reveal"]["outcome"]["remapped_dests"] == []
    assert substrate.sign_calls == substrate.submit_calls == 1
    assert instance.recover() is None, "a proven reveal has nothing left to prove"


def test_reveal_names_uids_remapped_since_the_commit(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, _planned, _encryptor = commit_once(tmp_path, monkeypatch)
    subtensor.remap_after = REVEAL_BLOCK - 5
    subtensor.substrate.chain.reveal_block = REVEAL_BLOCK
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 3

    revealed = instance.recover()

    assert revealed is not None and revealed.status == STATUS_REVEALED
    outcome = journal(instance)["last_attempt"]["reveal"]["outcome"]
    assert outcome["remapped_dests"] == [[19, base.MINER_ONE, "5Replacement"]]


def test_commit_consumed_without_its_reveal_is_recorded_and_stops(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, _planned, _encryptor = commit_once(tmp_path, monkeypatch)
    chain = subtensor.substrate.chain
    chain.reveal_block = REVEAL_BLOCK
    chain.reveal_applied = False
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 3

    with pytest.raises(DirectCommitNotRevealed, match="without applying"):
        instance.recover()

    last = journal(instance)["last_attempt"]
    assert last["status"] == STATUS_REVEAL_NOT_APPLIED
    assert last["reveal"]["outcome"] == {
        "applied": False,
        "consumed_block": REVEAL_BLOCK,
        "consumed_block_hash": subtensor.substrate.block_hash(REVEAL_BLOCK),
    }
    # The stop is not a one-shot: the next recovery raises it again.
    with pytest.raises(DirectCommitNotRevealed, match="record-failed-write"):
        instance.recover()


def stopped_on_reveal_not_applied(tmp_path: Path, monkeypatch):
    """Commit, then let the chain consume the commit without applying it."""

    instance, subtensor, planned, encryptor = commit_once(tmp_path, monkeypatch)
    chain = subtensor.substrate.chain
    chain.reveal_block = REVEAL_BLOCK
    chain.reveal_applied = False
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 3
    with pytest.raises(DirectCommitNotRevealed, match="without applying"):
        instance.recover()
    assert journal(instance)["last_attempt"]["status"] == STATUS_REVEAL_NOT_APPLIED
    return instance, subtensor, planned, encryptor


def test_reveal_not_applied_survives_a_restart_and_blocks_every_write(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, encryptor = stopped_on_reveal_not_applied(
        tmp_path, monkeypatch
    )
    substrate = subtensor.substrate
    stopped = instance.state_path.read_bytes()
    reads = list(substrate.chain.raw_reads)
    # Much later, past every block the reveal search read.
    substrate.finalized_number = REVEAL_BLOCK + 500

    # A restarted process, opted in or not, finds the same stop on recovery
    # and refuses to sign anything, commit or plain.
    restarted, _subtensor, _planned, restarted_encryptor = cr_writer(
        tmp_path, monkeypatch
    )
    restarted.subtensor = subtensor
    plain = DirectWeightWriter(
        subtensor=subtensor,
        keypair=base.FakeKeypair(),
        netuid=NETUID,
        call_builder=lambda _kwargs: "direct-call",
    )
    for writer_object in (instance, restarted, plain):
        assert writer_object.state_path == instance.state_path
        with pytest.raises(DirectCommitNotRevealed, match="REVEAL_NOT_APPLIED"):
            writer_object.recover()
        with pytest.raises(DirectCommitNotRevealed, match="record-failed-write"):
            base.submit_before_deadline(writer_object, planned)

    assert substrate.sign_calls == substrate.submit_calls == 1
    assert len(encryptor.calls) == 1
    assert restarted_encryptor.calls == []
    # The stop reads nothing more from the chain and leaves the journal as is.
    assert substrate.chain.raw_reads == reads
    assert instance.state_path.read_bytes() == stopped
    # The updater, which would restart the service, refuses as it does for a
    # pending finalized_failed write.
    with pytest.raises(UpdateRefused, match="REVEAL_NOT_APPLIED"):
        require_idle_direct_writer_journal(instance.state_path)
    tool = base._status_tool()
    last = journal(instance)["last_attempt"]
    assert tool._last_attempt_summary(last, expected_identity=VALIDATOR) == (
        STATUS_REVEAL_NOT_APPLIED,
        REVEAL_BLOCK,
    )


def test_record_failed_write_clears_a_reveal_not_applied_stop(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = stopped_on_reveal_not_applied(
        tmp_path, monkeypatch
    )
    substrate = subtensor.substrate
    stopped = journal(instance)
    reads = list(substrate.chain.raw_reads)

    # Another signer's command never touches this journal.
    class OtherKeypair:
        ss58_address = "5OtherValidator"

    other = DirectWeightWriter(
        netuid=NETUID, subtensor=subtensor, keypair=OtherKeypair()
    )
    other.state_path = instance.state_path
    with pytest.raises(FailedWriteRecordRefused, match="another signer"):
        other.record_finalized_failure()
    # Nor does it run while the validator holds its locks.
    for held in (instance.cycle_locked, instance.process_locked):
        with held():
            with pytest.raises(FailedWriteRecordRefused, match="lock"):
                instance.record_finalized_failure()
    assert journal(instance) == stopped

    record = instance.record_finalized_failure()

    assert record == {
        "status": STATUS_REVEAL_NOT_APPLIED_RECORDED,
        "attempt_id": stopped["last_attempt"]["attempt_id"],
        "extrinsic_hash": stopped["last_attempt"]["intent"]["extrinsic_hash"],
        "consumed_block": REVEAL_BLOCK,
        "consumed_block_hash": substrate.block_hash(REVEAL_BLOCK),
    }
    recorded = journal(instance)
    # Only the status moved; the proof, the intent and the anchor stay.
    expected = json.loads(json.dumps(stopped))
    expected["last_attempt"]["status"] = STATUS_REVEAL_NOT_APPLIED_RECORDED
    assert recorded == expected
    assert substrate.chain.raw_reads == reads
    assert substrate.sign_calls == substrate.submit_calls == 1

    # Cleared: recovery has nothing left to prove, the updater goes ahead,
    # and submit gets past the stop to the anchor fence the record kept.
    assert instance.recover() is None
    require_idle_direct_writer_journal(instance.state_path)
    with pytest.raises(DirectValidatorError, match="already attempted this"):
        base.submit_before_deadline(instance, planned)
    assert substrate.sign_calls == 1
    tool = base._status_tool()
    assert tool._last_attempt_summary(
        recorded["last_attempt"], expected_identity=VALIDATOR
    ) == (STATUS_REVEAL_NOT_APPLIED_RECORDED, REVEAL_BLOCK)
    # A second record finds nothing to clear.
    with pytest.raises(FailedWriteRecordRefused, match="no pending intent"):
        instance.record_finalized_failure()
    assert journal(instance) == recorded


def test_record_refuses_a_tampered_reveal_not_applied_stop(
    tmp_path: Path, monkeypatch
) -> None:
    instance, _subtensor, _planned, _encryptor = stopped_on_reveal_not_applied(
        tmp_path, monkeypatch
    )
    stopped = journal(instance)
    for tamper in (
        lambda last: last["reveal"]["outcome"].update(applied=True),
        lambda last: last["reveal"]["outcome"].update(
            consumed_block=last["reveal"]["present_through_block"]
        ),
        lambda last: last["receipt"].update(status=STATUS_CONFIRMED),
        lambda last: last["intent"]["kwargs"].update(netuid=NETUID + 1),
        lambda last: last.pop("reveal"),
    ):
        document = json.loads(json.dumps(stopped))
        tamper(document["last_attempt"])
        instance.state_path.write_text(json.dumps(document), encoding="ascii")
        before = instance.state_path.read_bytes()
        with pytest.raises(FailedWriteRecordRefused):
            instance.record_finalized_failure()
        assert instance.state_path.read_bytes() == before
        # Tampered or not, the status alone keeps the validator stopped.
        with pytest.raises(DirectCommitNotRevealed):
            instance.recover()


def test_cli_stops_on_reveal_not_applied_until_the_record_command_clears_it(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime
    from cathedral_thin.independent_runtime import failed_write_recovery

    instance, subtensor, planned, _encryptor = stopped_on_reveal_not_applied(
        tmp_path, monkeypatch
    )
    base._cli_with_real_writer(monkeypatch, instance, subtensor, [planned.snapshot])
    monkeypatch.setattr(
        runtime, "_notify_ready", lambda: pytest.fail("stopped writer reported ready")
    )

    # Every start stops before readiness with the never-restarted exit code.
    for _start in range(2):
        assert runtime.main(base.VALIDATOR_ARGS) == runtime.EXIT_CONTRADICTION_STOPPED
        (stop,) = base._lines(capsys)
        assert stop["status"] == "CONTRADICTION_STOPPED"
        assert "REVEAL_NOT_APPLIED" in stop["error"]
        assert "record-failed-write" in stop["error"]
    assert subtensor.substrate.sign_calls == 1

    # The operator's record command, with its own key-less writer.
    assert runtime.main(base.RECORD_ARGS) == failed_write_recovery.EXIT_RECORDED
    (recorded,) = base._lines(capsys)
    assert (
        recorded["status"] == failed_write_recovery.STATUS_REVEAL_NOT_APPLIED_RECORDED
    )
    assert recorded["consumed_block"] == REVEAL_BLOCK
    assert journal(instance)["last_attempt"]["status"] == (
        STATUS_REVEAL_NOT_APPLIED_RECORDED
    )
    assert instance.recover() is None


def test_status_tool_reports_the_reveal_stop_and_its_command(
    tmp_path: Path, monkeypatch
) -> None:
    import time

    instance, _subtensor, _planned, _encryptor = stopped_on_reveal_not_applied(
        tmp_path, monkeypatch
    )
    tool = base._status_tool()
    release = "sha256:" + "1" * 64

    def direct_summary(_identity: str) -> dict[str, Any]:
        last = journal(instance)["last_attempt"]
        result, block = tool._last_attempt_summary(last, expected_identity=VALIDATOR)
        return {
            "pending": False,
            "pending_phase": None,
            "last_result": result,
            "block_number": block,
            "recorded_unix": int(time.time()),
        }

    monkeypatch.setattr(tool, "_systemd_state", lambda *_args: False)
    monkeypatch.setattr(tool, "_current_release", lambda: release)
    monkeypatch.setattr(tool, "_release_metadata_summary", lambda _now: None)
    monkeypatch.setattr(tool, "_release_metadata_warning", lambda _summary: None)
    monkeypatch.setattr(tool, "_identity", lambda: VALIDATOR)
    monkeypatch.setattr(
        tool,
        "_updater_summary",
        lambda: {
            "archive_digest": release,
            "channel": "stable",
            "pending_recovery": False,
        },
    )
    monkeypatch.setattr(tool, "_direct_summary", direct_summary)

    report = tool.collect()

    assert report["result"] == "REVEAL_NOT_APPLIED_STOPPED"
    assert "`cathedral-validator record-failed-write`" in report["action"]
    assert "Commit-reveal subnets" in report["action"]

    instance.record_finalized_failure()
    assert tool.collect()["result"] == "NEEDS_REVIEW"


def test_unreadable_recent_history_during_the_reveal_search_changes_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, _planned, _encryptor = commit_once(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.finalized_number = REVEAL_BLOCK - 30
    assert instance.recover().status == STATUS_AWAITING_REVEAL
    substrate.chain.reveal_block = REVEAL_BLOCK
    substrate.finalized_number = REVEAL_BLOCK + 3
    # The node could not serve the block the commit was last seen in, which
    # is recent, so the next cycle simply asks again.
    substrate.chain.discarded = {REVEAL_BLOCK - 30}
    before = instance.state_path.read_bytes()

    with pytest.raises(DirectSubmissionAmbiguous, match="unreadable"):
        instance.recover()

    assert instance.state_path.read_bytes() == before
    assert journal(instance)["last_attempt"]["status"] == STATUS_COMMITTED


def test_a_commit_gone_past_readable_history_closes_unproven_and_writes_on(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = commit_once(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.chain.reveal_block = REVEAL_BLOCK
    # The validator was down for longer than a pruning node keeps state.
    substrate.finalized_number = REVEAL_BLOCK + 300
    substrate.chain.discarded = set(range(0, REVEAL_BLOCK + 300 - 256))

    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_REVEAL_UNPROVEN
    last = journal(instance)["last_attempt"]
    assert last["status"] == STATUS_REVEAL_UNPROVEN
    assert last["reveal"]["outcome"]["applied"] is None
    assert last["reveal"]["outcome"]["absent_at_block"] == REVEAL_BLOCK + 300
    assert "discarded" in last["reveal"]["outcome"]["unreadable"] or (
        "unreadable" in last["reveal"]["outcome"]["unreadable"]
    )
    assert instance.recover() is None
    tool = base._status_tool()
    assert tool._last_attempt_summary(last, expected_identity=VALIDATOR) == (
        STATUS_REVEAL_UNPROVEN,
        REVEAL_BLOCK + 300,
    )
    # A commit still stored at the head is never closed this way.
    fresh, fresh_subtensor, _planned, _encryptor = commit_once(
        tmp_path / "held", monkeypatch
    )
    fresh_subtensor.substrate.finalized_number = REVEAL_BLOCK - 1
    fresh_subtensor.substrate.chain.discarded = set(range(0, 200))
    assert fresh.recover().status == STATUS_AWAITING_REVEAL


def test_mismatched_reveal_period_is_refused_before_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, encryptor = cr_writer(tmp_path, monkeypatch)
    subtensor.substrate.chain.reveal_period = 2

    with pytest.raises(DirectValidatorError, match="reveal period is 2 epochs"):
        base.submit_before_deadline(instance, planned)

    assert subtensor.substrate.sign_calls == 0
    assert encryptor.calls == []
    assert not instance.state_path.exists()


@pytest.mark.parametrize(
    ("change", "message"),
    (
        (lambda chain, _enc, _inst: setattr(chain, "version", 5), "version is 5"),
        (
            # A 20-block tempo whose next epoch fires at block 110.
            lambda chain, _enc, _inst: chain.__dict__.update(
                tempo=20, last_epoch_block=90
            ),
            "starts at block 110, inside the signing era",
        ),
        (
            lambda _chain, _enc, inst: setattr(
                inst, "wall_clock", lambda: drand_time(DRAND_HEAD + 400)
            ),
            "local clock",
        ),
        (
            lambda _chain, enc, _inst: setattr(enc, "round_offset", 500),
            "disagrees with the chain-derived round",
        ),
        (
            lambda _chain, enc, _inst: setattr(
                enc, "round_offset", DRAND_HEAD - expected_round()
            ),
            "already on chain",
        ),
        (
            lambda chain, _enc, _inst: setattr(chain, "drand_head", 0),
            "reads as storage defaults",
        ),
        (
            lambda chain, _enc, _inst: setattr(chain, "stray_commit", True),
            "already has an unrevealed timelocked commit",
        ),
    ),
)
def test_every_commit_gate_refuses_before_signing_or_journaling(
    tmp_path: Path, monkeypatch, change, message
) -> None:
    instance, subtensor, planned, encryptor = cr_writer(tmp_path, monkeypatch)
    change(subtensor.substrate.chain, encryptor, instance)

    with pytest.raises(DirectValidatorError, match=message):
        base.submit_before_deadline(instance, planned)

    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


class ProcessDied(BaseException):
    """Stands in for a crash: nothing in the writer catches it."""


@pytest.mark.parametrize("landed", (False, True))
def test_crash_between_journal_and_submit_is_recovered_by_hash_never_resent(
    tmp_path: Path, monkeypatch, landed: bool
) -> None:
    instance, subtensor, planned, _encryptor = cr_writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate

    def crash(signed, *, wait_for_inclusion, wait_for_finalization):
        if landed:
            # The bytes reached the node before the process died.
            substrate.included = True
            substrate.included_hash = signed.extrinsic_hash
        raise ProcessDied()

    monkeypatch.setattr(substrate, "submit_extrinsic", crash)
    with pytest.raises(ProcessDied):
        base.submit_before_deadline(instance, planned)
    state = journal(instance)
    assert state["pending"]["phase"] == "signed_intent"
    assert "commit_reveal" in state["pending"]["intent"]

    # A restarted process signs nothing while the intent is unresolved.
    restarted, _subtensor, _planned, restarted_encryptor = cr_writer(
        tmp_path, monkeypatch
    )
    restarted.subtensor = subtensor
    with pytest.raises(DirectSubmissionAmbiguous, match="must be recovered"):
        base.submit_before_deadline(restarted, planned)
    assert restarted_encryptor.calls == []

    substrate.finalized_number = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    receipt = restarted.recover()

    assert substrate.sign_calls == 1, "recovery never signs"
    if landed:
        assert receipt is not None and receipt.status == STATUS_COMMITTED
        assert receipt.recovered is True
        assert journal(restarted)["last_attempt"]["reveal"]["commit_epoch"] == EPOCH
    else:
        assert receipt is not None and receipt.status == STATUS_EXPIRED
        assert journal(restarted)["last_attempt"]["status"] == STATUS_EXPIRED


@pytest.mark.parametrize("phase", ("pending", "committed"))
@pytest.mark.parametrize("genesis_result", ("wrong", "missing", "unavailable"))
def test_recovery_pins_uncached_genesis_before_history_or_journal_mutation(
    tmp_path: Path, monkeypatch, phase: str, genesis_result: str
) -> None:
    instance, subtensor, planned, _encryptor = cr_writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    if phase == "pending":

        def crash(*_args, **_kwargs):
            raise ProcessDied()

        monkeypatch.setattr(substrate, "submit_extrinsic", crash)
        with pytest.raises(ProcessDied):
            base.submit_before_deadline(instance, planned)
        # A wrong chain at this height used to clear the intent as expired.
        substrate.finalized_number = SIGN_HEAD + MORTAL_PERIOD_BLOCKS + 100
    else:
        base.submit_before_deadline(instance, planned)
        substrate.chain.reveal_block = REVEAL_BLOCK
        substrate.finalized_number = REVEAL_BLOCK + 3

    before = instance.state_path.read_bytes()
    signed, submitted = substrate.sign_calls, substrate.submit_calls
    # Seed a correct client cache before repointing the responding node.
    assert substrate.get_block_hash(0) == base.FINNEY_GENESIS_HASH
    reads: list[tuple[str, list[object]]] = []

    def repointed_node(method, params):
        reads.append((method, params))
        assert (method, params) == ("chain_getBlockHash", [0])
        if genesis_result == "unavailable":
            raise ConnectionError("node unavailable")
        return {"result": "0x" + "a" * 64 if genesis_result == "wrong" else None}

    monkeypatch.setattr(substrate, "rpc_request", repointed_node)
    monkeypatch.setattr(
        substrate,
        "get_chain_finalised_head",
        lambda: pytest.fail("history queried before genesis was authenticated"),
    )
    with pytest.raises(DirectSubmissionAmbiguous, match="genesis"):
        instance.recover()

    assert reads == [("chain_getBlockHash", [0])]
    assert instance.state_path.read_bytes() == before
    assert (substrate.sign_calls, substrate.submit_calls) == (signed, submitted)


@pytest.mark.parametrize("stop", ("reveal_not_applied", "finalized_failed"))
def test_recovery_keeps_terminal_stop_without_any_genesis_or_history_rpc(
    tmp_path: Path, monkeypatch, stop: str
) -> None:
    if stop == "reveal_not_applied":
        instance, subtensor, _plan, _encryptor = stopped_on_reveal_not_applied(
            tmp_path, monkeypatch
        )
        error = DirectCommitNotRevealed
    else:
        instance, subtensor, _plan = base.stopped_on_failed_write(tmp_path, monkeypatch)
        error = base.DirectSubmissionFinalizedFailure
    before = instance.state_path.read_bytes()
    monkeypatch.setattr(
        subtensor.substrate,
        "rpc_request",
        lambda *_a, **_k: pytest.fail("terminal stop must not query the chain"),
    )
    with pytest.raises(error):
        instance.recover()
    assert instance.state_path.read_bytes() == before


def test_idle_recovery_does_not_need_a_chain_connection(tmp_path: Path, monkeypatch):
    instance, subtensor, _planned, _encryptor = cr_writer(tmp_path, monkeypatch)
    monkeypatch.setattr(
        subtensor.substrate,
        "rpc_request",
        lambda *_a, **_k: pytest.fail("idle recovery must not query the chain"),
    )
    assert instance.recover() is None
    assert not instance.state_path.exists()


def test_duplicate_submit_is_refused_while_a_commit_awaits_its_reveal(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, encryptor = commit_once(tmp_path, monkeypatch)

    with pytest.raises(DirectValidatorError, match="not proven revealed"):
        base.submit_before_deadline(instance, planned)

    # Removing the opt-in does not unlock a plain write over a stored commit.
    plain = DirectWeightWriter(
        netuid=NETUID,
        subtensor=subtensor,
        keypair=base.FakeKeypair(),
        call_builder=lambda _kwargs: "direct-call",
    )
    with pytest.raises(DirectValidatorError, match="not proven revealed"):
        base.submit_before_deadline(plain, planned)
    assert subtensor.substrate.sign_calls == 1
    assert len(encryptor.calls) == 1


def test_a_commit_is_proven_even_after_the_opt_in_is_removed(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = cr_writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        base.submit_before_deadline(instance, planned)

    plain = DirectWeightWriter(
        netuid=NETUID, subtensor=subtensor, keypair=base.FakeKeypair()
    )
    receipt = plain.recover()

    assert receipt is not None and receipt.status == STATUS_COMMITTED
    assert journal(plain)["last_attempt"]["reveal"]["outcome"] is None


# The cycle and the local status tool -------------------------------------------


def _cycle_with(writer_object) -> dict[str, Any]:
    return run_direct_cycle(
        netuid=NETUID,
        subtensor=object(),
        keypair=base.FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=writer_object,
        report_recovery=lambda _event: None,
    )


def test_cycle_waits_on_a_commit_and_scores_after_its_proven_reveal(
    monkeypatch,
) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    def receipt(status: str) -> SimpleNamespace:
        return SimpleNamespace(status=status, as_document=lambda: {"status": status})

    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: pytest.fail("an awaited reveal reached collection"),
    )
    waiting = SimpleNamespace(recover=lambda: receipt(STATUS_AWAITING_REVEAL))
    assert _cycle_with(waiting)["status"] == STATUS_AWAITING_REVEAL

    reached: list[str] = []

    def collect(*_args):
        reached.append("collect")
        raise DirectValidatorError("stop after recovery")

    monkeypatch.setattr(runtime, "finalized_serving_miners_snapshot", collect)
    revealed = SimpleNamespace(recover=lambda: receipt(STATUS_REVEALED))
    with pytest.raises(DirectValidatorError, match="stop after recovery"):
        _cycle_with(revealed)
    assert reached == ["collect"]


def test_status_tool_reads_committed_and_revealed_attempts(
    tmp_path: Path, monkeypatch
) -> None:
    tool = base._status_tool()
    instance, subtensor, _planned, _encryptor = commit_once(tmp_path, monkeypatch)

    committed = journal(instance)["last_attempt"]
    assert tool._last_attempt_summary(committed, expected_identity=VALIDATOR) == (
        STATUS_COMMITTED,
        INCLUSION,
    )

    subtensor.substrate.chain.reveal_block = REVEAL_BLOCK
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 3
    instance.recover()
    revealed = journal(instance)["last_attempt"]
    assert tool._last_attempt_summary(revealed, expected_identity=VALIDATOR) == (
        STATUS_REVEALED,
        REVEAL_BLOCK,
    )

    tampered = json.loads(json.dumps(revealed))
    tampered["reveal"]["outcome"]["applied"] = False
    with pytest.raises(tool.StatusUnavailable):
        tool._last_attempt_summary(tampered, expected_identity=VALIDATOR)


def test_cli_refuses_a_malformed_opt_in_before_wallet_access(monkeypatch) -> None:
    from cathedral_thin.independent_runtime import direct_validator as runtime

    monkeypatch.setenv(cr.COMMIT_REVEAL_OPT_IN_ENV, "yes")
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: pytest.fail("wallet opened before the opt-in"),
    )

    with pytest.raises(SystemExit, match="commit-reveal opt-in refused"):
        runtime.main(base._CLI_ARGUMENTS)


# Telemetry: a revealed commit is the write the public event reports ------------


def _identity_sha256(planned) -> str:
    return (
        "sha256:"
        + hashlib.sha256(canonical_document_bytes(planned.identity())).hexdigest()
    )


def test_a_proven_reveal_reads_from_the_journal_as_a_confirmed_write(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = commit_once(tmp_path, monkeypatch)
    plan_id = _identity_sha256(planned)

    # Stored, not revealed: no weights are written, so nothing is finalized.
    assert journal_receipt_for_plan(instance.state_path, plan_id) is None
    subtensor.substrate.finalized_number = 300
    assert instance.recover().status == STATUS_AWAITING_REVEAL
    assert journal_receipt_for_plan(instance.state_path, plan_id) is None

    subtensor.substrate.chain.reveal_block = REVEAL_BLOCK
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 30
    revealed = instance.recover()
    assert revealed is not None and revealed.status == STATUS_REVEALED

    public = journal_receipt_for_plan(instance.state_path, plan_id)
    assert public == applied_reveal_receipt(revealed)
    assert public.status == STATUS_CONFIRMED
    assert public.recovered is False
    assert public.block_number == REVEAL_BLOCK
    assert public.block_hash == revealed.block_hash
    assert (
        public.extrinsic_hash
        == journal(instance)["last_attempt"]["receipt"]["extrinsic_hash"]
    )
    # The shape the telemetry reader depends on, as the writer really wrote it.
    last = journal(instance)["last_attempt"]
    assert set(last) == {
        "attempt_id",
        "status",
        "identity",
        "intent",
        "receipt",
        "reveal",
    }
    assert set(last["reveal"]["outcome"]) == {
        "applied",
        "consumed_block",
        "consumed_block_hash",
        "confirmation_heads",
        "remapped_dests",
    }
    # Another plan is never answered with this attempt's receipt.
    assert journal_receipt_for_plan(instance.state_path, "sha256:" + "0" * 64) is None


def test_a_reveal_that_landed_on_a_reregistered_uid_is_not_reported(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned, _encryptor = commit_once(tmp_path, monkeypatch)
    subtensor.remap_after = REVEAL_BLOCK - 5
    subtensor.substrate.chain.reveal_block = REVEAL_BLOCK
    subtensor.substrate.finalized_number = REVEAL_BLOCK + 3
    assert instance.recover().status == STATUS_REVEALED

    # The event would name the hotkey the round scored, not the one paid.
    assert (
        journal_receipt_for_plan(instance.state_path, _identity_sha256(planned)) is None
    )


def test_an_unproven_reveal_is_not_reported(tmp_path: Path, monkeypatch) -> None:
    instance, subtensor, planned, _encryptor = commit_once(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.chain.reveal_block = REVEAL_BLOCK
    substrate.finalized_number = REVEAL_BLOCK + 300
    substrate.chain.discarded = set(range(0, REVEAL_BLOCK + 300 - 256))
    assert instance.recover().status == STATUS_REVEAL_UNPROVEN

    assert (
        journal_receipt_for_plan(instance.state_path, _identity_sha256(planned)) is None
    )


def test_only_a_proven_reveal_is_republished_as_confirmed() -> None:
    def receipt(status: str, recovered: bool) -> DirectSubmissionReceipt:
        return DirectSubmissionReceipt(
            status=status,
            attempt_id="sha256:" + "1" * 64,
            extrinsic_hash="0x" + "2" * 64,
            block_hash="0x" + "3" * 64,
            block_number=REVEAL_BLOCK,
            recovered=recovered,
        )

    for status, recovered in (
        (STATUS_CONFIRMED, False),
        (STATUS_COMMITTED, False),
        (STATUS_AWAITING_REVEAL, True),
        (STATUS_REVEAL_UNPROVEN, True),
        (STATUS_EXPIRED, True),
    ):
        unchanged = receipt(status, recovered)
        assert applied_reveal_receipt(unchanged) is unchanged
    stub = SimpleNamespace(status=STATUS_REVEALED)
    assert applied_reveal_receipt(stub) is stub


def _telemetry_round(keypair, marker: str):
    observed = replace(
        base.snapshot(miners=(base.MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    row = base.machine_row(marker)
    row["tee_kind"] = "tdx"
    row["phase_timings_ms"] = {"binding": 1}
    scored = base.round_result(row, miners=(base.MINER_ONE_AXON,))
    return observed, scored, build_direct_plan(observed, scored)


def _write_journal(path: Path, last_attempt: dict[str, Any]) -> None:
    # The telemetry reader accepts only the writer's canonical bytes.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": None,
                "last_attempt": last_attempt,
            }
        )
    )
    os.chmod(path, 0o600)


@pytest.mark.parametrize("kill_mid_commit", [False, True])
def test_a_commit_keeps_its_round_and_the_proven_reveal_publishes_it(
    tmp_path: Path, monkeypatch, kill_mid_commit: bool
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    observed, scored, planned = _telemetry_round(keypair, "committed")
    commit = DirectSubmissionReceipt(
        status=STATUS_COMMITTED,
        attempt_id="sha256:" + "1" * 64,
        extrinsic_hash="0x" + "2" * 64,
        block_hash="0x" + "3" * 64,
        block_number=INCLUSION,
        recovered=False,
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl", netuid=NETUID)
    pending = PendingTelemetryStore(spool)
    state_path = tmp_path / "writer" / "state.json"
    adapter = SimpleNamespace(qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST)
    monkeypatch.setattr(
        validator_runtime, "finalized_serving_miners_snapshot", lambda *_a: observed
    )
    monkeypatch.setattr(
        validator_runtime, "score_multicompute_round", lambda **_k: scored
    )

    def submit(_plan, **_kwargs):
        # The file must exist before the writer gets control, not in an
        # exception handler that SIGKILL/OOM would never run.
        assert pending.plan_identity_sha256() == _identity_sha256(planned)
        assert json.loads(pending.path.read_bytes())["receipt"] is None
        assert not spool.path.exists()
        if kill_mid_commit:
            raise SystemExit("simulate hard exit before submit returns")
        return commit

    def cycle():
        return run_direct_cycle(
            netuid=NETUID,
            subtensor=object(),
            keypair=keypair,
            verifier_adapter=adapter,
            writer=SimpleNamespace(
                recover=lambda: None,
                submit=submit,
                state_path=state_path,
                commit_reveal=cr.CommitRevealOptIn(1),
            ),
            telemetry_sink=spool,
            report_recovery=base.no_expired_recovery,
        )

    if kill_mid_commit:
        with pytest.raises(SystemExit, match="simulate hard exit"):
            cycle()
    else:
        committed = cycle()
        assert committed["status"] == STATUS_COMMITTED
        assert committed["telemetry"] == {"status": "AWAITING_REVEAL"}

    # Nothing is published while the weights are still secret.
    assert not spool.path.exists()
    assert pending.plan_identity_sha256() == _identity_sha256(planned)
    kept = json.loads(pending.path.read_bytes())
    assert kept["receipt"] is None
    round_observed_at = kept["candidate"]["observed_at"]

    # While the commit awaits its reveal the round stays unpublished.
    heads = [
        [REVEAL_BLOCK + offset, "0x" + f"{offset + 4}" * 64] for offset in range(3)
    ]
    attempt = {
        "attempt_id": commit.attempt_id,
        "status": STATUS_COMMITTED,
        "identity": planned.identity(),
        "intent": {},
        "receipt": commit.as_document(),
        "reveal": {
            "commit_epoch": EPOCH,
            "present_through_block": INCLUSION,
            "outcome": None,
        },
    }
    _write_journal(state_path, attempt)
    awaiting = run_direct_cycle(
        netuid=NETUID,
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=adapter,
        writer=SimpleNamespace(
            recover=lambda: replace(
                commit, status=STATUS_AWAITING_REVEAL, recovered=True
            ),
            state_path=state_path,
        ),
        telemetry_sink=spool,
        report_recovery=base.no_expired_recovery,
    )
    assert awaiting["status"] == STATUS_AWAITING_REVEAL
    assert awaiting["telemetry"] == {"status": "NO_FINALIZED_EVENT"}
    assert not spool.path.exists()
    assert pending.path.exists()

    # The reveal is proven: that cycle publishes the round it committed.
    attempt["status"] = STATUS_REVEALED
    attempt["reveal"] = {
        "commit_epoch": EPOCH,
        "present_through_block": REVEAL_BLOCK - 1,
        "outcome": {
            "applied": True,
            "consumed_block": REVEAL_BLOCK,
            "consumed_block_hash": heads[0][1],
            "confirmation_heads": heads,
            "remapped_dests": [],
        },
    }
    _write_journal(state_path, attempt)
    revealed = DirectSubmissionReceipt(
        status=STATUS_REVEALED,
        attempt_id=commit.attempt_id,
        extrinsic_hash=commit.extrinsic_hash,
        block_hash=heads[0][1],
        block_number=REVEAL_BLOCK,
        recovered=True,
        confirmation_heads=tuple((row[0], row[1]) for row in heads),
    )
    reported: list[dict[str, Any]] = []

    def stop_after_recovery(*_args):
        raise DirectValidatorError("stop after recovery")

    monkeypatch.setattr(
        validator_runtime, "finalized_serving_miners_snapshot", stop_after_recovery
    )
    with pytest.raises(DirectValidatorError, match="stop after recovery"):
        run_direct_cycle(
            netuid=NETUID,
            subtensor=object(),
            keypair=keypair,
            verifier_adapter=adapter,
            writer=SimpleNamespace(recover=lambda: revealed, state_path=state_path),
            telemetry_sink=spool,
            report_recovery=reported.append,
        )

    assert [event["status"] for event in reported] == [STATUS_REVEALED]
    event = latest_telemetry_event(spool.path, netuid=NETUID)
    assert reported[0]["telemetry"] == {
        "status": "SPOOLED",
        "event_id": event["event_id"],
    }
    assert event["submission"] == {
        "status": STATUS_CONFIRMED,
        "block_number": REVEAL_BLOCK,
        "block_hash": heads[0][1],
        "recovered": False,
    }
    # The event is the committed round: its time, its anchor and its machines.
    assert event["observed_at"] == round_observed_at
    assert event["anchor"]["block_number"] == observed.block_number
    assert [miner["uid"] for miner in event["miners"]] == [base.MINER_ONE_AXON.uid]
    assert event["miners"][0]["weight_u16"] == W
    assert not pending.path.exists()
    assert len(spool.path.read_text().splitlines()) == 1


def test_a_commit_first_publishes_a_prior_round_that_is_already_bound(
    tmp_path: Path, monkeypatch
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    observed, scored, planned = _telemetry_round(keypair, "earlier")
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl", netuid=NETUID)
    pending = PendingTelemetryStore(spool)
    # An earlier round whose finalized receipt was bound, then not spooled.
    earlier = DirectSubmissionReceipt(
        status=STATUS_CONFIRMED,
        attempt_id="sha256:" + "5" * 64,
        extrinsic_hash="0x" + "6" * 64,
        block_hash="0x" + "7" * 64,
        block_number=REVEAL_BLOCK,
        recovered=False,
    )
    pending.prepare(
        telemetry_runtime.build_telemetry_candidate(
            result_rows=scored.rows, plan=planned
        ),
        planned,
        earlier,
    )
    commit = DirectSubmissionReceipt(
        status=STATUS_COMMITTED,
        attempt_id="sha256:" + "1" * 64,
        extrinsic_hash="0x" + "2" * 64,
        block_hash="0x" + "3" * 64,
        block_number=INCLUSION,
        recovered=False,
    )
    monkeypatch.setattr(
        validator_runtime, "finalized_serving_miners_snapshot", lambda *_a: observed
    )
    monkeypatch.setattr(
        validator_runtime, "score_multicompute_round", lambda **_k: scored
    )

    result = run_direct_cycle(
        netuid=NETUID,
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(recover=lambda: None, submit=lambda _p, **_k: commit),
        telemetry_sink=spool,
        report_recovery=base.no_expired_recovery,
    )

    event = latest_telemetry_event(spool.path, netuid=NETUID)
    assert event["submission"]["block_number"] == REVEAL_BLOCK
    assert result["reconciled_telemetry_event_id"] == event["event_id"]
    assert result["telemetry"] == {"status": "AWAITING_REVEAL"}
    # The new commit's round now waits in its place.
    assert json.loads(pending.path.read_bytes())["receipt"] is None


def test_a_failed_round_projection_never_changes_a_commit(
    tmp_path: Path, monkeypatch
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    observed, scored, _planned = _telemetry_round(keypair, "unprojected")
    commit = SimpleNamespace(
        status=STATUS_COMMITTED, as_document=lambda: {"status": STATUS_COMMITTED}
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl", netuid=NETUID)
    monkeypatch.setattr(
        validator_runtime, "finalized_serving_miners_snapshot", lambda *_a: observed
    )
    monkeypatch.setattr(
        validator_runtime, "score_multicompute_round", lambda **_k: scored
    )

    def broken(**_kwargs):
        raise telemetry_runtime.TelemetryError("no candidate")

    monkeypatch.setattr(validator_runtime, "build_telemetry_candidate", broken)

    result = run_direct_cycle(
        netuid=NETUID,
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(recover=lambda: None, submit=lambda _p, **_k: commit),
        telemetry_sink=spool,
        report_recovery=base.no_expired_recovery,
    )

    assert result["status"] == STATUS_COMMITTED
    assert result["telemetry"] == {"status": "FAILED"}
    assert not PendingTelemetryStore(spool).path.exists()


def test_a_commit_without_a_telemetry_sink_reports_no_telemetry(monkeypatch) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    observed, scored, _planned = _telemetry_round(keypair, "quiet")
    commit = SimpleNamespace(
        status=STATUS_COMMITTED, as_document=lambda: {"status": STATUS_COMMITTED}
    )
    monkeypatch.setattr(
        validator_runtime, "finalized_serving_miners_snapshot", lambda *_a: observed
    )
    monkeypatch.setattr(
        validator_runtime, "score_multicompute_round", lambda **_k: scored
    )

    result = run_direct_cycle(
        netuid=NETUID,
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(recover=lambda: None, submit=lambda _p, **_k: commit),
        report_recovery=base.no_expired_recovery,
    )

    assert result["status"] == STATUS_COMMITTED
    assert "telemetry" not in result
