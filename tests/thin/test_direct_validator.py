from __future__ import annotations

import importlib.util
import json
import os
import socket
import stat
from contextlib import contextmanager
from dataclasses import replace
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest
from async_substrate_interface.errors import (
    StateDiscardedError,
    SubstrateRequestException,
)
from async_substrate_interface.sync_substrate import SubstrateInterface
from async_substrate_interface.types import RuntimeCache
from bittensor.core.subtensor import Subtensor
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import (
    FINNEY_GENESIS_HASH,
    MORTAL_PERIOD_BLOCKS,
    NETUID,
    W,
)
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import failed_write_recovery as record_cli
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    DirectSubmissionReceipt,
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.direct_validator import (
    build_direct_plan,
    finalized_serving_miners_snapshot,
    run_direct_cycle,
)
from cathedral_thin.independent_runtime.direct_writer import (
    DirectSubmissionAmbiguous,
    DirectSubmissionContradiction,
    DirectSubmissionFinalizedFailure,
    DirectWeightWriter,
    FailedWriteRecordRefused,
    PHASE_FINALIZED_FAILED,
    STATE_SCHEMA,
    STATUS_CONFIRMED,
    STATUS_EXPIRED,
    STATUS_FINALIZED_FAILED,
    STATUS_RECOVERED,
    canonical_state_path,
)
from cathedral_thin.independent_runtime.errors import ChainClientError, QuoteVerifyError
from cathedral_thin.independent_runtime.fleet_score import (
    DISCOVERY_RESPONSE_DEADLINE_SECONDS,
    FULL_CYCLE_RESPONSE_DEADLINE_SECONDS,
    MINER_RESPONSE_DEADLINE_SECONDS,
    MultiComputeRound,
)
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.telemetry import TelemetrySpool

VALIDATOR = "5Validator"
MINER_ONE = "5MinerOne"
MINER_TWO = "5MinerTwo"
OTHER_VALIDATOR = "5OtherValidator"
ANCHOR_NUMBER = 100
ANCHOR_HASH = "0x" + "a" * 64
FRESH_HASH = "0x" + "b" * 64
EXTRINSIC_HASH = "0x" + "c" * 64
INCLUSION_HASH = "0x" + "d" * 64
SECOND_EXTRINSIC_HASH = "0x" + "e" * 64
ORPHAN_HASH = "0x" + "f" * 64
REPORTED_HASH = "0x" + "9" * 64
MINER_ONE_AXON = ServingAxon(19, MINER_ONE, "1.1.1.1", 8081)
MINER_TWO_AXON = ServingAxon(20, MINER_TWO, "8.8.8.8", 8081)
_Q32 = 1 << 32


def pallet_storage_weights(weights: list[int] | tuple[int, ...]) -> list[int]:
    """Independent oracle for Subtensor's I32F32 max-upscale storage step."""

    if not weights:
        return []
    maximum = max(weights)
    if maximum == 0:
        return [0] * len(weights)
    if maximum > 32_768:
        multiplier_q32 = (W * _Q32) // maximum
        return [(weight * multiplier_q32 + _Q32 // 2) // _Q32 for weight in weights]
    return [
        (((weight * W * _Q32) // maximum) + _Q32 // 2) // _Q32 for weight in weights
    ]


class FakeKeypair:
    ss58_address = VALIDATOR

    def sign(self, body: bytes) -> bytes:
        del body
        return b"s" * 64


class Axon:
    def __init__(self, ip: str, port: int, *, serving: bool) -> None:
        self.ip = ip
        self.port = port
        self.is_serving = serving


class Metagraph:
    def __init__(
        self,
        block: int = ANCHOR_NUMBER,
        *,
        miners: tuple[ServingAxon, ...] = (MINER_ONE_AXON,),
        include_other_validator: bool = False,
    ) -> None:
        self.block = block
        self.uids = [7]
        self.hotkeys = [VALIDATOR]
        self.validator_permit = [True]
        self.axons = [Axon("0.0.0.0", 0, serving=False)]
        self.last_update = [max(0, block - 100)]
        self.total_stake = [SimpleNamespace(rao=10_000)]
        if include_other_validator:
            self.uids.append(8)
            self.hotkeys.append(OTHER_VALIDATOR)
            self.validator_permit.append(True)
            self.axons.append(Axon("9.9.9.9", 8081, serving=True))
            self.last_update.append(0)
            self.total_stake.append(SimpleNamespace(rao=10_000))
        for miner in miners:
            self.uids.append(miner.uid)
            self.hotkeys.append(miner.hotkey)
            self.validator_permit.append(False)
            self.axons.append(Axon(miner.ip, miner.port, serving=True))
            self.last_update.append(0)
            self.total_stake.append(SimpleNamespace(rao=0))


class SnapshotSubstrate:
    def get_chain_finalised_head(self) -> str:
        return ANCHOR_HASH

    def get_block_number(self, block_hash: str) -> int:
        assert block_hash == ANCHOR_HASH
        return ANCHOR_NUMBER

    def get_block_hash(self, block: int) -> str:
        if block == 0:
            return FINNEY_GENESIS_HASH
        assert block == ANCHOR_NUMBER
        return ANCHOR_HASH


class SnapshotSubtensor:
    substrate = SnapshotSubstrate()

    def __init__(self, metagraph: Metagraph | None = None) -> None:
        self.value = metagraph or Metagraph()

    def metagraph(self, netuid: int, *, block: int) -> Metagraph:
        assert netuid == 39
        assert block == ANCHOR_NUMBER
        return self.value


def snapshot(
    block_number: int = ANCHOR_NUMBER,
    *,
    miners: tuple[ServingAxon, ...] = (MINER_ONE_AXON,),
) -> FinalizedMetagraphSnapshot:
    block_hash = ANCHOR_HASH if block_number == ANCHOR_NUMBER else FRESH_HASH
    return FinalizedMetagraphSnapshot(
        block_number=block_number,
        block_hash=block_hash,
        validator_uid=7,
        validator_hotkey=VALIDATOR,
        miners=miners,
        skipped_axons={
            "refuse_or_canary": 0,
            "port_zero": 0,
            "not_serving": 0,
            "unroutable": 0,
            "unusable_ip": 0,
        },
    )


def machine_row(
    marker: str,
    *,
    uid: int = 19,
    hotkey: str = MINER_ONE,
    paid: bool = True,
) -> dict[str, object]:
    row: dict[str, object] = {
        "uid": uid,
        "hotkey": hotkey,
        "endpoint": f"https://1.1.{uid}.{marker}:8081",
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "sat_units": 20,
        "counted_units": 20 if paid else 0,
        "channel_id": f"channel-{uid}-{marker}",
        "machine_id": f"machine-{uid}-{marker}",
    }
    if not paid:
        row["score_reasons"] = ["duplicate_hardware_identity"]
    return row


def round_result(
    *rows: dict[str, object],
    miners: tuple[ServingAxon, ...] = (MINER_ONE_AXON,),
    legacy_uids: frozenset[int] = frozenset(),
) -> MultiComputeRound:
    fleets = []
    verified: dict[str, int] = {}
    for miner in miners:
        matching = [row for row in rows if row["uid"] == miner.uid]
        fleets.append(
            {
                "uid": miner.uid,
                "hotkey": miner.hotkey,
                "primary": f"https://{miner.ip}:{miner.port}",
                "ok": True,
                "singleton_compatibility": miner.uid in legacy_uids,
                "candidate_count": len(matching),
                "endpoints": [row["endpoint"] for row in matching],
            }
        )
        units = sum(int(row["counted_units"]) for row in matching)
        if units:
            verified[miner.hotkey] = units
    return MultiComputeRound(
        rows=tuple(dict(row) for row in rows),
        fleet=tuple(fleets),
        verified_units=verified,
        pass_count=len(rows),
        qvl_infra_count=0,
        feature_blocked=False,
        exclusions=(),
        blockers=(),
    )


def plan(
    block_number: int = ANCHOR_NUMBER,
    *,
    miners: tuple[ServingAxon, ...] = (MINER_ONE_AXON,),
    rows: tuple[dict[str, object], ...] | None = None,
) -> DirectWeightPlan:
    selected_rows = rows or (machine_row("1"),)
    return build_direct_plan(
        snapshot(block_number, miners=miners),
        round_result(*selected_rows, miners=miners),
    )


def test_finalized_snapshot_discovers_all_miners_and_excludes_all_validators() -> None:
    graph = Metagraph(
        miners=(MINER_TWO_AXON, MINER_ONE_AXON), include_other_validator=True
    )

    observed = finalized_serving_miners_snapshot(
        SnapshotSubtensor(graph), FakeKeypair()
    )

    assert observed.block_number == ANCHOR_NUMBER
    assert observed.block_hash == ANCHOR_HASH
    assert observed.validator_uid == 7
    assert observed.miners == (MINER_ONE_AXON, MINER_TWO_AXON)
    assert all(miner.hotkey != OTHER_VALIDATOR for miner in observed.miners)


def test_finalized_snapshot_skips_private_miner_without_losing_healthy_miner() -> None:
    private = ServingAxon(21, "5PrivateMiner", "10.0.0.1", 8081)
    graph = Metagraph(miners=(private, MINER_ONE_AXON))

    observed = finalized_serving_miners_snapshot(
        SnapshotSubtensor(graph), FakeKeypair()
    )

    assert observed.miners == (MINER_ONE_AXON,)
    assert observed.skipped_axons["unroutable"] == 1


def test_cycle_with_only_unroutable_miners_refuses_without_writer_submit() -> None:
    private = ServingAxon(21, "5PrivateMiner", "10.0.0.1", 8081)
    writer_object = SimpleNamespace(
        recover=lambda: None,
        submit=lambda *_args, **_kwargs: pytest.fail("unroutable miner reached writer"),
    )

    with pytest.raises(DirectValidatorError, match="no serving miner"):
        run_direct_cycle(
            subtensor=SnapshotSubtensor(Metagraph(miners=(private,))),
            keypair=FakeKeypair(),
            verifier_adapter=SimpleNamespace(
                qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
            ),
            writer=writer_object,
            report_recovery=no_expired_recovery,
        )


def test_finalized_snapshot_refuses_no_serving_miners_or_missing_permit() -> None:
    no_miner = Metagraph(miners=())
    no_permit = Metagraph()
    no_permit.validator_permit[0] = False

    with pytest.raises(DirectValidatorError, match="no serving miner"):
        finalized_serving_miners_snapshot(SnapshotSubtensor(no_miner), FakeKeypair())
    with pytest.raises(DirectValidatorError, match="lacks a finalized permit"):
        finalized_serving_miners_snapshot(SnapshotSubtensor(no_permit), FakeKeypair())


def test_finalized_snapshot_refuses_a_truthy_non_boolean_permit() -> None:
    graph = Metagraph()
    graph.validator_permit[0] = 1

    with pytest.raises(DirectValidatorError, match="explicit boolean"):
        finalized_serving_miners_snapshot(SnapshotSubtensor(graph), FakeKeypair())


def test_plan_counts_unique_verified_machines_per_uid_and_normalizes_zero_burn() -> (
    None
):
    miners = (MINER_ONE_AXON, MINER_TWO_AXON)
    result = round_result(
        machine_row("1"),
        machine_row("2"),
        machine_row("3", uid=20, hotkey=MINER_TWO),
        miners=miners,
    )

    planned = build_direct_plan(snapshot(miners=miners), result)

    assert planned.raw_scores == ((19, 2), (20, 1))
    assert planned.machine_ids_by_uid == (
        (19, ("machine-19-1", "machine-19-2")),
        (20, ("machine-20-3",)),
    )
    assert planned.wire_uids == (19, 20)
    assert planned.wire_weights == (43690, 21845)
    assert sum(planned.wire_weights) == W
    assert planned.identity()["burn_uid"] is None
    assert planned.identity()["burn_weight"] == 0
    assert planned.qvl_digest == qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
    assert planned.identity()["qvl_digest"] == qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST


def test_plan_tie_break_and_duplicate_zeroing_are_deterministic() -> None:
    miners = (MINER_TWO_AXON, MINER_ONE_AXON)
    result = round_result(
        machine_row("1"),
        machine_row("2", paid=False),
        machine_row("3", uid=20, hotkey=MINER_TWO),
        miners=miners,
    )

    planned = build_direct_plan(snapshot(miners=miners), result)

    assert planned.raw_scores == ((19, 1), (20, 1))
    assert planned.wire_uids == (19, 20)
    assert planned.wire_weights == (32768, 32767)


def test_phase_latency_is_evidence_only_and_never_changes_score() -> None:
    source = machine_row("1")
    fast = round_result(source)
    slow_row = dict(source)
    slow_row["phase_timings_ms"] = {
        "binding": 10_000,
        "evidence": 20_000,
        "fleet": 30_000,
        "qvl": 40_000,
        "snp": None,
        "sat": 50_000,
    }
    slow = round_result(slow_row)

    fast_plan = build_direct_plan(snapshot(), fast)
    slow_plan = build_direct_plan(snapshot(), slow)

    assert slow_plan.raw_scores == fast_plan.raw_scores == ((19, 1),)
    assert slow_plan.wire_uids == fast_plan.wire_uids == (19,)
    assert slow_plan.wire_weights == fast_plan.wire_weights == (W,)


def test_evidence_summary_is_fixed_shape_deterministic_and_bounded() -> None:
    first = machine_row("1")
    first["phase_timings_ms"] = {
        "binding": 4,
        "evidence": 8,
        "fleet": 12,
        "qvl": 16,
        "snp": None,
        "sat": 20,
    }
    second = machine_row("2", paid=False)
    second["phase_timings_ms"] = {
        "binding": 6,
        "evidence": None,
        "fleet": 12,
        "qvl": 18,
        "snp": None,
        "sat": None,
    }
    exclusions = (
        "fleet uid 19: request failed with private detail",
        "duplicate endpoints: 2 verified claimants zeroed",
        "duplicate channels: 2 verified claimants zeroed",
        "duplicate hardware: 2 verified claimants zeroed",
        "unexpected private detail",
    )
    result = replace(
        round_result(first, second),
        exclusions=exclusions,
    )
    result = replace(
        result,
        fleet=tuple({**row, "phase_timings_ms": {"fleet": 12}} for row in result.fleet),
    )
    observed = replace(
        snapshot(),
        skipped_axons={**snapshot().skipped_axons, "unroutable": 2},
    )

    planned = build_direct_plan(observed, result)
    summary = runtime._evidence_cycle_summary(observed, result, planned)
    reordered = runtime._evidence_cycle_summary(
        observed,
        replace(result, rows=tuple(reversed(result.rows)), exclusions=exclusions[::-1]),
        planned,
    )

    assert reordered == summary
    assert summary["phase_timings_ms"] == {
        "binding": {"samples": 2, "minimum": 4, "maximum": 6, "sample_sum": 10},
        "evidence": {"samples": 1, "minimum": 8, "maximum": 8, "sample_sum": 8},
        "fleet": {"samples": 1, "minimum": 12, "maximum": 12, "sample_sum": 12},
        "qvl": {"samples": 2, "minimum": 16, "maximum": 18, "sample_sum": 34},
        "snp": {"samples": 0, "minimum": None, "maximum": None, "sample_sum": 0},
        "sat": {"samples": 1, "minimum": 20, "maximum": 20, "sample_sum": 20},
    }
    assert summary["exclusions"] == {
        "skipped_axons": {
            "refuse_or_canary": 0,
            "port_zero": 0,
            "not_serving": 0,
            "unroutable": 2,
            "unusable_ip": 0,
        },
        "failed_fleets": 0,
        "excluded_machine_rows": 1,
        "reported": 5,
        "reported_categories": {
            "fleet": 1,
            "duplicate_endpoint": 1,
            "duplicate_channel": 1,
            "duplicate_hardware": 1,
            "other": 1,
        },
    }
    encoded = json.dumps(summary, sort_keys=True)
    assert "private detail" not in encoded
    assert len(encoded) < 1_000
    assert planned.raw_scores == ((19, 1),)


def test_legacy_singleton_fleet_earns_zero_without_blocking_other_miners() -> None:
    miners = (MINER_ONE_AXON, MINER_TWO_AXON)
    result = round_result(
        machine_row("1"),
        machine_row("2", uid=20, hotkey=MINER_TWO),
        miners=miners,
        legacy_uids=frozenset({19}),
    )

    planned = build_direct_plan(snapshot(miners=miners), result)

    assert planned.raw_scores == ((19, 0), (20, 1))
    assert planned.wire_uids == (20,)
    assert planned.wire_weights == (W,)


def test_qvl_infrastructure_failure_halts_instead_of_redistributing() -> None:
    result = replace(round_result(machine_row("1")), qvl_infra_count=1)

    with pytest.raises(DirectValidatorError, match="not fully proven"):
        build_direct_plan(snapshot(), result)


class Extrinsic:
    def __init__(
        self, value: dict[str, object], *, extrinsic_hash: str = EXTRINSIC_HASH
    ) -> None:
        self.value = value
        # async-substrate-interface stores the hash on GenericExtrinsic, not
        # inside GenericExtrinsic.value.
        self.extrinsic_hash = extrinsic_hash


class Signed:
    def __init__(self, extrinsic_hash: str = EXTRINSIC_HASH) -> None:
        self.extrinsic_hash = extrinsic_hash


class ExecutionReceipt:
    is_success = True
    error_message = None


class WriterSubstrate:
    def __init__(self) -> None:
        self.finalized_number = ANCHOR_NUMBER + 4
        self.inclusion_block = ANCHOR_NUMBER + 2
        self.included = False
        self.raise_after_include = False
        self.raise_without_include = False
        self.wrong_call = False
        self.wrong_storage = False
        self.sign_calls = 0
        self.submit_calls = 0
        self.submission_flags: list[tuple[bool, bool]] = []
        self.expected_uids = [19]
        self.expected_weights = [W]
        # The finalized head the writer signs at, the account's next index,
        # and the hash the next signature gets.
        self.sign_head = ANCHOR_NUMBER + 1
        self.nonce = 4
        self.extrinsic_hash = EXTRINSIC_HASH
        self.included_hash = EXTRINSIC_HASH
        self.signed: list[tuple[int, int]] = []
        self.broadcast: list[str] = []
        # The best head the node validates a broadcast against; by default it
        # sits on the finalized sign head, as with no finality lag.
        self.best_number = ANCHOR_NUMBER + 1
        self.best_reads = 0
        # The pinned client's number-to-hash map. get_block_hash below is the
        # library's own cached lookup over it; rpc_request is the node.
        self.runtime_cache = RuntimeCache()
        # Blocks the node served as best head and then reorged out. With
        # best_orphaned, signing initializes the runtime at the best head by
        # number while the node still serves the orphan there, so the client
        # caches the orphan for that height.
        self.orphans: dict[int, str] = {}
        self.serving_orphans = False
        self.best_orphaned = False
        # The node drops bytes that never land, and the library's watch then
        # raises, exactly as for a dropped or invalid subscription.
        self.drop_after_broadcast = False
        # The node reports the bytes finalized, yet finalized history never
        # holds them, and the finalized head reaches the era's last block.
        self.report_finalized_without_inclusion = False
        # Model a client that the direct validator already bounded.
        self.retry_timeout = writer_runtime.DIRECT_RPC_RETRY_TIMEOUT_SECONDS
        self.max_retries = writer_runtime.DIRECT_RPC_MAX_RETRIES
        self.waits_seen: dict[str, tuple[float, int]] = {}

    def block_hash(self, block: int) -> str:
        if block == 0:
            return FINNEY_GENESIS_HASH
        if block == ANCHOR_NUMBER:
            return ANCHOR_HASH
        if block == ANCHOR_NUMBER + 1:
            return FRESH_HASH
        if block == self.inclusion_block:
            return INCLUSION_HASH
        return "0x" + f"{block:064x}"

    # The pinned client's cached lookup, run as is: its number-to-hash map,
    # then a memo of the node's chain_getBlockHash answers.
    get_block_hash = SubstrateInterface.get_block_hash
    _get_block_hash = SubstrateInterface._get_block_hash

    def rpc_request(self, method: str, params: list[object]) -> dict[str, object]:
        # The node, answering from its canonical chain once any fork is gone.
        assert method == "chain_getBlockHash"
        (block,) = params
        if self.serving_orphans and block in self.orphans:
            return {"jsonrpc": "2.0", "result": self.orphans[block]}
        return {"jsonrpc": "2.0", "result": self.block_hash(block)}

    def get_chain_finalised_head(self) -> str:
        return self.block_hash(self.finalized_number)

    def get_block_number(self, block_hash: str | None) -> int:
        if block_hash is None:
            self.best_reads += 1
            return self.best_number
        for block in range(0, self.finalized_number + 1):
            if self.block_hash(block) == block_hash:
                return block
        raise ValueError(block_hash)

    def get_account_next_index(self, hotkey: str) -> int:
        assert hotkey == VALIDATOR
        return self.nonce

    def create_signed_extrinsic(self, *, call, keypair, nonce, era):
        assert call == "direct-call"
        assert keypair.ss58_address == VALIDATOR
        assert nonce == self.nonce
        assert era == {
            "period": MORTAL_PERIOD_BLOCKS,
            "current": self.sign_head,
        }
        self.sign_calls += 1
        self.signed.append((era["current"], nonce))
        self.waits_seen["sign"] = (self.retry_timeout, self.max_retries)
        if self.best_orphaned:
            self.orphans[self.best_number] = ORPHAN_HASH
            self.serving_orphans = True
            self.get_block_hash(self.best_number)
            self.serving_orphans = False
        return Signed(self.extrinsic_hash)

    def submit_extrinsic(
        self, signed, *, wait_for_inclusion: bool, wait_for_finalization: bool
    ):
        assert isinstance(signed, Signed)
        self.submit_calls += 1
        self.broadcast.append(signed.extrinsic_hash)
        self.submission_flags.append((wait_for_inclusion, wait_for_finalization))
        self.waits_seen["submit"] = (self.retry_timeout, self.max_retries)
        if self.raise_without_include:
            raise TimeoutError("response lost")
        if self.drop_after_broadcast:
            raise SubstrateRequestException("Subscription 1 dropped: {'dropped': None}")
        if self.report_finalized_without_inclusion:
            self.finalized_number = self.sign_head + MORTAL_PERIOD_BLOCKS - 1
            return SimpleNamespace(
                extrinsic_hash=signed.extrinsic_hash, block_hash=REPORTED_HASH
            )
        self.included = True
        self.included_hash = signed.extrinsic_hash
        if self.raise_after_include:
            raise TimeoutError("response lost after inclusion")
        return Signed(signed.extrinsic_hash)

    def get_block(self, *, block_hash: str) -> dict[str, object]:
        if block_hash in self.orphans.values():
            # The node still serves the orphan, which never held this write.
            return {"extrinsics": []}
        block_number = self.get_block_number(block_hash)
        if not self.included or block_number != self.inclusion_block:
            return {"extrinsics": []}
        weights = [1] if self.wrong_call else list(self.expected_weights)
        return {
            "extrinsics": [
                Extrinsic(
                    {
                        "address": VALIDATOR,
                        "call": {
                            "call_module": "SubtensorModule",
                            "call_function": "set_mechanism_weights",
                            "call_args": [
                                {"name": "netuid", "value": 39},
                                {"name": "mecid", "value": 0},
                                {"name": "dests", "value": self.expected_uids},
                                {"name": "weights", "value": weights},
                                {"name": "version_key", "value": 10005000},
                            ],
                        },
                    },
                    extrinsic_hash=self.included_hash,
                )
            ]
        }

    def retrieve_extrinsic_by_hash(
        self, block_hash: str, extrinsic_hash: str
    ) -> ExecutionReceipt:
        assert block_hash == INCLUSION_HASH
        assert extrinsic_hash == self.included_hash
        return ExecutionReceipt()

    def query(self, *, module, storage_function, params, block_hash):
        assert module == "SubtensorModule"
        if storage_function == "StakeThreshold":
            assert params == []
            assert block_hash == self.block_hash(self.sign_head)
            return self.owner.stake_threshold
        if storage_function == "WeightsVersionKey":
            assert params == [39]
            assert block_hash == self.block_hash(self.sign_head)
            return 0
        assert storage_function == "Weights"
        assert params[1] == 7
        self.get_block_number(block_hash)
        weights = (
            [1] if self.wrong_storage else pallet_storage_weights(self.expected_weights)
        )
        return list(zip(self.expected_uids, weights))


class WriterSubtensor:
    def __init__(
        self,
        *,
        miners: tuple[ServingAxon, ...] = (MINER_ONE_AXON,),
    ) -> None:
        self.substrate = WriterSubstrate()
        self.substrate.owner = self
        self.miners = miners
        self.blocks_since = 100
        self.rate_limit = 20
        self.remap_after: int | None = None
        self.extra_miner_after: int | None = None
        self.truthy_permit_at: int | None = None
        self.validator_stake = 10_000
        self.stake_threshold = 1_000
        self.eligibility_blocks: list[int] = []
        self.metagraph_reads: list[tuple[int, str]] = []

    # bittensor's by-number lookup and its memo, run as is: every read that
    # names only a block, the metagraph included, resolves it here.
    get_block_hash = Subtensor.get_block_hash
    _get_block_hash = Subtensor._get_block_hash

    def metagraph(self, netuid: int, *, block: int) -> Metagraph:
        assert netuid == 39
        block_hash = self.get_block_hash(block)
        self.metagraph_reads.append((block, block_hash))
        if block_hash in self.substrate.orphans.values():
            # A pruning node discards a reorged-out block's state.
            raise StateDiscardedError(block_hash)
        miners = self.miners
        if self.remap_after is not None and block >= self.remap_after:
            miners = tuple(
                replace(miner, hotkey="5Replacement") if miner.uid == 19 else miner
                for miner in miners
            )
        if self.extra_miner_after is not None and block >= self.extra_miner_after:
            miners = (*miners, MINER_TWO_AXON)
        result = Metagraph(block, miners=miners)
        if block == self.substrate.sign_head:
            result.last_update[0] = block - self.blocks_since
        if self.truthy_permit_at is not None and block >= self.truthy_permit_at:
            result.validator_permit[0] = 1
        result.total_stake[0] = SimpleNamespace(rao=self.validator_stake)
        return result

    def get_metagraph_info(
        self, netuid: int, mechid: int, *, block: int
    ) -> SimpleNamespace:
        assert (netuid, mechid) == (39, 0)
        graph = self.metagraph(netuid, block=block)
        size = max(graph.uids) + 1
        hotkeys = [""] * size
        permits = [False] * size
        stakes = [SimpleNamespace(rao=0) for _ in range(size)]
        for index, uid in enumerate(graph.uids):
            hotkeys[uid] = graph.hotkeys[index]
            permits[uid] = graph.validator_permit[index]
            stakes[uid] = graph.total_stake[index]
        return SimpleNamespace(
            block=block,
            hotkeys=hotkeys,
            validator_permit=permits,
            total_stake=stakes,
        )

    def weights_rate_limit(self, netuid: int, *, block: int) -> int:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        self.eligibility_blocks.append(block)
        return self.rate_limit

    def blocks_since_last_update(self, netuid: int, uid: int, *, block: int) -> int:
        assert (netuid, uid, block) == (NETUID, 7, self.substrate.sign_head)
        return self.blocks_since

    def min_allowed_weights(self, *, netuid: int, block: int) -> int:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        return 1

    def max_weight_limit(self, *, netuid: int, block: int) -> float:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        return 1.0

    def commit_reveal_enabled(self, *, netuid: int, block: int) -> bool:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        return False

    def get_mechanism_count(self, netuid: int, *, block: int) -> int:
        assert (netuid, block) == (NETUID, self.substrate.sign_head)
        return 1


def writer(
    tmp_path: Path,
    monkeypatch,
    *,
    planned: DirectWeightPlan | None = None,
) -> tuple[DirectWeightWriter, WriterSubtensor, DirectWeightPlan]:
    selected = planned or plan()
    miners = selected.snapshot.miners
    subtensor = WriterSubtensor(miners=miners)
    subtensor.substrate.expected_uids = list(selected.wire_uids)
    subtensor.substrate.expected_weights = list(selected.wire_weights)
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    instance = DirectWeightWriter(
        subtensor=subtensor,
        keypair=FakeKeypair(),
        snapshot_reader=lambda _subtensor, _keypair: replace(
            snapshot(subtensor.substrate.sign_head, miners=miners),
            block_hash=subtensor.substrate.block_hash(subtensor.substrate.sign_head),
        ),
        call_builder=lambda _kwargs: "direct-call",
    )
    return instance, subtensor, selected


def no_expired_recovery(event: dict[str, object]) -> None:
    pytest.fail(f"cycle reported an unexpected expired recovery: {event}")


def submit_before_deadline(instance: DirectWeightWriter, planned: DirectWeightPlan):
    return instance.submit(
        planned,
        cycle_deadline_monotonic=writer_runtime.time.monotonic() + 600.0,
    )


def test_writer_uses_one_canonical_signer_network_path(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    first = DirectWeightWriter(subtensor=object(), keypair=FakeKeypair())
    second = DirectWeightWriter(subtensor=object(), keypair=FakeKeypair())

    assert first.state_path == second.state_path == canonical_state_path(FakeKeypair())
    assert first.state_path == (
        tmp_path / "finney-sn39-mechanism-0" / VALIDATOR / "state.json"
    )


def test_writer_process_lock_allows_only_one_recurring_instance(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    first = DirectWeightWriter(subtensor=object(), keypair=FakeKeypair())
    second = DirectWeightWriter(subtensor=object(), keypair=FakeKeypair())

    with first.process_locked():
        with pytest.raises(DirectSubmissionAmbiguous, match="process lock"):
            with second.process_locked():
                pytest.fail("second recurring validator acquired the signer lock")


def test_default_state_root_is_deterministic_per_user() -> None:
    assert writer_runtime.DIRECT_STATE_ROOT == (
        Path.home() / ".local/state/cathedral-validator/direct-writer"
    )
    assert not str(writer_runtime.DIRECT_STATE_ROOT).startswith("/var/lib/")


def test_multi_uid_writer_persists_exact_intent_and_confirms_three_heads(
    tmp_path: Path, monkeypatch
) -> None:
    miners = (MINER_ONE_AXON, MINER_TWO_AXON)
    planned = plan(
        miners=miners,
        rows=(
            machine_row("1"),
            machine_row("2"),
            machine_row("3", uid=20, hotkey=MINER_TWO),
        ),
    )
    instance, subtensor, _planned = writer(tmp_path, monkeypatch, planned=planned)

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert receipt.extrinsic_hash == EXTRINSIC_HASH
    assert receipt.block_hash == INCLUSION_HASH
    assert receipt.recovered is False
    assert [row[0] for row in receipt.confirmation_heads] == [102, 103, 104]
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1
    assert subtensor.substrate.submission_flags == [(True, True)]
    state_path = instance.state_path
    state = json.loads(state_path.read_text(encoding="ascii"))
    assert state["schema"] == STATE_SCHEMA
    assert state["pending"] is None
    assert state["last_attempt"]["identity"]["raw_scores"] == [[19, 2], [20, 1]]
    assert state["last_attempt"]["intent"]["kwargs"]["dests"] == [19, 20]
    assert state["last_attempt"]["intent"]["kwargs"]["weights"] == [43690, 21845]
    assert state["last_attempt"]["intent"]["eligibility"]["weights_rate_limit"] == 20
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_writer_confirms_subtensor_max_upscaled_tied_weights(
    tmp_path: Path, monkeypatch
) -> None:
    miners = (MINER_ONE_AXON, MINER_TWO_AXON)
    planned = plan(
        miners=miners,
        rows=(
            machine_row("1"),
            machine_row("2", uid=20, hotkey=MINER_TWO),
        ),
    )
    assert planned.wire_weights == (32_768, 32_767)
    assert pallet_storage_weights(planned.wire_weights) == [65_535, 65_533]
    instance, subtensor, _planned = writer(tmp_path, monkeypatch, planned=planned)

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert subtensor.substrate.expected_weights == [32_768, 32_767]
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["intent"]["kwargs"]["weights"] == [
        32_768,
        32_767,
    ]


@pytest.mark.parametrize(
    ("submitted", "stored"),
    (
        ((32_768, 32_767), (65_535, 65_533)),
        ((40_000, 20_000, 5_535), (65_535, 32_767, 9_068)),
        ((43_690, 21_845), (65_535, 32_768)),
        ((65_534, 32_767), (65_535, 32_767)),
    ),
)
def test_subtensor_max_upscale_q32_regressions(
    submitted: tuple[int, ...], stored: tuple[int, ...]
) -> None:
    assert writer_runtime._subtensor_max_upscale_to_u16(submitted) == stored
    assert tuple(pallet_storage_weights(submitted)) == stored


def test_subtensor_max_upscale_properties_across_every_u16_maximum() -> None:
    for maximum in range(1, W + 1):
        submitted = tuple(sorted((0, 1, maximum // 2, max(0, maximum - 1), maximum)))
        stored = writer_runtime._subtensor_max_upscale_to_u16(submitted)

        assert stored == tuple(pallet_storage_weights(submitted))
        assert stored[-1] == W
        assert all(0 <= weight <= W for weight in stored)
        assert all(left <= right for left, right in zip(stored, stored[1:]))


def test_cooldown_refuses_before_signing_or_journaling(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.blocks_since = 5

    with pytest.raises(
        DirectValidatorError, match="inside the finalized weight cooldown"
    ):
        submit_before_deadline(instance, planned)

    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


def test_stake_threshold_refuses_before_signing_or_journaling(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.validator_stake = subtensor.stake_threshold - 1

    with pytest.raises(DirectValidatorError, match="below.*stake threshold"):
        submit_before_deadline(instance, planned)

    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


def test_slow_fresh_snapshot_rpc_expires_before_signing_or_journaling(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    now = [100.0]
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])

    def slow_snapshot(_subtensor, _keypair):
        now[0] = 221.0
        return snapshot(ANCHOR_NUMBER + 1)

    instance.snapshot_reader = slow_snapshot
    with pytest.raises(
        DirectValidatorError, match="expired during fresh snapshot RPC"
    ) as raised:
        instance.submit(planned, cycle_deadline_monotonic=220.0)

    assert not isinstance(raised.value, DirectSubmissionAmbiguous)
    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


def test_slow_eligibility_rpc_expires_before_later_preflight_or_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    now = [100.0]
    original = subtensor.weights_rate_limit
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])

    def slow_rate_limit(netuid, *, block):
        value = original(netuid, block=block)
        now[0] = 221.0
        return value

    subtensor.weights_rate_limit = slow_rate_limit
    with pytest.raises(
        DirectValidatorError, match="expired during weight cooldown RPC"
    ):
        instance.submit(planned, cycle_deadline_monotonic=220.0)

    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


def test_call_builder_deadline_is_rechecked_immediately_before_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    now = [100.0]
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])

    def slow_call_builder(_kwargs):
        now[0] = 221.0
        return "direct-call"

    instance.call_builder = slow_call_builder
    with pytest.raises(
        DirectValidatorError, match="expired during immediately before signing"
    ):
        instance.submit(planned, cycle_deadline_monotonic=220.0)

    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()


SIGN_HEAD = ANCHOR_NUMBER + 1
LAST_BROADCAST_HEAD = (
    SIGN_HEAD + MORTAL_PERIOD_BLOCKS - writer_runtime.BROADCAST_ERA_MARGIN_BLOCKS - 1
)
TOO_FEW_BLOCKS = (
    f"leaves fewer than {writer_runtime.BROADCAST_ERA_MARGIN_BLOCKS} blocks"
)


def test_era_guard_keeps_every_write_with_two_inclusion_blocks_left() -> None:
    # A refusal now costs the same single interval as an expiry, so only a
    # write left with one block of its era, or none, is refused.
    era_last_block = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    assert writer_runtime.BROADCAST_ERA_MARGIN_BLOCKS == 2
    assert era_last_block - LAST_BROADCAST_HEAD == 2


@pytest.mark.parametrize(
    ("best_head", "message"),
    (
        (LAST_BROADCAST_HEAD + 1, TOO_FEW_BLOCKS),
        (SIGN_HEAD + MORTAL_PERIOD_BLOCKS, TOO_FEW_BLOCKS),
        (SIGN_HEAD - 1, "behind the signed era anchor"),
    ),
)
def test_nearly_expired_signature_is_dropped_before_journal_or_broadcast(
    tmp_path: Path, monkeypatch, best_head: int, message: str
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.best_number = best_head

    with pytest.raises(DirectValidatorError, match=message) as raised:
        submit_before_deadline(instance, planned)

    assert not isinstance(raised.value, DirectSubmissionAmbiguous)
    assert substrate.sign_calls == 1, "the signature existed only in memory"
    assert substrate.best_reads == 1
    assert substrate.submit_calls == 0
    assert not instance.state_path.exists()
    assert instance.recover() is None

    # Nothing was journaled, so the next cycle signs and writes as usual.
    substrate.best_number = LAST_BROADCAST_HEAD
    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert substrate.sign_calls == 2
    assert substrate.submit_calls == 1


def test_best_head_rpc_failure_refuses_before_journal_or_broadcast(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    original = substrate.get_block_number

    def lose_best_head(block_hash):
        if block_hash is None:
            raise ConnectionError("best head RPC disconnected")
        return original(block_hash)

    monkeypatch.setattr(substrate, "get_block_number", lose_best_head)
    with pytest.raises(
        DirectValidatorError, match="best head is unavailable before broadcast"
    ) as raised:
        submit_before_deadline(instance, planned)

    assert not isinstance(raised.value, DirectSubmissionAmbiguous)
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 0
    assert not instance.state_path.exists()


@pytest.mark.parametrize(
    ("stalled", "stage", "best_reads"),
    (
        ("create_signed_extrinsic", "signing", 0),
        ("get_block_number", "best-head RPC", 1),
    ),
)
def test_post_sign_stall_expires_the_deadline_before_journaling(
    tmp_path: Path, monkeypatch, stalled: str, stage: str, best_reads: int
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    now = [100.0]
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])
    original = getattr(substrate, stalled)

    def stall(*args, **kwargs):
        # Signing makes its own chain calls after the last check before it,
        # and the best-head read follows; either can hang past the deadline.
        value = original(*args, **kwargs)
        now[0] = 221.0
        return value

    monkeypatch.setattr(substrate, stalled, stall)
    with pytest.raises(DirectValidatorError, match=f"expired during {stage}$"):
        instance.submit(planned, cycle_deadline_monotonic=220.0)

    assert substrate.sign_calls == 1
    assert substrate.best_reads == best_reads
    assert substrate.submit_calls == 0
    assert not instance.state_path.exists()


@pytest.mark.parametrize("response_lost", (False, True))
def test_only_the_broadcast_watch_gets_the_library_waits(
    tmp_path: Path, monkeypatch, response_lost: bool
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.raise_without_include = response_lost
    bounded = (
        writer_runtime.DIRECT_RPC_RETRY_TIMEOUT_SECONDS,
        writer_runtime.DIRECT_RPC_MAX_RETRIES,
    )

    if response_lost:
        with pytest.raises(DirectSubmissionAmbiguous):
            submit_before_deadline(instance, planned)
    else:
        assert submit_before_deadline(instance, planned).status == STATUS_CONFIRMED

    assert substrate.waits_seen == {
        "sign": bounded,
        "submit": (
            writer_runtime.BROADCAST_WATCH_RETRY_TIMEOUT_SECONDS,
            writer_runtime.BROADCAST_WATCH_MAX_RETRIES,
        ),
    }
    assert (substrate.retry_timeout, substrate.max_retries) == bounded


def test_rpc_bound_caps_each_call_of_the_pinned_substrate_client() -> None:
    from async_substrate_interface.errors import MaxRetriesExceeded
    from async_substrate_interface.sync_substrate import SubstrateInterface

    client = SubstrateInterface("ws://127.0.0.1:9", _mock=True)
    waits: list[float] = []
    sends: list[str] = []

    class SilentSocket:
        def send(self, payload: str) -> None:
            sends.append(payload)

        def recv(self, *, timeout: float, decode: bool) -> bytes:
            waits.append(timeout)
            raise TimeoutError

    client.connect = lambda init=False: SilentSocket()
    writer_runtime.bound_rpc_waits(SimpleNamespace(substrate=client))

    with pytest.raises(MaxRetriesExceeded):
        client.get_block_number(None)

    assert waits == [writer_runtime.DIRECT_RPC_RETRY_TIMEOUT_SECONDS] * (
        writer_runtime.DIRECT_RPC_MAX_RETRIES
    )
    assert len(sends) == writer_runtime.DIRECT_RPC_MAX_RETRIES
    # Every wait of one silent call plus its reconnect (the websocket open
    # timeout) stays well inside a single mortal era.
    assert sum(waits) + 10.0 < MORTAL_PERIOD_BLOCKS * 12.0 / 2


def test_broadcast_watch_keeps_the_pinned_client_defaults() -> None:
    import inspect

    from async_substrate_interface.sync_substrate import SubstrateInterface

    parameters = inspect.signature(SubstrateInterface.__init__).parameters
    assert parameters["retry_timeout"].default == (
        writer_runtime.BROADCAST_WATCH_RETRY_TIMEOUT_SECONDS
    )
    assert parameters["max_retries"].default == (
        writer_runtime.BROADCAST_WATCH_MAX_RETRIES
    )


def test_broadcast_watch_leaves_a_client_without_wait_knobs_alone() -> None:
    client = SimpleNamespace()

    with writer_runtime._broadcast_watch_waits(client):
        assert vars(client) == {}
    assert vars(client) == {}


@pytest.mark.parametrize(
    "subtensor",
    (
        object(),
        SimpleNamespace(substrate=object()),
        SimpleNamespace(substrate=SimpleNamespace(retry_timeout=60.0)),
        SimpleNamespace(
            substrate=SimpleNamespace(retry_timeout=60.0, max_retries=True)
        ),
    ),
)
def test_rpc_bound_refuses_a_client_it_cannot_bound(subtensor) -> None:
    with pytest.raises(DirectValidatorError, match="to bound"):
        writer_runtime.bound_rpc_waits(subtensor)


def test_inclusion_waits_for_two_later_heads_then_recovers_without_resubmit(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.finalized_number = subtensor.substrate.inclusion_block
    monkeypatch.setattr(writer_runtime, "CONFIRMATION_WAIT_SECONDS", 0.0)

    with pytest.raises(DirectSubmissionAmbiguous, match="two later finalized heads"):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "included_awaiting_confirmation"
    signed = subtensor.substrate.sign_calls
    submitted = subtensor.substrate.submit_calls

    subtensor.substrate.finalized_number = ANCHOR_NUMBER + 4
    receipt = instance.recover()

    assert receipt is not None
    assert receipt.status == STATUS_RECOVERED
    assert receipt.recovered is True
    assert subtensor.substrate.sign_calls == signed
    assert subtensor.substrate.submit_calls == submitted


def test_submit_confirmation_hash_rpc_failure_keeps_recoverable_pending_intent(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    original = substrate.rpc_request
    reads = 0

    def fail_during_confirmation(method: str, params: list[object]):
        nonlocal reads
        if params == [substrate.inclusion_block + 1]:
            reads += 1
            if reads == 2:
                raise ConnectionError("confirmation RPC disconnected")
        return original(method, params)

    monkeypatch.setattr(substrate, "rpc_request", fail_during_confirmation)
    with pytest.raises(
        DirectSubmissionAmbiguous, match="confirmation block 103 hash is unavailable"
    ):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "included_awaiting_confirmation"
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1

    monkeypatch.setattr(substrate, "rpc_request", original)
    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_RECOVERED
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_confirmation_poll_allows_once_style_submission_to_finish(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.finalized_number = subtensor.substrate.inclusion_block
    sleeps: list[float] = []

    def advance(delay: float) -> None:
        sleeps.append(delay)
        subtensor.substrate.finalized_number = ANCHOR_NUMBER + 4

    monkeypatch.setattr(writer_runtime.time, "sleep", advance)

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert sleeps and sleeps[0] <= writer_runtime.CONFIRMATION_POLL_SECONDS


def test_submit_rereads_finalized_history_once_the_head_reaches_inclusion(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.finalized_number = substrate.inclusion_block - 1
    locates = 0
    original_locate = instance._locate

    def counting_locate(pending, **kwargs):
        nonlocal locates
        locates += 1
        return original_locate(pending, **kwargs)

    monkeypatch.setattr(instance, "_locate", counting_locate)
    sleeps: list[float] = []

    def advance_head_on_third_poll(delay: float) -> None:
        sleeps.append(delay)
        if len(sleeps) == 3:
            substrate.finalized_number = ANCHOR_NUMBER + 4

    monkeypatch.setattr(writer_runtime.time, "sleep", advance_head_on_third_poll)

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert receipt.recovered is False
    assert receipt.block_number == substrate.inclusion_block
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1
    assert len(sleeps) == 3
    assert all(delay <= writer_runtime.CONFIRMATION_POLL_SECONDS for delay in sleeps)
    assert locates == 2, "the era is re-read only when the finalized head advances"
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"] is None
    assert state["last_attempt"]["status"] == STATUS_CONFIRMED


def test_submit_stops_rereading_finalized_history_at_the_bound_then_recovers(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.finalized_number = substrate.inclusion_block - 1
    now = [1000.0]
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])
    sleeps: list[float] = []

    def advance_clock(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay

    monkeypatch.setattr(writer_runtime.time, "sleep", advance_clock)
    locates = 0
    original_locate = instance._locate

    def counting_locate(pending, **kwargs):
        nonlocal locates
        locates += 1
        return original_locate(pending, **kwargs)

    monkeypatch.setattr(instance, "_locate", counting_locate)

    with pytest.raises(
        DirectSubmissionAmbiguous, match="without exact finalized history"
    ):
        submit_before_deadline(instance, planned)

    assert sum(sleeps) == pytest.approx(writer_runtime.FINALIZED_HISTORY_WAIT_SECONDS)
    assert locates == 1, "an unchanged finalized head is never re-scanned"
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "ambiguous"

    substrate.finalized_number = ANCHOR_NUMBER + 4
    receipt = instance.recover()

    assert receipt is not None
    assert receipt.status == STATUS_RECOVERED
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_finalized_head_failure_during_the_wait_journals_the_broadcast(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.finalized_number = substrate.inclusion_block - 1
    monkeypatch.setattr(writer_runtime.time, "sleep", lambda _delay: None)
    original = substrate.get_chain_finalised_head
    reads = 0

    def fail_on_the_second_poll() -> str:
        nonlocal reads
        reads += 1
        if reads == 2:
            raise ConnectionError("finalized head RPC disconnected")
        return original()

    monkeypatch.setattr(substrate, "get_chain_finalised_head", fail_on_the_second_poll)

    with pytest.raises(
        DirectSubmissionAmbiguous,
        match="finalized head is unavailable after submission",
    ):
        submit_before_deadline(instance, planned)

    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "ambiguous"
    assert state["pending"]["error"] == "DirectSubmissionAmbiguous"

    monkeypatch.setattr(substrate, "get_chain_finalised_head", original)
    substrate.finalized_number = ANCHOR_NUMBER + 4
    receipt = instance.recover()

    assert receipt is not None
    assert receipt.status == STATUS_RECOVERED
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_two_head_advances_rescan_the_era_each_time(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.finalized_number = substrate.inclusion_block - 2
    locates = 0
    original_locate = instance._locate

    def counting_locate(pending, **kwargs):
        nonlocal locates
        locates += 1
        return original_locate(pending, **kwargs)

    monkeypatch.setattr(instance, "_locate", counting_locate)
    sleeps: list[float] = []

    def advance_head_each_poll(delay: float) -> None:
        sleeps.append(delay)
        if len(sleeps) == 1:
            substrate.finalized_number = substrate.inclusion_block - 1
        elif len(sleeps) == 2:
            substrate.finalized_number = ANCHOR_NUMBER + 4

    monkeypatch.setattr(writer_runtime.time, "sleep", advance_head_each_poll)

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert locates == 3
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_post_broadcast_waits_stay_well_under_the_cycle_interval() -> None:
    combined = (
        writer_runtime.FINALIZED_HISTORY_WAIT_SECONDS
        + writer_runtime.CONFIRMATION_WAIT_SECONDS
    )
    assert combined <= 0.2 * runtime.DEFAULT_INTERVAL_SECONDS


def test_timeout_after_inclusion_recovers_hash_and_row_without_resubmit(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_after_include = True

    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        submit_before_deadline(instance, planned)
    signed = subtensor.substrate.sign_calls
    submitted = subtensor.substrate.submit_calls

    receipt = instance.recover()

    assert receipt is not None
    assert receipt.status == STATUS_RECOVERED
    assert subtensor.substrate.sign_calls == signed
    assert subtensor.substrate.submit_calls == submitted
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"] is None


def test_recovery_confirmation_hash_rpc_failure_stays_recoverable_without_resign(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    original = substrate.rpc_request
    reads = 0

    def fail_during_confirmation(method: str, params: list[object]):
        nonlocal reads
        if params == [substrate.inclusion_block + 1]:
            reads += 1
            if reads == 2:
                raise BrokenPipeError("confirmation RPC pipe closed")
        return original(method, params)

    monkeypatch.setattr(substrate, "rpc_request", fail_during_confirmation)
    with pytest.raises(
        DirectSubmissionAmbiguous, match="confirmation block 103 hash is unavailable"
    ):
        instance.recover()
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "included_awaiting_confirmation"
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1

    monkeypatch.setattr(substrate, "rpc_request", original)
    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_RECOVERED
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_unresolved_timeout_is_fenced_until_the_mortal_era_expires(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_without_include = True

    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    with pytest.raises(DirectSubmissionAmbiguous, match="unresolved"):
        instance.recover()
    with pytest.raises(DirectSubmissionAmbiguous, match="must be recovered"):
        submit_before_deadline(instance, planned)
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1

    subtensor.substrate.finalized_number = ANCHOR_NUMBER + 1 + MORTAL_PERIOD_BLOCKS - 1
    receipt = instance.recover()
    assert receipt is not None
    assert receipt.status == STATUS_EXPIRED


def test_dropped_broadcast_is_fenced_until_recovery_proves_expiry(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.drop_after_broadcast = True

    # The library's watch raises when the node drops bytes that never land,
    # so a real expiry is not closed inside submit(): it stays fenced.
    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "ambiguous"
    assert state["pending"]["error"] == "SubstrateRequestException"
    with pytest.raises(DirectSubmissionAmbiguous, match="unresolved"):
        instance.recover()

    substrate.finalized_number = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_EXPIRED
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_reported_finalization_absent_from_history_is_journaled_expired(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    instance, subtensor, planned = writer(tmp_path / "submit", monkeypatch)
    subtensor.substrate.report_finalized_without_inclusion = True

    with caplog.at_level("WARNING", logger=writer_runtime.__name__):
        receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_EXPIRED
    assert receipt.block_hash is None and receipt.block_number is None
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"] is None
    assert state["last_attempt"]["status"] == STATUS_EXPIRED
    assert instance.recover() is None, "the next cycle has nothing to recover"
    [warning] = [
        record.getMessage()
        for record in caplog.records
        if record.name == writer_runtime.__name__
    ]
    assert REPORTED_HASH in warning and EXTRINSIC_HASH in warning

    # It is exactly the record recovery writes for the same intent a cycle
    # later, after a dropped broadcast had been fenced as ambiguous.
    recovering, recovering_subtensor, _planned = writer(
        tmp_path / "recover", monkeypatch, planned=planned
    )
    recovering_subtensor.substrate.drop_after_broadcast = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(recovering, planned)
    recovering_subtensor.substrate.finalized_number = (
        SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    )

    assert recovering.recover() == receipt
    assert json.loads(recovering.state_path.read_text(encoding="ascii")) == state


@pytest.mark.parametrize("path", ("submit", "recover"))
def test_era_scan_and_confirmation_ignore_a_cached_orphan_sign_head(
    tmp_path: Path, monkeypatch, path: str
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    inclusion = substrate.inclusion_block
    # The best head seen while signing is later reorged out, and the write
    # lands in the canonical block that replaced it at the same height.
    substrate.best_number = inclusion
    substrate.best_orphaned = True
    now = [1000.0]
    monkeypatch.setattr(writer_runtime.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        writer_runtime.time,
        "sleep",
        lambda delay: now.__setitem__(0, now[0] + delay),
    )

    if path == "submit":
        receipt = instance.submit(planned, cycle_deadline_monotonic=now[0] + 600.0)
        assert receipt.status == STATUS_CONFIRMED
    else:
        substrate.raise_after_include = True
        with pytest.raises(DirectSubmissionAmbiguous):
            instance.submit(planned, cycle_deadline_monotonic=now[0] + 600.0)
        substrate.finalized_number = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
        # Any by-number read of that height puts the orphan in bittensor's
        # memo as well as the client's map.
        assert subtensor.get_block_hash(inclusion) == ORPHAN_HASH
        receipt = instance.recover()
        assert receipt is not None and receipt.status == STATUS_RECOVERED

    assert substrate.orphans == {inclusion: ORPHAN_HASH}
    assert receipt.block_number == inclusion
    assert receipt.block_hash == INCLUSION_HASH
    assert substrate.submit_calls == 1
    # The confirmation's metagraph names its block by number, yet it read the
    # canonical block, never the orphan whose state the node discarded.
    assert (inclusion, INCLUSION_HASH) in subtensor.metagraph_reads
    assert ORPHAN_HASH not in {read for _block, read in subtensor.metagraph_reads}
    # The correction sticks for every later by-number read of that height,
    # even once the client's map has evicted it and asks its memo again.
    assert subtensor.get_block_hash(inclusion) == INCLUSION_HASH
    substrate.runtime_cache.blocks.cache.pop(inclusion)
    assert substrate.get_block_hash(inclusion) == INCLUSION_HASH


def test_uncorrected_cached_orphan_is_corrected_by_the_next_recovery(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    inclusion = substrate.inclusion_block
    substrate.best_number = inclusion
    substrate.best_orphaned = True
    substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    substrate.finalized_number = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    assert subtensor.get_block_hash(inclusion) == ORPHAN_HASH

    # For one cycle the client's map drops the correction of that height.
    add_item = substrate.runtime_cache.add_item
    dropped: list[dict[str, object]] = []

    def drop_the_correction(**kwargs: object) -> None:
        if kwargs == {"block": inclusion, "block_hash": INCLUSION_HASH}:
            dropped.append(kwargs)
            return
        add_item(**kwargs)

    monkeypatch.setattr(substrate.runtime_cache, "add_item", drop_the_correction)
    with pytest.raises(DirectSubmissionAmbiguous, match="not canonical"):
        instance.recover()

    assert dropped == [{"block": inclusion, "block_hash": INCLUSION_HASH}]
    assert inclusion not in {block for block, _read in subtensor.metagraph_reads}
    pending = json.loads(instance.state_path.read_text(encoding="ascii"))["pending"]
    assert pending is not None

    # The next cycle recovers the same pending write, corrects the cache, and
    # resolves it: the stale entry cannot keep it ambiguous.
    monkeypatch.setattr(substrate.runtime_cache, "add_item", add_item)
    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_RECOVERED
    assert receipt.attempt_id == pending["attempt_id"]
    assert receipt.block_hash == INCLUSION_HASH
    assert (inclusion, INCLUSION_HASH) in subtensor.metagraph_reads
    assert ORPHAN_HASH not in {read for _block, read in subtensor.metagraph_reads}
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1


def test_recovery_refuses_a_mutated_exact_signed_intent(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_without_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    state["pending"]["intent"]["nonce"] += 1
    instance.state_path.write_text(json.dumps(state), encoding="ascii")

    with pytest.raises(DirectSubmissionContradiction, match="attempt id is wrong"):
        instance.recover()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong_call", "different chain call"),
        ("wrong_storage", "stored mechanism row differs"),
        ("inclusion_mapping", "weighted miner mapping changed"),
    ],
)
def test_recovery_stops_on_finalized_contradiction(
    tmp_path: Path, monkeypatch, mutation: str, message: str
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    if mutation == "wrong_call":
        subtensor.substrate.wrong_call = True
    elif mutation == "wrong_storage":
        subtensor.substrate.wrong_storage = True
    else:
        subtensor.remap_after = ANCHOR_NUMBER + 2

    with pytest.raises(DirectSubmissionContradiction, match=message):
        instance.recover()
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1


@pytest.mark.parametrize("remap_after", (ANCHOR_NUMBER + 3, ANCHOR_NUMBER + 4))
def test_later_miner_remap_keeps_exact_stored_row_confirmed(
    tmp_path: Path, monkeypatch, remap_after: int
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.remap_after = remap_after

    receipt = submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert [row[0] for row in receipt.confirmation_heads] == [102, 103, 104]
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1


def test_writer_refuses_remapped_miner_before_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    changed = snapshot(
        ANCHOR_NUMBER + 1,
        miners=(replace(MINER_ONE_AXON, hotkey="5Replacement"),),
    )
    instance.snapshot_reader = lambda _subtensor, _keypair: changed

    with pytest.raises(DirectValidatorError, match="serving miner set changed"):
        submit_before_deadline(instance, planned)
    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0


def test_writer_refuses_a_new_serving_miner_before_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    instance.snapshot_reader = lambda _subtensor, _keypair: snapshot(
        ANCHOR_NUMBER + 1, miners=(MINER_ONE_AXON, MINER_TWO_AXON)
    )

    with pytest.raises(DirectValidatorError, match="serving miner set changed"):
        submit_before_deadline(instance, planned)
    assert subtensor.substrate.sign_calls == 0


def test_writer_refuses_truthy_non_boolean_permit_before_signing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.truthy_permit_at = ANCHOR_NUMBER + 1

    with pytest.raises(DirectValidatorError, match="explicit boolean"):
        submit_before_deadline(instance, planned)
    assert subtensor.substrate.sign_calls == 0


def test_confirmation_refuses_truthy_non_boolean_permit(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    subtensor.truthy_permit_at = ANCHOR_NUMBER + 3

    with pytest.raises(DirectSubmissionAmbiguous, match="confirmation block"):
        instance.recover()


def test_direct_validator_qvl_pin_rejects_the_retired_binary(monkeypatch) -> None:
    old_digest = qvl_runtime.LAUNCH_QVL_DIGEST
    assert qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST == (
        "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148"
    )
    assert old_digest != qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
    monkeypatch.setattr(
        qvl_runtime,
        "SubprocessQuoteVerifier",
        lambda _command: SimpleNamespace(digest=old_digest),
    )

    with pytest.raises(QuoteVerifyError, match="direct-validator pin"):
        qvl_runtime.load_direct_validator_verifier("/retired/qvl")


def test_cycle_recovers_before_collecting_or_signing(monkeypatch) -> None:
    recovered = SimpleNamespace(
        status=STATUS_RECOVERED,
        as_document=lambda: {"status": STATUS_RECOVERED},
    )
    writer_object = SimpleNamespace(recover=lambda: recovered)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: pytest.fail("recovery reached collection"),
    )

    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=object(),
        writer=writer_object,
        report_recovery=lambda _event: pytest.fail("a confirmed recovery fell through"),
    )

    assert result["status"] == STATUS_RECOVERED


@pytest.mark.parametrize("fresh_anchor", ("newer", "expired_attempt"))
def test_cycle_recovers_an_expired_intent_then_signs_a_fresh_write(
    tmp_path: Path, monkeypatch, fresh_anchor: str
) -> None:
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    substrate.drop_after_broadcast = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)

    # One interval later the dropped intent's era has passed. The fresh cycle
    # reads a newer anchor and signs at a newer finalized head; the account's
    # next index has moved on too, so a nonce copied from the journal would
    # be stale.
    era_end = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
    substrate.drop_after_broadcast = False
    substrate.finalized_number = era_end + 2
    substrate.sign_head = substrate.best_number = era_end + 2
    substrate.nonce = 5
    substrate.extrinsic_hash = SECOND_EXTRINSIC_HASH
    substrate.inclusion_block = era_end + 3
    anchor = (
        replace(snapshot(era_end + 1), block_hash=substrate.block_hash(era_end + 1))
        if fresh_anchor == "newer"
        else snapshot(ANCHOR_NUMBER)
    )
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: anchor
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: round_result(machine_row("fresh")),
    )

    def finalize_after_broadcast(_delay: float) -> None:
        substrate.finalized_number = substrate.inclusion_block + 2

    monkeypatch.setattr(writer_runtime.time, "sleep", finalize_after_broadcast)
    reports: list[dict[str, object]] = []

    def cycle() -> dict[str, object]:
        return run_direct_cycle(
            subtensor=subtensor,
            keypair=FakeKeypair(),
            verifier_adapter=SimpleNamespace(
                qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
            ),
            writer=instance,
            report_recovery=reports.append,
        )

    if fresh_anchor == "newer":
        result = cycle()
    else:
        with pytest.raises(DirectValidatorError, match="already attempted"):
            cycle()

    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert reports == [
        {
            "status": STATUS_EXPIRED,
            "recovery": {
                "status": STATUS_EXPIRED,
                "attempt_id": reports[0]["recovery"]["attempt_id"],
                "extrinsic_hash": EXTRINSIC_HASH,
                "block_hash": None,
                "block_number": None,
                "recovered": True,
                "confirmation_heads": [],
            },
        }
    ]
    # The dropped bytes were never signed again nor sent again.
    assert substrate.broadcast.count(EXTRINSIC_HASH) == 1
    if fresh_anchor == "expired_attempt":
        # The expired attempt still fences its own anchor: nothing new signed.
        assert substrate.signed == [(SIGN_HEAD, 4)]
        assert state["pending"] is None
        assert state["last_attempt"]["status"] == STATUS_EXPIRED
        return

    assert result["status"] == STATUS_CONFIRMED
    assert result["receipt"]["extrinsic_hash"] == SECOND_EXTRINSIC_HASH
    assert result["receipt"]["block_number"] == substrate.inclusion_block
    assert substrate.signed == [(SIGN_HEAD, 4), (era_end + 2, 5)]
    assert subtensor.eligibility_blocks == [SIGN_HEAD, era_end + 2]
    assert substrate.broadcast == [EXTRINSIC_HASH, SECOND_EXTRINSIC_HASH]
    assert state["pending"] is None
    assert state["last_attempt"]["status"] == STATUS_CONFIRMED
    assert state["last_attempt"]["identity"]["anchor"]["block_number"] == (era_end + 1)
    assert state["last_attempt"]["intent"]["era_reference_block"] == era_end + 2
    assert state["last_attempt"]["intent"]["nonce"] == 5


def test_cycle_requires_a_reporter_for_an_expired_recovery() -> None:
    import inspect

    for function in (run_direct_cycle, runtime._run_direct_cycle_unlocked):
        parameter = inspect.signature(function).parameters["report_recovery"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty


def test_cycle_reports_an_expired_submission_without_telemetry(
    tmp_path: Path, monkeypatch
) -> None:
    expired = DirectSubmissionReceipt(
        status=STATUS_EXPIRED,
        attempt_id="sha256:" + "1" * 64,
        extrinsic_hash=EXTRINSIC_HASH,
        block_hash=None,
        block_number=None,
        recovered=True,
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: snapshot()
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: round_result(machine_row("1")),
    )
    monkeypatch.setattr(
        runtime,
        "build_telemetry_candidate",
        lambda **_kwargs: pytest.fail("telemetry built for an unwritten plan"),
    )

    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(
            recover=lambda: None, submit=lambda _plan, **_kwargs: expired
        ),
        telemetry_sink=spool,
        report_recovery=no_expired_recovery,
    )

    assert result["status"] == STATUS_EXPIRED
    assert result["receipt"] == expired.as_document()
    assert "telemetry" not in result
    assert not spool.path.exists()
    assert not runtime.PendingTelemetryStore(spool).path.exists()


def test_cycle_scores_every_discovered_serving_miner(monkeypatch) -> None:
    miners = (MINER_ONE_AXON, MINER_TWO_AXON)
    observed = snapshot(miners=miners)
    scored = round_result(
        machine_row("1"),
        machine_row("2", uid=20, hotkey=MINER_TWO),
        miners=miners,
    )
    submitted: list[DirectWeightPlan] = []
    seen_axons: list[tuple[ServingAxon, ...]] = []
    seen_deadlines: list[float] = []
    writer_deadlines: list[float] = []
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED,
        as_document=lambda: {"status": STATUS_CONFIRMED},
    )

    def submit(value, *, cycle_deadline_monotonic):
        submitted.append(value)
        writer_deadlines.append(float(cycle_deadline_monotonic))
        return receipt

    writer_object = SimpleNamespace(recover=lambda: None, submit=submit)
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: observed
    )

    def score(**kwargs):
        seen_axons.append(tuple(kwargs["axons"]))
        seen_deadlines.append(float(kwargs["cycle_deadline_monotonic"]))
        return scored

    monkeypatch.setattr(runtime, "score_multicompute_round", score)

    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=writer_object,
        report_recovery=no_expired_recovery,
    )

    assert seen_axons == [miners]
    assert seen_deadlines[0] > runtime.time.monotonic()
    assert writer_deadlines == seen_deadlines
    assert result["status"] == STATUS_CONFIRMED
    assert result["raw_scores"] == [[19, 1], [20, 1]]
    assert result["wire_uids"] == [19, 20]
    assert result["wire_weights"] == [32768, 32767]
    assert set(result["evidence_summary"]) == {"phase_timings_ms", "exclusions"}
    assert submitted[0].raw_scores == ((19, 1), (20, 1))


def test_cycle_lock_covers_recovery_collection_and_submission(monkeypatch) -> None:
    held = [False]
    observed = snapshot()
    scored = round_result(machine_row("1"))
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED,
        as_document=lambda: {"status": STATUS_CONFIRMED},
    )

    @contextmanager
    def cycle_locked():
        assert held[0] is False
        held[0] = True
        try:
            yield
        finally:
            held[0] = False

    def recover():
        assert held[0] is True
        return None

    def submit(_plan, **_kwargs):
        assert held[0] is True
        return receipt

    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: observed if held[0] else pytest.fail("collection outside lock"),
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: scored if held[0] else pytest.fail("scoring outside lock"),
    )

    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(
            cycle_locked=cycle_locked,
            recover=recover,
            submit=submit,
        ),
        report_recovery=no_expired_recovery,
    )

    assert result["status"] == STATUS_CONFIRMED
    assert held[0] is False


def test_telemetry_failure_never_prevents_a_finalized_weight_write(
    monkeypatch,
    tmp_path,
) -> None:
    observed = snapshot(miners=(MINER_ONE_AXON,))
    scored = round_result(machine_row("1"), miners=(MINER_ONE_AXON,))
    submitted: list[DirectWeightPlan] = []
    order: list[str] = []
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED,
        as_document=lambda: {"status": STATUS_CONFIRMED},
    )
    writer_object = SimpleNamespace(
        recover=lambda: None,
        submit=lambda plan, **_kwargs: (
            order.append("submit"),
            submitted.append(plan),
            receipt,
        )[-1],
    )
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: observed
    )
    monkeypatch.setattr(runtime, "score_multicompute_round", lambda **_kwargs: scored)
    monkeypatch.setattr(
        runtime,
        "build_telemetry_candidate",
        lambda **_kwargs: (
            order.append("telemetry"),
            (_ for _ in ()).throw(RuntimeError("spool unavailable")),
        )[-1],
    )

    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=writer_object,
        telemetry_sink=TelemetrySpool(tmp_path / "telemetry" / "events.jsonl"),
        report_recovery=no_expired_recovery,
    )

    assert submitted and submitted[0].raw_scores == ((19, 1),)
    assert order == ["submit", "telemetry"]
    assert result["status"] == STATUS_CONFIRMED
    assert result["telemetry"] == {"status": "FAILED"}


def test_existing_pending_telemetry_waits_for_fresh_finalized_write(
    monkeypatch,
    tmp_path,
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    prior_observed = replace(
        snapshot(miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    current_observed = replace(
        snapshot(ANCHOR_NUMBER + 1, miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    prior_row = machine_row("prior")
    prior_row["tee_kind"] = "tdx"
    prior_row["phase_timings_ms"] = {"binding": 1}
    current_row = machine_row("current")
    current_row["tee_kind"] = "tdx"
    current_row["phase_timings_ms"] = {"binding": 1}
    prior_result = round_result(prior_row, miners=(MINER_ONE_AXON,))
    current_result = round_result(current_row, miners=(MINER_ONE_AXON,))
    prior_plan = build_direct_plan(prior_observed, prior_result)
    prior_receipt = DirectSubmissionReceipt(
        status=STATUS_CONFIRMED,
        attempt_id="sha256:" + "1" * 64,
        extrinsic_hash="0x" + "2" * 64,
        block_hash="0x" + "3" * 64,
        block_number=ANCHOR_NUMBER,
        recovered=False,
    )
    current_receipt = DirectSubmissionReceipt(
        status=STATUS_CONFIRMED,
        attempt_id="sha256:" + "4" * 64,
        extrinsic_hash="0x" + "5" * 64,
        block_hash="0x" + "6" * 64,
        block_number=ANCHOR_NUMBER + 1,
        recovered=False,
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    pending = runtime.PendingTelemetryStore(spool)
    pending.prepare(
        runtime.build_telemetry_candidate(
            result_rows=prior_result.rows,
            plan=prior_plan,
        ),
        prior_plan,
        prior_receipt,
    )
    assert pending.path.exists()

    order: list[str] = []
    original_prepare = runtime.PendingTelemetryStore.prepare
    original_finalize = runtime.PendingTelemetryStore.finalize
    original_append = TelemetrySpool.append

    def tracked_prepare(self, *args, **kwargs):
        order.append("pending-prepare")
        return original_prepare(self, *args, **kwargs)

    def tracked_finalize(self, *args, **kwargs):
        order.append("pending-finalize")
        return original_finalize(self, *args, **kwargs)

    def tracked_append(self, *args, **kwargs):
        order.append("spool-append")
        return original_append(self, *args, **kwargs)

    monkeypatch.setattr(runtime.PendingTelemetryStore, "prepare", tracked_prepare)
    monkeypatch.setattr(runtime.PendingTelemetryStore, "finalize", tracked_finalize)
    monkeypatch.setattr(TelemetrySpool, "append", tracked_append)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: current_observed,
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: current_result,
    )

    result = run_direct_cycle(
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(
            recover=lambda: None,
            submit=lambda _plan, **_kwargs: (
                order.append("submit"),
                current_receipt,
            )[-1],
        ),
        telemetry_sink=spool,
        report_recovery=no_expired_recovery,
    )

    assert order == [
        "submit",
        "pending-finalize",
        "spool-append",
        "pending-prepare",
        "pending-finalize",
        "spool-append",
    ]
    events = [json.loads(line) for line in spool.path.read_text().splitlines()]
    assert [event["submission"]["block_number"] for event in events] == [
        ANCHOR_NUMBER,
        ANCHOR_NUMBER + 1,
    ]
    assert result["status"] == STATUS_CONFIRMED
    assert result["telemetry"]["status"] == "SPOOLED"
    assert result["reconciled_telemetry_event_id"] == events[0]["event_id"]


def test_ambiguous_write_persists_candidate_only_after_submit_for_recovery(
    monkeypatch,
    tmp_path,
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    observed = replace(
        snapshot(miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    row = machine_row("ambiguous")
    row["tee_kind"] = "tdx"
    row["phase_timings_ms"] = {"binding": 1}
    scored = round_result(row, miners=(MINER_ONE_AXON,))
    ambiguous_plan = build_direct_plan(observed, scored)
    spool = TelemetrySpool(
        tmp_path / "telemetry" / "events.jsonl",
        reader_gid=os.getegid(),
    )
    writer_state = tmp_path / "direct-writer" / "state.json"
    writer_state.parent.mkdir(mode=0o700)
    writer_state.write_bytes(
        canonical_document_bytes(
            {
                "schema": STATE_SCHEMA,
                "pending": {"identity": ambiguous_plan.identity()},
                "last_attempt": None,
            }
        )
    )
    writer_state.chmod(0o600)
    order: list[str] = []
    original_prepare = runtime.PendingTelemetryStore.prepare

    def tracked_prepare(self, *args, **kwargs):
        order.append("pending-prepare")
        return original_prepare(self, *args, **kwargs)

    monkeypatch.setattr(runtime.PendingTelemetryStore, "prepare", tracked_prepare)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: observed,
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: scored,
    )

    def ambiguous_submit(_plan, **_kwargs):
        order.append("submit")
        raise DirectSubmissionAmbiguous("broadcast result is unresolved")

    with pytest.raises(DirectSubmissionAmbiguous, match="unresolved"):
        run_direct_cycle(
            subtensor=object(),
            keypair=keypair,
            verifier_adapter=SimpleNamespace(
                qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
            ),
            writer=SimpleNamespace(
                state_path=writer_state,
                recover=lambda: None,
                submit=ambiguous_submit,
            ),
            telemetry_sink=spool,
            report_recovery=no_expired_recovery,
        )

    pending_path = spool.path.with_name("pending.json")
    assert order == ["submit", "pending-prepare"]
    assert json.loads(pending_path.read_text())["receipt"] is None
    assert not spool.path.exists()

    recovered_receipt = DirectSubmissionReceipt(
        status=STATUS_RECOVERED,
        attempt_id="sha256:" + "7" * 64,
        extrinsic_hash="0x" + "8" * 64,
        block_hash="0x" + "9" * 64,
        block_number=ANCHOR_NUMBER,
        recovered=True,
    )

    def recover():
        writer_state.write_bytes(
            canonical_document_bytes(
                {
                    "schema": STATE_SCHEMA,
                    "pending": None,
                    "last_attempt": {
                        "identity": ambiguous_plan.identity(),
                        "receipt": recovered_receipt.as_document(),
                    },
                }
            )
        )
        writer_state.chmod(0o600)
        return recovered_receipt

    _stub_cli_runtime(monkeypatch, [])
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=keypair),
    )
    startup_writer = SimpleNamespace(state_path=writer_state, recover=recover)
    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: startup_writer,
    )
    monkeypatch.setattr(
        runtime.grp,
        "getgrnam",
        lambda group: (
            SimpleNamespace(gr_gid=os.getegid())
            if group == "cathedral-telemetry"
            else pytest.fail("unexpected telemetry group")
        ),
    )
    original_append = TelemetrySpool.append
    append_attempts = 0

    def fail_first_append(self, event):
        nonlocal append_attempts
        append_attempts += 1
        if append_attempts == 1:
            raise runtime.TelemetryError("transient startup spool failure")
        return original_append(self, event)

    monkeypatch.setattr(TelemetrySpool, "append", fail_first_append)
    cli_args = [
        "--qvl",
        "/reviewed/qvl",
        "--snp-policy",
        "/reviewed/snp-policy.json",
        "--snpguest",
        "/reviewed/snpguest",
        f"--expected-hotkey={keypair.ss58_address}",
        f"--telemetry-spool={spool.path.resolve()}",
        "--telemetry-reader-group=cathedral-telemetry",
        "--once",
        "--confirm-direct-write",
    ]

    assert runtime.main(cli_args) == 0
    assert append_attempts == 1
    assert pending_path.exists()
    assert not spool.path.exists()
    assert json.loads(pending_path.read_text())["receipt"] == (
        recovered_receipt.as_document()
    )

    current_observed = replace(
        snapshot(ANCHOR_NUMBER + 1, miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    current_row = machine_row("after-restart")
    current_row["tee_kind"] = "tdx"
    current_row["phase_timings_ms"] = {"binding": 1}
    current_result = round_result(current_row, miners=(MINER_ONE_AXON,))
    current_receipt = DirectSubmissionReceipt(
        status=STATUS_CONFIRMED,
        attempt_id="sha256:" + "a" * 64,
        extrinsic_hash="0x" + "b" * 64,
        block_hash="0x" + "c" * 64,
        block_number=ANCHOR_NUMBER + 1,
        recovered=False,
    )
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: current_observed,
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: current_result,
    )

    current = run_direct_cycle(
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(
            recover=lambda: None,
            submit=lambda _plan, **_kwargs: current_receipt,
        ),
        telemetry_sink=spool,
        report_recovery=no_expired_recovery,
    )

    events = [json.loads(line) for line in spool.path.read_text().splitlines()]
    assert current["status"] == STATUS_CONFIRMED
    assert append_attempts == 3
    assert [event["submission"]["block_number"] for event in events] == [
        ANCHOR_NUMBER,
        ANCHOR_NUMBER + 1,
    ]
    assert events[0]["submission"] == {
        "block_hash": recovered_receipt.block_hash,
        "block_number": recovered_receipt.block_number,
        "recovered": True,
        "status": STATUS_RECOVERED,
    }
    assert not pending_path.exists()


def test_prior_pending_ambiguity_never_overwrites_another_telemetry_plan(
    monkeypatch,
    tmp_path,
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    prior_observed = replace(
        snapshot(miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    current_observed = replace(
        snapshot(ANCHOR_NUMBER + 1, miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    prior_row = machine_row("prior-pending")
    current_row = machine_row("new-unsubmitted")
    prior_result = round_result(prior_row, miners=(MINER_ONE_AXON,))
    current_result = round_result(current_row, miners=(MINER_ONE_AXON,))
    prior_plan = build_direct_plan(prior_observed, prior_result)
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    pending = runtime.PendingTelemetryStore(spool)
    pending.prepare(
        runtime.build_telemetry_candidate(
            result_rows=prior_result.rows,
            plan=prior_plan,
        ),
        prior_plan,
        None,
    )
    pending_before = pending.path.read_bytes()
    writer_state = tmp_path / "direct-writer" / "state.json"
    writer_state.parent.mkdir(mode=0o700)
    writer_state.write_bytes(
        canonical_document_bytes(
            {
                "schema": STATE_SCHEMA,
                "pending": {"identity": prior_plan.identity()},
                "last_attempt": None,
            }
        )
    )
    writer_state.chmod(0o600)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: current_observed,
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: current_result,
    )

    with pytest.raises(DirectSubmissionAmbiguous, match="prior intent"):
        run_direct_cycle(
            subtensor=object(),
            keypair=keypair,
            verifier_adapter=SimpleNamespace(
                qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
            ),
            writer=SimpleNamespace(
                state_path=writer_state,
                recover=lambda: None,
                submit=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    DirectSubmissionAmbiguous("prior intent is still pending")
                ),
            ),
            telemetry_sink=spool,
            report_recovery=no_expired_recovery,
        )

    assert pending.path.read_bytes() == pending_before
    assert not spool.path.exists()


def test_recovered_receipt_refuses_a_different_pending_telemetry_plan(
    tmp_path,
) -> None:
    keypair = Keypair.create_from_uri("//Alice")
    pending_observed = replace(
        snapshot(miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    journal_observed = replace(
        snapshot(ANCHOR_NUMBER + 1, miners=(MINER_ONE_AXON,)),
        validator_hotkey=keypair.ss58_address,
    )
    row = machine_row("mismatch")
    scored = round_result(row, miners=(MINER_ONE_AXON,))
    pending_plan = build_direct_plan(pending_observed, scored)
    journal_plan = build_direct_plan(journal_observed, scored)
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    pending = runtime.PendingTelemetryStore(spool)
    pending.prepare(
        runtime.build_telemetry_candidate(
            result_rows=scored.rows,
            plan=pending_plan,
        ),
        pending_plan,
        None,
    )
    recovered_receipt = DirectSubmissionReceipt(
        status=STATUS_RECOVERED,
        attempt_id="sha256:" + "a" * 64,
        extrinsic_hash="0x" + "b" * 64,
        block_hash="0x" + "c" * 64,
        block_number=ANCHOR_NUMBER + 1,
        recovered=True,
    )
    writer_state = tmp_path / "direct-writer" / "state.json"
    writer_state.parent.mkdir(mode=0o700)
    writer_state.write_bytes(
        canonical_document_bytes(
            {
                "schema": STATE_SCHEMA,
                "pending": None,
                "last_attempt": {
                    "identity": journal_plan.identity(),
                    "receipt": recovered_receipt.as_document(),
                },
            }
        )
    )
    writer_state.chmod(0o600)

    result = run_direct_cycle(
        subtensor=object(),
        keypair=keypair,
        verifier_adapter=object(),
        writer=SimpleNamespace(
            state_path=writer_state,
            recover=lambda: recovered_receipt,
        ),
        telemetry_sink=spool,
        report_recovery=no_expired_recovery,
    )

    assert result["status"] == STATUS_RECOVERED
    assert result["telemetry"] == {"status": "NO_FINALIZED_EVENT"}
    assert pending.path.exists()
    assert not spool.path.exists()


def test_cycle_refuses_an_adapter_with_another_qvl_pin(monkeypatch) -> None:
    writer_object = SimpleNamespace(recover=lambda: None)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: pytest.fail("wrong QVL reached collection"),
    )

    with pytest.raises(DirectValidatorError, match="pinned QVL digest"):
        run_direct_cycle(
            subtensor=object(),
            keypair=FakeKeypair(),
            verifier_adapter=SimpleNamespace(qvl_digest="0" * 64),
            writer=writer_object,
            report_recovery=no_expired_recovery,
        )


def test_snapshot_and_scoring_share_one_end_to_end_presign_deadline(
    monkeypatch,
) -> None:
    submitted: list[DirectWeightPlan] = []
    writer_object = SimpleNamespace(
        recover=lambda: None,
        submit=lambda value, **_kwargs: submitted.append(value),
    )
    now = [100.0]
    monkeypatch.setattr(runtime.time, "monotonic", lambda: now[0])

    def read_snapshot(*_args):
        now[0] = 140.0
        return snapshot()

    def slow_score(**kwargs):
        assert kwargs["cycle_deadline_monotonic"] == 220.0
        now[0] = 221.0
        return round_result(machine_row("1"))

    monkeypatch.setattr(runtime, "finalized_serving_miners_snapshot", read_snapshot)
    monkeypatch.setattr(runtime, "score_multicompute_round", slow_score)
    with pytest.raises(DirectValidatorError, match="expired before submission"):
        run_direct_cycle(
            subtensor=object(),
            keypair=FakeKeypair(),
            verifier_adapter=SimpleNamespace(
                qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
            ),
            writer=writer_object,
            report_recovery=no_expired_recovery,
        )
    assert submitted == []


def test_evidence_elapsed_excludes_writer_chain_wait(monkeypatch) -> None:
    now = [100.0]
    observed = snapshot()
    scored = round_result(machine_row("1"))
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED,
        as_document=lambda: {"status": STATUS_CONFIRMED},
    )
    deadlines: list[float] = []
    monkeypatch.setattr(runtime.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: observed
    )

    def score(**_kwargs):
        now[0] = 110.0
        return scored

    def submit(_plan, *, cycle_deadline_monotonic):
        deadlines.append(float(cycle_deadline_monotonic))
        now[0] = 500.0
        return receipt

    monkeypatch.setattr(runtime, "score_multicompute_round", score)
    result = run_direct_cycle(
        subtensor=object(),
        keypair=FakeKeypair(),
        verifier_adapter=SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
        writer=SimpleNamespace(recover=lambda: None, submit=submit),
        report_recovery=no_expired_recovery,
    )

    assert deadlines == [220.0]
    assert result["evidence_cycle_elapsed_ms"] == 10_000


def test_cli_refuses_before_wallet_or_chain_access(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: pytest.fail("wallet opened without confirmation"),
    )

    with pytest.raises(SystemExit, match="confirm-direct-write"):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
            ]
        )


def test_cli_refuses_non_finney_and_bad_interval_before_wallet_access(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: pytest.fail("wallet opened before argument gates"),
    )

    with pytest.raises(SystemExit, match="pinned to the Finney"):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                "--network",
                "local",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )
    for interval in ("0", "nan", "inf", "-inf"):
        with pytest.raises(SystemExit, match=r"interval must be positive$"):
            runtime.main(
                [
                    "--qvl",
                    "/reviewed/qvl",
                    "--snp-policy",
                    "/reviewed/snp-policy.json",
                    "--snpguest",
                    "/reviewed/snpguest",
                    f"--interval-seconds={interval}",
                    f"--expected-hotkey={VALIDATOR}",
                    "--confirm-direct-write",
                ]
            )


def test_cli_checks_direct_qvl_pin_before_wallet_or_chain_access(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: pytest.fail("wallet opened before QVL pin"),
    )
    monkeypatch.setattr(
        runtime,
        "load_direct_validator_verifier",
        lambda _path: (_ for _ in ()).throw(QuoteVerifyError("wrong QVL pin")),
    )

    with pytest.raises(QuoteVerifyError, match="wrong QVL pin"):
        runtime.main(
            [
                "--qvl",
                "/retired/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )


def test_systemd_readiness_datagram_is_exact(tmp_path: Path, monkeypatch) -> None:
    notify_path = Path("/tmp") / f"cv-notify-{id(tmp_path):x}.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(str(notify_path))
            server.settimeout(1.0)
            monkeypatch.setenv("NOTIFY_SOCKET", str(notify_path))

            runtime._notify_ready()

            assert server.recv(512) == (
                b"READY=1\nSTATUS=initialized; waiting for the next direct cycle"
            )
    finally:
        notify_path.unlink(missing_ok=True)


def _stub_cli_runtime(monkeypatch, events):
    monkeypatch.setattr(
        runtime,
        "load_direct_validator_verifier",
        lambda _path: SimpleNamespace(digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST),
    )
    monkeypatch.setattr(
        runtime,
        "ComputeAdapter",
        lambda *_args, **_kwargs: SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
    )
    monkeypatch.setattr(runtime, "load_snp_policy", lambda _path: object())
    monkeypatch.setattr(
        runtime,
        "SnpProductionVerifier",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=FakeKeypair()),
    )
    monkeypatch.setattr(
        runtime,
        "make_subtensor",
        lambda *_args, **_kwargs: SimpleNamespace(
            substrate=SimpleNamespace(retry_timeout=60.0, max_retries=5)
        ),
    )
    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: SimpleNamespace(recover=lambda: None),
    )

    def cycle(**_kwargs):
        value = events.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(runtime, "run_direct_cycle", cycle)


def test_cli_refuses_mismatched_hotkey_before_chain_access(monkeypatch) -> None:
    _stub_cli_runtime(monkeypatch, [])
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(
            hotkey=SimpleNamespace(
                ss58_address="5DifferentValidator",
                sign=lambda _body: b"signature",
            )
        ),
    )
    monkeypatch.setattr(
        runtime,
        "make_subtensor",
        lambda *_args, **_kwargs: pytest.fail("chain accessed after identity mismatch"),
    )

    with pytest.raises(SystemExit, match="does not match --expected-hotkey"):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )


@pytest.mark.parametrize(
    "expected_hotkey",
    ("", "../other", "5Validator/other", "5 validator", "\N{SNOWMAN}", "x" * 65),
)
def test_cli_rejects_unsafe_expected_hotkey_before_wallet_access(
    monkeypatch, expected_hotkey: str
) -> None:
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: pytest.fail("wallet opened for unsafe identity"),
    )

    with pytest.raises(SystemExit, match="path-safe public SS58 address"):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={expected_hotkey}",
                "--confirm-direct-write",
            ]
        )


def test_cli_recovers_journal_before_reporting_ready(monkeypatch) -> None:
    order: list[str] = []
    events = [{"status": STATUS_CONFIRMED}]
    _stub_cli_runtime(monkeypatch, events)
    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: SimpleNamespace(
            recover=lambda: order.append("recover") or None
        ),
    )
    monkeypatch.setattr(runtime, "_notify_ready", lambda: order.append("ready"))

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 0
    )
    assert order == ["recover", "ready"]


def test_cli_bounds_rpc_waits_on_the_constructed_client_before_recovery(
    monkeypatch,
) -> None:
    _stub_cli_runtime(monkeypatch, [{"status": STATUS_CONFIRMED}])
    client = SimpleNamespace(
        substrate=SimpleNamespace(retry_timeout=60.0, max_retries=5)
    )
    monkeypatch.setattr(runtime, "make_subtensor", lambda *_args, **_kwargs: client)
    seen: list[tuple[float, int]] = []

    def build_writer(*, subtensor, keypair):
        assert subtensor is client
        return SimpleNamespace(
            recover=lambda: seen.append(
                (subtensor.substrate.retry_timeout, subtensor.substrate.max_retries)
            )
        )

    monkeypatch.setattr(writer_runtime, "DirectWeightWriter", build_writer)

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 0
    )
    assert seen == [
        (
            writer_runtime.DIRECT_RPC_RETRY_TIMEOUT_SECONDS,
            writer_runtime.DIRECT_RPC_MAX_RETRIES,
        )
    ]


def test_cli_refuses_a_chain_client_it_cannot_bound_before_recovery(
    monkeypatch,
) -> None:
    _stub_cli_runtime(monkeypatch, [])
    monkeypatch.setattr(runtime, "make_subtensor", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: pytest.fail("writer built on an unbounded client"),
    )

    with pytest.raises(SystemExit, match="chain client refused"):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )


def test_cli_prints_an_expired_recovery_then_the_same_cycles_fresh_write(
    monkeypatch, capsys
) -> None:
    _stub_cli_runtime(monkeypatch, [])

    def cycle(**kwargs):
        kwargs["report_recovery"](
            {"status": STATUS_EXPIRED, "recovery": {"status": STATUS_EXPIRED}}
        )
        return {"status": STATUS_CONFIRMED}

    monkeypatch.setattr(runtime, "run_direct_cycle", cycle)

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 0
    )
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["status"] for line in lines] == [STATUS_EXPIRED, STATUS_CONFIRMED]


def test_cli_startup_recovery_contradiction_stops_before_ready(
    monkeypatch, capsys
) -> None:
    _stub_cli_runtime(monkeypatch, [])

    def recover():
        raise DirectSubmissionContradiction("stored row differs")

    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: SimpleNamespace(recover=recover),
    )
    monkeypatch.setattr(
        runtime,
        "_notify_ready",
        lambda: pytest.fail("contradictory journal reported ready"),
    )

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out) == {
        "status": "CONTRADICTION_STOPPED",
        "error": "stored row differs",
    }


def test_cli_once_reports_startup_recovery_ambiguity_without_ready(
    monkeypatch, capsys
) -> None:
    _stub_cli_runtime(monkeypatch, [])

    def recover():
        raise DirectSubmissionAmbiguous("signed intent is unresolved")

    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: SimpleNamespace(recover=recover),
    )
    monkeypatch.setattr(
        runtime,
        "_notify_ready",
        lambda: pytest.fail("ambiguous one-shot recovery reported ready"),
    )

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out) == {
        "status": "NOT_PROVEN",
        "error": "signed intent is unresolved",
    }


def test_recurring_cli_paces_startup_recovery_ambiguity(monkeypatch, capsys) -> None:
    class StopLoop(BaseException):
        pass

    events = [StopLoop()]
    order: list[str] = []
    _stub_cli_runtime(monkeypatch, events)

    def recover():
        raise DirectSubmissionAmbiguous("signed intent is unresolved")

    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: SimpleNamespace(recover=recover),
    )
    monkeypatch.setattr(runtime, "_notify_ready", lambda: order.append("ready"))
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: order.append("sleep"))

    with pytest.raises(StopLoop):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )

    assert json.loads(capsys.readouterr().out) == {
        "status": "NOT_PROVEN",
        "error": "signed intent is unresolved",
    }
    assert order == ["ready", "sleep"]
    assert events == []


def test_cli_reconciles_startup_telemetry_after_reporting_ready(
    monkeypatch, tmp_path: Path
) -> None:
    order: list[str] = []
    _stub_cli_runtime(monkeypatch, [])
    recovered_receipt = DirectSubmissionReceipt(
        status=STATUS_RECOVERED,
        attempt_id="sha256:" + "1" * 64,
        extrinsic_hash="0x" + "2" * 64,
        block_hash="0x" + "3" * 64,
        block_number=ANCHOR_NUMBER,
        recovered=True,
    )
    writer = SimpleNamespace(
        state_path=tmp_path / "direct-writer" / "state.json",
        recover=lambda: order.append("recover") or recovered_receipt,
    )
    monkeypatch.setattr(
        writer_runtime,
        "DirectWeightWriter",
        lambda **_kwargs: writer,
    )
    monkeypatch.setattr(runtime, "_notify_ready", lambda: order.append("ready"))
    monkeypatch.setattr(
        runtime.grp,
        "getgrnam",
        lambda group: (
            SimpleNamespace(gr_gid=1234)
            if group == "cathedral-telemetry"
            else pytest.fail("unexpected telemetry group")
        ),
    )
    captured: dict[str, object] = {}

    def recovered_cycle_event(**kwargs):
        order.append("telemetry")
        captured.update(kwargs)
        return {
            "status": recovered_receipt.status,
            "recovery": recovered_receipt.as_document(),
            "telemetry": {"status": "SPOOLED", "event_id": "sha256:event"},
        }

    monkeypatch.setattr(runtime, "_recovered_cycle_event", recovered_cycle_event)
    spool_path = (tmp_path / "telemetry" / "events.jsonl").resolve()

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                f"--telemetry-spool={spool_path}",
                "--telemetry-reader-group=cathedral-telemetry",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 0
    )
    assert order == ["recover", "ready", "telemetry"]
    assert captured["recovered"] == recovered_receipt
    assert captured["writer"] is writer
    assert captured["keypair"].ss58_address == VALIDATOR
    assert isinstance(captured["telemetry_sink"], TelemetrySpool)
    assert captured["telemetry_sink"].path == spool_path


@pytest.mark.parametrize(
    "status,expected",
    (
        (STATUS_CONFIRMED, 0),
        (STATUS_RECOVERED, 0),
        (STATUS_EXPIRED, 2),
    ),
)
def test_cli_once_succeeds_only_after_exact_confirmation(
    monkeypatch, status, expected
) -> None:
    _stub_cli_runtime(monkeypatch, [{"status": status}])

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == expected
    )


def test_cli_once_returns_nonzero_for_expected_chain_failure(monkeypatch) -> None:
    _stub_cli_runtime(monkeypatch, [ChainClientError("finalized head unavailable")])

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 2
    )


def test_recurring_cli_continues_after_expected_chain_failure(monkeypatch) -> None:
    class StopLoop(BaseException):
        pass

    events = [ChainClientError("finalized head unavailable"), StopLoop()]
    _stub_cli_runtime(monkeypatch, events)
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(StopLoop):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )
    assert events == []


def test_recurring_cli_reports_unexpected_exception_and_continues(
    monkeypatch, capsys
) -> None:
    class StopLoop(BaseException):
        pass

    events = [RuntimeError("worker pool failed"), StopLoop()]
    _stub_cli_runtime(monkeypatch, events)
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(StopLoop):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )

    event = json.loads(capsys.readouterr().out.splitlines()[0])
    assert event == {
        "status": "NOT_PROVEN",
        "error": "RuntimeError: worker pool failed",
    }
    assert events == []


def test_cli_once_returns_nonzero_for_unexpected_exception(monkeypatch) -> None:
    _stub_cli_runtime(monkeypatch, [RuntimeError("worker pool failed")])

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 2
    )


def test_cli_final_exception_handler_does_not_catch_process_control(
    monkeypatch,
) -> None:
    _stub_cli_runtime(monkeypatch, [KeyboardInterrupt()])

    with pytest.raises(KeyboardInterrupt):
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )


def test_recurring_cli_stops_on_submission_contradiction(monkeypatch) -> None:
    events = [DirectSubmissionContradiction("stored row differs"), {"status": "later"}]
    _stub_cli_runtime(monkeypatch, events)

    assert (
        runtime.main(
            [
                "--qvl",
                "/reviewed/qvl",
                "--snp-policy",
                "/reviewed/snp-policy.json",
                "--snpguest",
                "/reviewed/snpguest",
                f"--expected-hotkey={VALIDATOR}",
                "--confirm-direct-write",
            ]
        )
        == 2
    )
    assert events == [{"status": "later"}]


def test_response_deadlines_are_observational_and_below_the_mortal_window() -> None:
    assert DISCOVERY_RESPONSE_DEADLINE_SECONDS == 60.0
    assert MINER_RESPONSE_DEADLINE_SECONDS == 90.0
    assert FULL_CYCLE_RESPONSE_DEADLINE_SECONDS == 120.0
    assert FULL_CYCLE_RESPONSE_DEADLINE_SECONDS < MORTAL_PERIOD_BLOCKS * 12.0


def test_direct_runtime_has_no_relay_publisher_or_cybergym_dependency() -> None:
    sources = "\n".join(
        Path(module.__file__).read_text(encoding="utf-8")
        for module in (runtime, writer_runtime)
    ).lower()
    assert "fetch_vector" not in sources
    assert "weights/next" not in sources
    assert "api.cathedral.computer" not in sources
    assert "scaffold" not in sources
    assert "cybergym" not in sources


def test_validator_and_writer_import_without_a_cycle() -> None:
    assert runtime.DirectWeightPlan is DirectWeightPlan
    assert writer_runtime.DirectWeightPlan is DirectWeightPlan


# A weight write included in a finalized block whose dispatch failed (V-07).
# The validator stops with its own exit code, only the operator's record
# command clears the journal, and only after it proves the failure from
# finalized chain state. The next cycle then writes fresh weights.

ROOT = Path(__file__).resolve().parents[2]
ERA_END = SIGN_HEAD + MORTAL_PERIOD_BLOCKS - 1
WEIGHT_CALL_INDEX = 2
FAILED_PALLET_INDEX = 7
FAILED_ERROR_INDEX = 15
FAILED_ERROR_NAME = "NeuronNoValidatorPermit"
FAILED_ERROR_DOCS = ["The validator has no permit."]
OTHER_GENESIS_HASH = "0x" + "7" * 64
VALIDATOR_ARGS = [
    "--qvl",
    "/reviewed/qvl",
    "--snp-policy",
    "/reviewed/snp-policy.json",
    "--snpguest",
    "/reviewed/snpguest",
    f"--expected-hotkey={VALIDATOR}",
    "--confirm-direct-write",
]
RECORD_ARGS = [runtime.RECORD_FAILED_WRITE_COMMAND, f"--expected-hotkey={VALIDATOR}"]


def _status_tool():
    name = "cathedral_test_direct_writer_status"
    path = ROOT / "deploy" / "validator-update" / "cathedral-validator-status"
    spec = importlib.util.spec_from_file_location(
        name, path, loader=SourceFileLoader(name, str(path))
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FailedExecutionReceipt:
    is_success = False
    error_message = {"type": "Module", "name": FAILED_ERROR_NAME, "docs": []}


class ModuleErrorMetadata:
    """The metadata lookup the pinned client names a module error with."""

    def __init__(self, name: str | None = FAILED_ERROR_NAME) -> None:
        self.name = name
        self.lookups: list[tuple[int, int]] = []

    def get_module_error(self, *, module_index: int, error_index: int):
        self.lookups.append((module_index, error_index))
        if self.name is not None and (module_index, error_index) == (
            FAILED_PALLET_INDEX,
            FAILED_ERROR_INDEX,
        ):
            return SimpleNamespace(name=self.name, docs=list(FAILED_ERROR_DOCS))
        return None


def event_record(
    index: int | None,
    module_id: str,
    event_id: str,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    """One decoded System.Events record, in the pinned client's shape."""

    body = {"module_id": module_id, "event_id": event_id, "attributes": attributes}
    return {
        "phase": "ApplyExtrinsic" if index is not None else "Finalization",
        "extrinsic_idx": index,
        "event": body,
        "event_index": "0000",
        **body,
        "topics": [],
    }


class FailedWriteSubstrate(WriterSubstrate):
    """The fake node, where the weight call lands and its dispatch fails.

    Two other extrinsics come first in its block and each has its own success
    event, so only the extrinsic index pairs the right outcome with the write.
    ``validator_sees_failure`` is what the validator's recovery reads through
    the pinned client's receipt; ``dispatch`` is what the block's events hold.
    A real node keeps the two in step. Refusal tests move them apart.
    """

    def __init__(self) -> None:
        super().__init__()
        self.validator_sees_failure = True
        self.dispatch = "failed"
        self.dispatch_error: object = {
            "Module": {"index": FAILED_PALLET_INDEX, "error": "0x0f000000"}
        }
        self.duplicate_block: int | None = None
        self.unreadable_block: int | None = None
        self.block_not_mapping: int | None = None
        self.bad_hash_block: int | None = None
        self.unreadable_extrinsic_block: int | None = None
        self.events_mode = "list"
        self.extra_events: list[object] = []
        self.genesis = FINNEY_GENESIS_HASH
        self.metadata = ModuleErrorMetadata()
        self.block_reads: list[int] = []
        self.event_reads: list[object] = []
        self.runtime_reads: list[object] = []

    def block_hash(self, block: int) -> str:
        if block == 0:
            return self.genesis
        return super().block_hash(block)

    def get_block(self, *, block_hash: str) -> dict[str, object]:
        if block_hash in self.orphans.values():
            # The node still serves the orphan, which never held this write.
            self.block_reads.append(-1)
            return {"extrinsics": []}
        block_number = self.get_block_number(block_hash)
        self.block_reads.append(block_number)
        if block_number == self.unreadable_block:
            return {"extrinsics": None}
        if block_number == self.block_not_mapping:
            return None
        extrinsics: list[object] = []
        if block_number == self.bad_hash_block:
            extrinsics.append(Extrinsic({"call": {}}, extrinsic_hash="not-a-hash"))
        if block_number == self.unreadable_extrinsic_block:
            extrinsics.append(Extrinsic("0x0400", extrinsic_hash="0x" + "3" * 64))
        if self.included and block_number in {
            self.inclusion_block,
            self.duplicate_block,
        }:
            (weight_call,) = super().get_block(
                block_hash=self.block_hash(self.inclusion_block)
            )["extrinsics"]
            extrinsics = [
                Extrinsic(
                    {"call": {"call_module": "Timestamp", "call_function": "set"}},
                    extrinsic_hash="0x" + "1" * 64,
                ),
                Extrinsic(
                    {
                        "address": MINER_ONE,
                        "call": {"call_module": "Balances", "call_function": "x"},
                    },
                    extrinsic_hash="0x" + "2" * 64,
                ),
                weight_call,
            ]
        return {"extrinsics": extrinsics}

    def retrieve_extrinsic_by_hash(self, block_hash: str, extrinsic_hash: str):
        receipt = super().retrieve_extrinsic_by_hash(block_hash, extrinsic_hash)
        return FailedExecutionReceipt() if self.validator_sees_failure else receipt

    def get_events(self, block_hash: str | None = None):
        self.event_reads.append(block_hash)
        if self.events_mode == "raise":
            raise SubstrateRequestException("events are unavailable")
        if self.events_mode == "not_list":
            return {"events": []}
        info = {"weight": {"ref_time": 1, "proof_size": 0}, "pays_fee": "No"}
        failed = event_record(
            WEIGHT_CALL_INDEX,
            "System",
            "ExtrinsicFailed",
            {"dispatch_error": self.dispatch_error, "dispatch_info": info},
        )
        succeeded = event_record(
            WEIGHT_CALL_INDEX, "System", "ExtrinsicSuccess", {"dispatch_info": info}
        )
        outcome = {
            "failed": [failed],
            "succeeded": [succeeded],
            "failed_and_succeeded": [failed, succeeded],
            "no_outcome": [],
            "failed_twice": [failed, failed],
        }[self.dispatch]
        return [
            event_record(0, "System", "ExtrinsicSuccess", {"dispatch_info": info}),
            event_record(1, "Balances", "Transfer", {}),
            event_record(1, "System", "ExtrinsicSuccess", {"dispatch_info": info}),
            event_record(
                WEIGHT_CALL_INDEX,
                "TransactionPayment",
                "TransactionFeePaid",
                {"who": VALIDATOR, "actual_fee": 0, "tip": 0},
            ),
            *outcome,
            *self.extra_events,
            event_record(None, "System", "Remarked", {}),
        ]

    def init_runtime(self, block_hash: str | None = None, block_id: int | None = None):
        assert block_id is None
        self.runtime_reads.append(block_hash)
        return SimpleNamespace(metadata=self.metadata)


def failed_write_writer(tmp_path: Path, monkeypatch):
    instance, subtensor, planned = writer(tmp_path, monkeypatch)
    substrate = FailedWriteSubstrate()
    substrate.owner = subtensor
    substrate.expected_uids = subtensor.substrate.expected_uids
    substrate.expected_weights = subtensor.substrate.expected_weights
    subtensor.substrate = substrate
    return instance, subtensor, planned


def stopped_on_failed_write(tmp_path: Path, monkeypatch):
    """Journal a real included-and-failed write, then finalize its whole era."""

    instance, subtensor, planned = failed_write_writer(tmp_path, monkeypatch)
    with pytest.raises(DirectSubmissionFinalizedFailure, match="finalized with"):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == PHASE_FINALIZED_FAILED
    subtensor.substrate.finalized_number = ERA_END + 1
    return instance, subtensor, planned


def assert_record_refused(instance: DirectWeightWriter, subtensor, match: str):
    before = instance.state_path.read_bytes()
    with pytest.raises(FailedWriteRecordRefused, match=match):
        instance.record_finalized_failure()
    assert instance.state_path.read_bytes() == before
    assert subtensor.substrate.sign_calls == 1
    assert subtensor.substrate.submit_calls == 1


def _cli_with_real_writer(monkeypatch, instance, subtensor, anchor: list):
    """Run the real validator CLI and record command over the fake chain."""

    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    # What the shipped unit declares: it keeps exit 3 stopped.
    monkeypatch.setenv(runtime.FAILED_WRITE_EXIT_CODE_ENV, "3")
    monkeypatch.setattr(
        runtime,
        "load_direct_validator_verifier",
        lambda _path: SimpleNamespace(digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST),
    )
    monkeypatch.setattr(
        runtime,
        "ComputeAdapter",
        lambda *_args, **_kwargs: SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
    )
    monkeypatch.setattr(runtime, "load_snp_policy", lambda _path: object())
    monkeypatch.setattr(runtime, "SnpProductionVerifier", lambda **_kwargs: object())
    wallets: list[str] = []

    def load_wallet(*_args, **_kwargs):
        wallets.append("validator")
        return SimpleNamespace(hotkey=FakeKeypair())

    monkeypatch.setattr(runtime, "make_wallet", load_wallet)
    monkeypatch.setattr(runtime, "make_subtensor", lambda *_a, **_k: subtensor)
    monkeypatch.setattr(record_cli, "make_subtensor", lambda *_a, **_k: subtensor)
    # The validator gets the test's writer; the record command builds its own
    # real writer from the public hotkey alone.
    monkeypatch.setattr(writer_runtime, "DirectWeightWriter", lambda **_k: instance)
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: anchor[0]
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: round_result(machine_row("1")),
    )
    return wallets


def _lines(capsys) -> list[dict[str, object]]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_failed_write_stops_then_a_proven_record_lets_the_next_cycle_write(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    instance, subtensor, planned = failed_write_writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    anchor = [planned.snapshot]
    wallets = _cli_with_real_writer(monkeypatch, instance, subtensor, anchor)
    ready: list[str] = []
    monkeypatch.setattr(runtime, "_notify_ready", lambda: ready.append("READY"))

    # 1. The write lands in a finalized block and fails: the cycle stops the
    #    validator with the failed-write exit code, not the contradiction one.
    assert runtime.main(VALIDATOR_ARGS) == runtime.EXIT_FINALIZED_FAILED_STOPPED == 3
    (stop,) = _lines(capsys)
    assert stop["status"] == runtime.STATUS_FINALIZED_FAILED_STOPPED
    assert "record-failed-write" in stop["action"]
    journal = json.loads(instance.state_path.read_text(encoding="ascii"))
    pending = journal["pending"]
    # The on-disk phase every reader keys on, including the status tool.
    assert pending["phase"] == PHASE_FINALIZED_FAILED == "finalized_failed"
    assert substrate.signed == [(SIGN_HEAD, 4)]
    assert ready == ["READY"]

    # 2. A restart finds the same stop before it reports ready.
    assert runtime.main(VALIDATOR_ARGS) == runtime.EXIT_FINALIZED_FAILED_STOPPED
    assert [line["status"] for line in _lines(capsys)] == [
        runtime.STATUS_FINALIZED_FAILED_STOPPED
    ]
    assert ready == ["READY"]
    stopped = instance.state_path.read_bytes()
    assert _status_tool()._pending_phase(pending, expected_identity=VALIDATOR) == (
        PHASE_FINALIZED_FAILED
    )

    # 3. The record command refuses while the validator or an update holds a
    #    lock, and while the era is not fully finalized. It changes nothing.
    wallets_before = list(wallets)
    for held, message in (
        (instance.cycle_locked, "cycle lock"),
        (instance.process_locked, "process lock"),
    ):
        with held():
            assert runtime.main(RECORD_ARGS) == 1
        (refused,) = _lines(capsys)
        assert refused["status"] == record_cli.STATUS_REFUSED
        assert message in refused["error"]
        assert instance.state_path.read_bytes() == stopped
    assert substrate.finalized_number < ERA_END
    assert runtime.main(RECORD_ARGS) == 1
    (refused,) = _lines(capsys)
    assert refused["error"] == (
        f"mortal era {SIGN_HEAD}-{ERA_END} is not finalized "
        f"(finalized head {substrate.finalized_number})"
    )
    assert instance.state_path.read_bytes() == stopped

    # 4. Once the era is finalized it proves the failure and records it. The
    #    record command bounds its own client and never loads a key.
    substrate.finalized_number = ERA_END + 1
    substrate.retry_timeout, substrate.max_retries = 60.0, 5
    assert runtime.main(RECORD_ARGS) == 0
    (recorded,) = _lines(capsys)
    dispatch_error = {
        "type": "Module",
        "pallet_index": FAILED_PALLET_INDEX,
        "error_index": FAILED_ERROR_INDEX,
        "name": FAILED_ERROR_NAME,
        "docs": FAILED_ERROR_DOCS,
    }
    assert recorded == {
        "status": record_cli.STATUS_RECORDED,
        "attempt_id": pending["attempt_id"],
        "extrinsic_hash": EXTRINSIC_HASH,
        "block_number": ANCHOR_NUMBER + 2,
        "block_hash": INCLUSION_HASH,
        "extrinsic_index": WEIGHT_CALL_INDEX,
        "dispatch_error": dispatch_error,
    }
    assert VALIDATOR not in json.dumps(recorded)
    assert (substrate.retry_timeout, substrate.max_retries) == (
        writer_runtime.DIRECT_RPC_RETRY_TIMEOUT_SECONDS,
        writer_runtime.DIRECT_RPC_MAX_RETRIES,
    )
    assert wallets == wallets_before
    assert substrate.event_reads == [INCLUSION_HASH]
    assert substrate.runtime_reads == [INCLUSION_HASH]
    assert substrate.metadata.lookups == [(FAILED_PALLET_INDEX, FAILED_ERROR_INDEX)]
    journal = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert journal["pending"] is None
    assert journal["last_attempt"] == {
        "attempt_id": pending["attempt_id"],
        "status": STATUS_FINALIZED_FAILED,
        "identity": pending["identity"],
        "intent": pending["intent"],
        "receipt": {
            "status": STATUS_FINALIZED_FAILED,
            "attempt_id": pending["attempt_id"],
            "extrinsic_hash": EXTRINSIC_HASH,
            "block_hash": INCLUSION_HASH,
            "block_number": ANCHOR_NUMBER + 2,
            "recovered": True,
            "confirmation_heads": [],
        },
        "failure": {
            "block_number": ANCHOR_NUMBER + 2,
            "block_hash": INCLUSION_HASH,
            "extrinsic_index": WEIGHT_CALL_INDEX,
            "dispatch_error": dispatch_error,
            "finalized_head": [ERA_END + 1, substrate.block_hash(ERA_END + 1)],
            "pending_phase": PHASE_FINALIZED_FAILED,
            "pending_receipt": None,
            "pending_error": None,
        },
    }
    # The status tool accepts the record the writer wrote.
    assert _status_tool()._last_attempt_summary(
        journal["last_attempt"], expected_identity=VALIDATOR
    ) == (STATUS_FINALIZED_FAILED, ANCHOR_NUMBER + 2)
    # Nothing was signed or sent again.
    assert substrate.signed == [(SIGN_HEAD, 4)]
    assert substrate.broadcast == [EXTRINSIC_HASH]

    # 5. The next cycle signs fresh weights at a newer anchor and sign head,
    #    with the nonce the chain reports now, and confirms them.
    substrate.validator_sees_failure = False
    substrate.sign_head = substrate.best_number = ERA_END + 2
    substrate.nonce = 5
    substrate.extrinsic_hash = SECOND_EXTRINSIC_HASH
    substrate.inclusion_block = ERA_END + 3
    substrate.finalized_number = substrate.inclusion_block + 2
    anchor[0] = replace(
        snapshot(ERA_END + 1), block_hash=substrate.block_hash(ERA_END + 1)
    )
    assert runtime.main([*VALIDATOR_ARGS, "--once"]) == 0
    (written,) = _lines(capsys)
    assert written["status"] == STATUS_CONFIRMED
    assert written["receipt"]["extrinsic_hash"] == SECOND_EXTRINSIC_HASH
    assert substrate.signed == [(SIGN_HEAD, 4), (ERA_END + 2, 5)]
    assert substrate.broadcast == [EXTRINSIC_HASH, SECOND_EXTRINSIC_HASH]
    journal = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert journal["pending"] is None
    assert journal["last_attempt"]["status"] == STATUS_CONFIRMED
    assert journal["last_attempt"]["identity"]["anchor"]["block_number"] == (
        ERA_END + 1
    )
    assert journal["last_attempt"]["intent"]["nonce"] == 5
    assert journal["last_attempt"]["intent"]["era_reference_block"] == ERA_END + 2


def test_record_reads_each_era_height_past_a_cached_orphan(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = failed_write_writer(tmp_path, monkeypatch)
    substrate = subtensor.substrate
    # Signing caches the best head by number; that block is then reorged out
    # and the write lands in the canonical block at the same height.
    substrate.best_number = substrate.inclusion_block
    substrate.best_orphaned = True
    with pytest.raises(DirectSubmissionFinalizedFailure):
        submit_before_deadline(instance, planned)
    assert substrate.get_block_hash(substrate.inclusion_block) == ORPHAN_HASH
    substrate.finalized_number = ERA_END + 1

    record = instance.record_finalized_failure()

    assert (record["block_number"], record["block_hash"]) == (
        substrate.inclusion_block,
        INCLUSION_HASH,
    )
    assert -1 not in substrate.block_reads


@pytest.mark.parametrize("declared", (None, "2", "4", " 3"))
def test_failed_write_stop_exits_two_unless_the_unit_keeps_three_stopped(
    tmp_path: Path, monkeypatch, capsys, declared: str | None
) -> None:
    # A unit from an older bootstrap keeps only exit 2 stopped; exit 3 would
    # restart every RestartSec. The stop line still names the failed write.
    instance, subtensor, planned = stopped_on_failed_write(tmp_path, monkeypatch)
    _cli_with_real_writer(monkeypatch, instance, subtensor, [planned.snapshot])
    if declared is None:
        monkeypatch.delenv(runtime.FAILED_WRITE_EXIT_CODE_ENV)
    else:
        monkeypatch.setenv(runtime.FAILED_WRITE_EXIT_CODE_ENV, declared)
    monkeypatch.setattr(
        runtime, "_notify_ready", lambda: pytest.fail("stopped writer reported ready")
    )

    assert runtime.main(VALIDATOR_ARGS) == runtime.EXIT_CONTRADICTION_STOPPED
    (stop,) = _lines(capsys)
    assert stop["status"] == runtime.STATUS_FINALIZED_FAILED_STOPPED
    assert "record-failed-write" in stop["action"]


def test_recorded_failure_keeps_fencing_its_anchor(tmp_path: Path, monkeypatch) -> None:
    instance, subtensor, planned = stopped_on_failed_write(tmp_path, monkeypatch)
    instance.record_finalized_failure()
    substrate = subtensor.substrate
    substrate.validator_sees_failure = False
    substrate.sign_head = substrate.best_number = ERA_END + 2
    substrate.nonce = 5

    with pytest.raises(DirectValidatorError, match="already attempted"):
        submit_before_deadline(instance, planned)

    assert substrate.signed == [(SIGN_HEAD, 4)]
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"] is None
    assert state["last_attempt"]["status"] == STATUS_FINALIZED_FAILED


def _mutate_substrate(substrate: FailedWriteSubstrate, mutation: str) -> None:
    if mutation == "genesis":
        substrate.genesis = OTHER_GENESIS_HASH
        substrate.runtime_cache = RuntimeCache()
        SubstrateInterface._get_block_hash.cache_clear()
    elif mutation == "inclusion_unfinalized":
        substrate.finalized_number = substrate.inclusion_block - 1
    elif mutation == "era_unfinalized":
        substrate.finalized_number = ERA_END - 1
    elif mutation == "not_included":
        substrate.included = False
    elif mutation == "duplicate":
        substrate.duplicate_block = substrate.inclusion_block + 3
    elif mutation == "wrong_call":
        substrate.wrong_call = True
    elif mutation == "unreadable_block":
        substrate.unreadable_block = ERA_END
    elif mutation == "block_not_mapping":
        substrate.block_not_mapping = ERA_END
    elif mutation == "bad_extrinsic_hash":
        substrate.bad_hash_block = ERA_END
    elif mutation == "unreadable_extrinsic":
        substrate.unreadable_extrinsic_block = ERA_END
    elif mutation == "finalized_head_down":

        def unavailable() -> str:
            raise SubstrateRequestException("finalized head is unavailable")

        substrate.get_chain_finalised_head = unavailable
    elif mutation in {"events_raise", "events_not_list"}:
        substrate.events_mode = mutation.removeprefix("events_")
    elif mutation == "event_not_mapping":
        substrate.extra_events = ["not-an-event"]
    elif mutation == "extrinsic_event_not_mapping":
        substrate.extra_events = [{"extrinsic_idx": WEIGHT_CALL_INDEX, "event": []}]
    elif mutation == "unnamed_error":
        substrate.metadata.name = None
    elif mutation == "empty_error_name":
        substrate.metadata.name = ""
    elif mutation == "malformed_error":
        substrate.dispatch_error = {"Module": "not-a-module-error"}
    else:
        substrate.dispatch = mutation


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("succeeded", "dispatch succeeded"),
        ("failed_and_succeeded", "dispatch succeeded"),
        ("no_outcome", "has 0 ExtrinsicFailed events"),
        ("failed_twice", "has 2 ExtrinsicFailed events"),
        ("not_included", "not in any finalized block of its era"),
        ("duplicate", "more than once"),
        ("inclusion_unfinalized", "is not finalized"),
        ("era_unfinalized", "is not finalized"),
        ("wrong_call", "different chain call"),
        ("genesis", "pinned Finney genesis"),
        ("finalized_head_down", "ChainClientError"),
        ("unreadable_block", "has no readable extrinsics"),
        ("block_not_mapping", "has no readable extrinsics"),
        ("bad_extrinsic_hash", "era extrinsic is not"),
        ("unreadable_extrinsic", f"extrinsic {ERA_END}-0 is not readable"),
        ("events_raise", "events are unavailable"),
        ("events_not_list", "has no readable events"),
        ("event_not_mapping", "an event record is not readable"),
        ("extrinsic_event_not_mapping", "an extrinsic event is not readable"),
        ("unnamed_error", "not named by its block's runtime"),
        ("empty_error_name", "not named by its block's runtime"),
        ("malformed_error", "dispatch module error is malformed"),
    ],
)
def test_record_refuses_unless_finalized_history_proves_the_failure(
    tmp_path: Path, monkeypatch, mutation: str, message: str
) -> None:
    instance, subtensor, _planned = stopped_on_failed_write(tmp_path, monkeypatch)
    _mutate_substrate(subtensor.substrate, mutation)

    assert_record_refused(instance, subtensor, message)


@pytest.mark.parametrize(
    "phase",
    ("signed_intent", "ambiguous", "included_awaiting_confirmation"),
)
def test_record_refuses_a_pending_intent_recovery_can_still_resolve(
    tmp_path: Path, monkeypatch, phase: str
) -> None:
    instance, subtensor, _planned = stopped_on_failed_write(tmp_path, monkeypatch)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    state["pending"]["phase"] = phase
    instance.state_path.write_text(json.dumps(state), encoding="ascii")
    reads = list(subtensor.substrate.block_reads)

    assert_record_refused(instance, subtensor, f"{phase!r}, not 'finalized_failed'")
    assert subtensor.substrate.block_reads == reads
    assert subtensor.substrate.event_reads == []


def test_record_refuses_a_real_ambiguous_journal_without_reading_the_chain(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, planned = failed_write_writer(tmp_path, monkeypatch)
    subtensor.substrate.raise_without_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    subtensor.substrate.finalized_number = ERA_END + 1

    assert_record_refused(instance, subtensor, "'ambiguous', not 'finalized_failed'")
    assert subtensor.substrate.block_reads == []
    assert subtensor.substrate.event_reads == []

    # Hand-editing the phase cannot clear it: the chain shows no inclusion.
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    state["pending"]["phase"] = PHASE_FINALIZED_FAILED
    instance.state_path.write_text(json.dumps(state), encoding="ascii")
    assert_record_refused(instance, subtensor, "not in any finalized block")


def test_record_refuses_a_confirmed_journal(tmp_path: Path, monkeypatch) -> None:
    instance, subtensor, planned = failed_write_writer(tmp_path, monkeypatch)
    subtensor.substrate.validator_sees_failure = False
    assert submit_before_deadline(instance, planned).status == STATUS_CONFIRMED
    reads = list(subtensor.substrate.block_reads)

    assert_record_refused(
        instance, subtensor, r"no pending intent \(last attempt: CONFIRMED\)"
    )
    assert subtensor.substrate.block_reads == reads


def _tamper(state: dict[str, object], tampering: str) -> dict[str, object] | str:
    pending = state["pending"]
    if tampering == "not_json":
        return "not-json"
    if tampering == "unbound_nonce":
        pending["intent"]["nonce"] += 1
        return state
    if tampering == "foreign_signer":
        pending["intent"]["validator_hotkey"] = OTHER_VALIDATOR
    elif tampering == "other_period":
        pending["intent"]["mortal_period_blocks"] = MORTAL_PERIOD_BLOCKS * 2
    pending["attempt_id"] = writer_runtime._attempt_id(
        pending["identity"], pending["intent"]
    )
    return state


@pytest.mark.parametrize(
    ("tampering", "message"),
    [
        ("not_json", "not strict JSON"),
        ("unbound_nonce", "attempt id is wrong"),
        ("foreign_signer", "names another signer"),
        ("other_period", "pending signed intent is invalid"),
    ],
)
def test_record_refuses_a_tampered_journal(
    tmp_path: Path, monkeypatch, tampering: str, message: str
) -> None:
    instance, subtensor, _planned = stopped_on_failed_write(tmp_path, monkeypatch)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    tampered = _tamper(state, tampering)
    instance.state_path.write_text(
        tampered if isinstance(tampered, str) else json.dumps(tampered),
        encoding="ascii",
    )

    assert_record_refused(instance, subtensor, message)
    assert subtensor.substrate.event_reads == []


def test_record_refuses_while_the_journal_lock_is_held(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, _planned = stopped_on_failed_write(tmp_path, monkeypatch)

    with instance._locked():
        assert_record_refused(instance, subtensor, "another direct writer")
    assert subtensor.substrate.event_reads == []
    # Every lock taken for the refusal was released again.
    assert instance.record_finalized_failure()["extrinsic_index"] == 2


def test_record_refuses_without_a_journal_and_creates_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    instance, subtensor, _planned = failed_write_writer(tmp_path, monkeypatch)

    with pytest.raises(FailedWriteRecordRefused, match="no direct writer journal"):
        instance.record_finalized_failure()
    assert list(tmp_path.iterdir()) == []


def test_record_command_reports_an_unwritten_record_as_not_proven(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    instance, subtensor, _planned = stopped_on_failed_write(tmp_path, monkeypatch)
    monkeypatch.setattr(record_cli, "make_subtensor", lambda *_a, **_k: subtensor)
    before = instance.state_path.read_bytes()

    def lose_the_write(self, document):
        raise DirectSubmissionAmbiguous("direct state could not be persisted")

    monkeypatch.setattr(DirectWeightWriter, "_write_state", lose_the_write)

    assert runtime.main(RECORD_ARGS) == 1
    (line,) = _lines(capsys)
    assert line["status"] == record_cli.STATUS_NOT_PROVEN
    assert "could not be persisted" in line["error"]
    assert instance.state_path.read_bytes() == before


def test_record_command_refuses_a_chain_client_it_cannot_bound(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    monkeypatch.setattr(
        record_cli,
        "make_subtensor",
        lambda *_a, **_k: SimpleNamespace(substrate=SimpleNamespace()),
    )

    assert runtime.main(RECORD_ARGS) == 1
    (line,) = _lines(capsys)
    assert line["status"] == record_cli.STATUS_REFUSED
    assert "chain client refused" in line["error"]
    assert list(tmp_path.iterdir()) == []


def test_record_command_refuses_an_unsafe_hotkey_before_chain_access(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        record_cli,
        "make_subtensor",
        lambda *_a, **_k: pytest.fail("record command reached the chain"),
    )

    with pytest.raises(SystemExit, match="path-safe"):
        runtime.main([runtime.RECORD_FAILED_WRITE_COMMAND, "--expected-hotkey=../x"])


@pytest.mark.parametrize(
    ("dispatch_error", "decoded"),
    [
        (
            {"Module": {"index": 7, "error": "0x0F000000"}},
            {"type": "Module", "pallet_index": 7, "error_index": 15},
        ),
        (
            {"Module": (7, 15)},
            {"type": "Module", "pallet_index": 7, "error_index": 15},
        ),
        (
            {"Module": {"index": 7, "error": [15, 0, 0, 0]}},
            {"type": "Module", "pallet_index": 7, "error_index": 15},
        ),
        ("BadOrigin", {"type": "System", "name": "BadOrigin", "detail": None}),
        (
            {"Token": "FundsUnavailable"},
            {"type": "System", "name": "Token", "detail": "FundsUnavailable"},
        ),
        (
            {"Arithmetic": {"Overflow": None}},
            {"type": "System", "name": "Arithmetic", "detail": {"Overflow": None}},
        ),
        (
            {"Other": [1, (2, 3)]},
            {"type": "System", "name": "Other", "detail": [1, [2, 3]]},
        ),
    ],
)
def test_dispatch_errors_are_decoded_from_the_block_runtime(
    dispatch_error: object, decoded: dict[str, object]
) -> None:
    metadata = ModuleErrorMetadata()

    result = writer_runtime._decoded_dispatch_error(
        {"dispatch_error": dispatch_error}, metadata
    )

    if decoded["type"] == "Module":
        decoded = {**decoded, "name": FAILED_ERROR_NAME, "docs": FAILED_ERROR_DOCS}
        assert metadata.lookups == [(7, 15)]
    else:
        assert metadata.lookups == []
    assert result == decoded


@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        (None, "not decodable"),
        ({"dispatch_error": None}, "not decodable"),
        ({"dispatch_error": {}}, "not decodable"),
        ({"dispatch_error": ""}, "not decodable"),
        ({"dispatch_error": {"A": 1, "B": 2}}, "not decodable"),
        ({"dispatch_error": {"Module": (7, 15), "Other": 1}}, "not decodable"),
        ({"dispatch_error": {1: "Other"}}, "not decodable"),
        ({"dispatch_error": {"": 1}}, "not decodable"),
        ({"dispatch_error": {"Module": 7}}, "module error is malformed"),
        ({"dispatch_error": {"Module": (7,)}}, "module error is malformed"),
        ({"dispatch_error": {"Module": (True, 15)}}, "module index is invalid"),
        ({"dispatch_error": {"Module": (256, 15)}}, "module index is invalid"),
        ({"dispatch_error": {"Module": ("7", 15)}}, "module index is invalid"),
        ({"dispatch_error": {"Module": (7, "0x0f00")}}, "error bytes are invalid"),
        ({"dispatch_error": {"Module": (7, "0x0f0000zz")}}, "error bytes are invalid"),
        ({"dispatch_error": {"Module": (7, "1x0f000000")}}, "error bytes are invalid"),
        ({"dispatch_error": {"Module": (7, 256)}}, "error index is invalid"),
        ({"dispatch_error": {"Module": (7, False)}}, "error index is invalid"),
        ({"dispatch_error": {"Module": (7, 15.0)}}, "error index is invalid"),
        ({"dispatch_error": {"Module": (7, 14)}}, "not named"),
        ({"dispatch_error": {"Other": b"bytes"}}, "not plain data"),
        ({"dispatch_error": {"Other": {1: "key"}}}, "not plain data"),
    ],
)
def test_undecodable_dispatch_errors_refuse(attributes: object, message: str) -> None:
    with pytest.raises(FailedWriteRecordRefused, match=message):
        writer_runtime._decoded_dispatch_error(attributes, ModuleErrorMetadata())


def test_unit_never_restarts_either_deliberate_stop() -> None:
    unit = (
        ROOT / "deploy" / "validator-update" / "cathedral-validator-direct.service"
    ).read_text(encoding="ascii")
    lines = unit.splitlines()

    assert runtime.EXIT_CONTRADICTION_STOPPED == 2
    assert runtime.EXIT_FINALIZED_FAILED_STOPPED not in {0, 1, 2}
    assert "Restart=on-failure" in lines
    assert [line for line in lines if line.startswith("RestartPreventExitStatus=")] == [
        "RestartPreventExitStatus="
        f"{runtime.EXIT_CONTRADICTION_STOPPED} "
        f"{runtime.EXIT_FINALIZED_FAILED_STOPPED}"
    ]
    # The unit declares that it keeps the failed-write code stopped.
    assert (
        f"Environment={runtime.FAILED_WRITE_EXIT_CODE_ENV}="
        f"{runtime.EXIT_FINALIZED_FAILED_STOPPED}"
    ) in lines
    # The bootstrap ships no alert unit to point at, so none is named here.
    assert not [line for line in lines if line.startswith("OnFailure=")]
