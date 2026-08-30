from __future__ import annotations

import json
import socket
import stat
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin.independent.constants import (
    FINNEY_GENESIS_HASH,
    SN39_MORTAL_PERIOD_BLOCKS,
    W,
)
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
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
    DirectWeightWriter,
    STATE_SCHEMA,
    STATUS_CONFIRMED,
    STATUS_EXPIRED,
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

VALIDATOR = "5Validator"
MINER_ONE = "5MinerOne"
MINER_TWO = "5MinerTwo"
OTHER_VALIDATOR = "5OtherValidator"
ANCHOR_NUMBER = 100
ANCHOR_HASH = "0x" + "a" * 64
FRESH_HASH = "0x" + "b" * 64
EXTRINSIC_HASH = "0x" + "c" * 64
INCLUSION_HASH = "0x" + "d" * 64
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
    extrinsic_hash = EXTRINSIC_HASH


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

    def get_block_hash(self, block: int) -> str:
        return self.block_hash(block)

    def get_chain_finalised_head(self) -> str:
        return self.block_hash(self.finalized_number)

    def get_block_number(self, block_hash: str) -> int:
        for block in range(0, self.finalized_number + 1):
            if self.block_hash(block) == block_hash:
                return block
        raise ValueError(block_hash)

    def get_account_next_index(self, hotkey: str) -> int:
        assert hotkey == VALIDATOR
        return 4

    def create_signed_extrinsic(self, *, call, keypair, nonce, era):
        assert call == "direct-call"
        assert keypair.ss58_address == VALIDATOR
        assert nonce == 4
        assert era == {
            "period": SN39_MORTAL_PERIOD_BLOCKS,
            "current": ANCHOR_NUMBER + 1,
        }
        self.sign_calls += 1
        return Signed()

    def submit_extrinsic(
        self, signed, *, wait_for_inclusion: bool, wait_for_finalization: bool
    ):
        assert isinstance(signed, Signed)
        self.submit_calls += 1
        self.submission_flags.append((wait_for_inclusion, wait_for_finalization))
        if self.raise_without_include:
            raise TimeoutError("response lost")
        self.included = True
        if self.raise_after_include:
            raise TimeoutError("response lost after inclusion")
        return Signed()

    def get_block(self, *, block_hash: str) -> dict[str, object]:
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
                    }
                )
            ]
        }

    def retrieve_extrinsic_by_hash(
        self, block_hash: str, extrinsic_hash: str
    ) -> ExecutionReceipt:
        assert block_hash == INCLUSION_HASH
        assert extrinsic_hash == EXTRINSIC_HASH
        return ExecutionReceipt()

    def query(self, *, module, storage_function, params, block_hash):
        assert module == "SubtensorModule"
        if storage_function == "StakeThreshold":
            assert params == []
            assert block_hash == FRESH_HASH
            return self.owner.stake_threshold
        if storage_function == "WeightsVersionKey":
            assert params == [39]
            assert block_hash == FRESH_HASH
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

    def metagraph(self, netuid: int, *, block: int) -> Metagraph:
        assert netuid == 39
        miners = self.miners
        if self.remap_after is not None and block >= self.remap_after:
            miners = tuple(
                replace(miner, hotkey="5Replacement") if miner.uid == 19 else miner
                for miner in miners
            )
        if self.extra_miner_after is not None and block >= self.extra_miner_after:
            miners = (*miners, MINER_TWO_AXON)
        result = Metagraph(block, miners=miners)
        if block == ANCHOR_NUMBER + 1:
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
        assert (netuid, block) == (39, ANCHOR_NUMBER + 1)
        return self.rate_limit

    def blocks_since_last_update(self, netuid: int, uid: int, *, block: int) -> int:
        assert (netuid, uid, block) == (39, 7, ANCHOR_NUMBER + 1)
        return self.blocks_since

    def min_allowed_weights(self, *, netuid: int, block: int) -> int:
        assert (netuid, block) == (39, ANCHOR_NUMBER + 1)
        return 1

    def max_weight_limit(self, *, netuid: int, block: int) -> float:
        assert (netuid, block) == (39, ANCHOR_NUMBER + 1)
        return 1.0

    def commit_reveal_enabled(self, *, netuid: int, block: int) -> bool:
        assert (netuid, block) == (39, ANCHOR_NUMBER + 1)
        return False

    def get_mechanism_count(self, netuid: int, *, block: int) -> int:
        assert (netuid, block) == (39, ANCHOR_NUMBER + 1)
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
        snapshot_reader=lambda _subtensor, _keypair: snapshot(
            ANCHOR_NUMBER + 1, miners=miners
        ),
        call_builder=lambda _kwargs: "direct-call",
    )
    return instance, subtensor, selected


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
    original = substrate.get_block_hash
    reads = 0

    def fail_during_confirmation(block: int) -> str:
        nonlocal reads
        if block == substrate.inclusion_block + 1:
            reads += 1
            if reads == 2:
                raise ConnectionError("confirmation RPC disconnected")
        return original(block)

    monkeypatch.setattr(substrate, "get_block_hash", fail_during_confirmation)
    with pytest.raises(
        DirectSubmissionAmbiguous, match="confirmation block 103 hash is unavailable"
    ):
        submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "included_awaiting_confirmation"
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1

    monkeypatch.setattr(substrate, "get_block_hash", original)
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
    original = substrate.get_block_hash
    reads = 0

    def fail_during_confirmation(block: int) -> str:
        nonlocal reads
        if block == substrate.inclusion_block + 1:
            reads += 1
            if reads == 2:
                raise BrokenPipeError("confirmation RPC pipe closed")
        return original(block)

    monkeypatch.setattr(substrate, "get_block_hash", fail_during_confirmation)
    with pytest.raises(
        DirectSubmissionAmbiguous, match="confirmation block 103 hash is unavailable"
    ):
        instance.recover()
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["pending"]["phase"] == "included_awaiting_confirmation"
    assert substrate.sign_calls == 1
    assert substrate.submit_calls == 1

    monkeypatch.setattr(substrate, "get_block_hash", original)
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

    subtensor.substrate.finalized_number = (
        ANCHOR_NUMBER + 1 + SN39_MORTAL_PERIOD_BLOCKS - 1
    )
    receipt = instance.recover()
    assert receipt is not None
    assert receipt.status == STATUS_EXPIRED


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
    )

    assert result["status"] == STATUS_RECOVERED


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
    )

    assert result["status"] == STATUS_CONFIRMED
    assert held[0] is False


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
    monkeypatch.setattr(runtime, "make_subtensor", lambda *_args, **_kwargs: object())
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
                "--once",
                "--confirm-direct-write",
            ]
        )
        == 0
    )
    assert order == ["recover", "ready"]


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
    assert FULL_CYCLE_RESPONSE_DEADLINE_SECONDS < SN39_MORTAL_PERIOD_BLOCKS * 12.0


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
