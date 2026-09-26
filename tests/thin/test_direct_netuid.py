"""The direct validator path carries its netuid explicitly.

This is the first step of making the netuid deploy configuration. Every layer
of the direct path now takes the netuid it was handed instead of reading the
compiled constant, while the command line still refuses any value this release
cannot run. The function-level tests run under two netuids, the compiled one
and the one after it, so a layer that quietly fell back to the constant fails
for the second. No value here is a written-out subnet number: each one is
derived from the compiled constant.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from bittensor.utils import get_mechid_storage_index
from bittensor_wallet import Keypair

from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteIdentityVerdict,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    INTEL_COLLATERAL,
    MAX_NETUID,
    MAX_WEIGHT_LIMIT,
    MECID,
    MIN_ALLOWED_WEIGHTS,
    NETUID,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.errors import BroadcastDisabled
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent.submit import build_mechanism_weights_kwargs
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import failed_write_recovery as record_cli
from cathedral_thin.independent_runtime import fleet_score
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime import updater
from cathedral_thin.independent_runtime.axon import AXON_SKIP_REASONS, ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    DirectSubmissionReceipt,
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
    require_netuid,
)
from cathedral_thin.independent_runtime.direct_validator import (
    build_direct_plan,
    finalized_serving_miners_snapshot,
)
from cathedral_thin.independent_runtime.direct_writer import (
    STATUS_CONFIRMED,
    DirectSubmissionAmbiguous,
    DirectSubmissionContradiction,
    DirectWeightWriter,
    canonical_state_path,
    direct_state_scope,
)
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.fleet_score import MultiComputeRound
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.telemetry import (
    PendingTelemetryStore,
    TelemetryError,
    TelemetrySpool,
    build_telemetry_candidate,
    build_telemetry_snapshot,
    validate_public_telemetry_event,
)
from cathedral_thin.independent_runtime.validator_request import (
    FleetDiscovery,
    SignedValidatorTransport,
    build_validator_request_header,
)
from test_independent_multicompute import (
    BOB,
    WINDOW,
    _NoNetworkHttps,
    _runtime_adapter,
    _runtime_collected,
    _runtime_keypair,
)
from test_independent_validator_request import (
    BINDING,
    NOW,
    PRIMARY,
    StubHttps,
    alice,
    bob,
    decode_header,
)

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy/validator-update/cathedral-validator-direct.service"
OTHER_NETUID = NETUID + 1
NETUIDS = pytest.mark.parametrize(
    "netuid", (NETUID, OTHER_NETUID), ids=("compiled", "next")
)

VALIDATOR = Keypair.create_from_uri("//Alice")
VALIDATOR_UID = 7
MINER = ServingAxon(19, Keypair.create_from_uri("//Bob").ss58_address, "1.1.1.1", 8081)
ANCHOR = 100
FRESH = ANCHOR + 1
INCLUSION = ANCHOR + 2
BLOCKS_SINCE_UPDATE = 100
EXTRINSIC_HASH = "0x" + "c" * 64
CLI_ARGS = (
    "--qvl",
    "/reviewed/qvl",
    "--snp-policy",
    "/reviewed/snp-policy.json",
    "--snpguest",
    "/reviewed/snpguest",
    f"--expected-hotkey={VALIDATOR.ss58_address}",
    "--once",
    "--confirm-direct-write",
)


def block_hash(number: int) -> str:
    return FINNEY_GENESIS_HASH if number == 0 else "0x" + f"{number:064x}"


def _module(name: str, relative: str) -> ModuleType:
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(
        name, path, loader=SourceFileLoader(name, str(path))
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _machine_row() -> dict[str, object]:
    endpoint = f"https://{MINER.ip}:{MINER.port}"
    return {
        "uid": MINER.uid,
        "hotkey": MINER.hotkey,
        "endpoint": endpoint,
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "sat_units": 20,
        "counted_units": 20,
        "channel_id": "channel-" + MINER.hotkey,
        "machine_id": "machine-" + MINER.hotkey,
        "tee_kind": "tdx",
        "phase_timings_ms": {"binding": 1, "evidence": 1, "qvl": 1, "sat": 1},
    }


def _round() -> MultiComputeRound:
    row = _machine_row()
    return MultiComputeRound(
        rows=(row,),
        fleet=(
            {
                "uid": MINER.uid,
                "hotkey": MINER.hotkey,
                "primary": row["endpoint"],
                "ok": True,
                "singleton_compatibility": False,
                "candidate_count": 1,
                "endpoints": [row["endpoint"]],
            },
        ),
        verified_units={MINER.hotkey: 20},
        pass_count=1,
        qvl_infra_count=0,
        feature_blocked=False,
        exclusions=(),
        blockers=(),
    )


def _snapshot(netuid: int) -> FinalizedMetagraphSnapshot:
    return FinalizedMetagraphSnapshot(
        block_number=ANCHOR,
        block_hash=block_hash(ANCHOR),
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR.ss58_address,
        miners=(MINER,),
        skipped_axons={reason: 0 for reason in AXON_SKIP_REASONS},
        netuid=netuid,
    )


def _plan(netuid: int) -> DirectWeightPlan:
    return build_direct_plan(_snapshot(netuid), _round())


def _receipt() -> DirectSubmissionReceipt:
    return DirectSubmissionReceipt(
        status=STATUS_CONFIRMED,
        attempt_id="sha256:" + "e" * 64,
        extrinsic_hash=EXTRINSIC_HASH,
        block_hash=block_hash(INCLUSION),
        block_number=INCLUSION,
        recovered=False,
    )


class WrongSubnet(AssertionError):
    """The code under test touched a subnet other than the one it was given."""


class _Axon:
    def __init__(self, ip: str, port: int, *, serving: bool) -> None:
        self.ip = ip
        self.port = port
        self.is_serving = serving


class _Metagraph:
    def __init__(self, block: int) -> None:
        self.block = block
        self.uids = [VALIDATOR_UID, MINER.uid]
        self.hotkeys = [VALIDATOR.ss58_address, MINER.hotkey]
        self.validator_permit = [True, False]
        self.axons = [
            _Axon("0.0.0.0", 0, serving=False),
            _Axon(MINER.ip, MINER.port, serving=True),
        ]
        self.last_update = [block - BLOCKS_SINCE_UPDATE, 0]
        self.total_stake = [SimpleNamespace(rao=10_000), SimpleNamespace(rao=0)]


class _Substrate:
    def __init__(self, chain: SubnetChain) -> None:
        self.chain = chain
        self.included = False
        self.lose_response = False
        # The library's two wait settings, which the direct validator bounds.
        self.retry_timeout = 60.0
        self.max_retries = 5

    def get_block_hash(self, number: int) -> str:
        return block_hash(number)

    def rpc_request(self, method: str, params: list[object]) -> dict[str, object]:
        # The writer's uncached read of finalized history.
        assert method == "chain_getBlockHash"
        (number,) = params
        return {"result": block_hash(number)}

    def get_chain_finalised_head(self) -> str:
        return block_hash(self.chain.finalized)

    def get_block_number(self, value: str | None) -> int:
        if value is None:
            # The best head, read by the era guard; this fake has no fork.
            return self.chain.finalized
        return 0 if value == FINNEY_GENESIS_HASH else int(value, 16)

    def query(self, *, module, storage_function, params, block_hash):
        del block_hash
        assert module == "SubtensorModule"
        if storage_function == "StakeThreshold":
            return 1_000
        if storage_function == "WeightsVersionKey":
            (netuid,) = params
            self.chain.read(netuid)
            return 0
        assert storage_function == "Weights"
        index, uid = params
        if index != get_mechid_storage_index(self.chain.netuid, MECID):
            raise WrongSubnet(f"weights storage index {index} is another subnet")
        assert uid == VALIDATOR_UID
        return [[MINER.uid, W]] if self.included else []

    def get_account_next_index(self, hotkey: str) -> int:
        assert hotkey == VALIDATOR.ss58_address
        return 4

    def create_signed_extrinsic(self, *, call, keypair, nonce, era):
        assert call == "direct-call" and nonce == 4
        assert keypair.ss58_address == VALIDATOR.ss58_address
        assert era["current"] == FRESH
        self.chain.sign_calls += 1
        return SimpleNamespace(extrinsic_hash=EXTRINSIC_HASH)

    def submit_extrinsic(self, signed, *, wait_for_inclusion, wait_for_finalization):
        assert signed.extrinsic_hash == EXTRINSIC_HASH
        assert wait_for_inclusion is True and wait_for_finalization is True
        if self.lose_response:
            raise TimeoutError("submission response lost")
        self.included = True
        self.chain.finalized = INCLUSION + 2
        return SimpleNamespace(extrinsic_hash=EXTRINSIC_HASH)

    def get_block(self, *, block_hash: str) -> dict[str, object]:
        if not self.included or self.get_block_number(block_hash) != INCLUSION:
            return {"extrinsics": []}
        call_args = [
            {"name": name, "value": value}
            for name, value in self.chain.signed_kwargs.items()
        ]
        return {
            "extrinsics": [
                SimpleNamespace(
                    value={
                        "address": VALIDATOR.ss58_address,
                        "call": {
                            "call_module": "SubtensorModule",
                            "call_function": "set_mechanism_weights",
                            "call_args": call_args,
                        },
                    },
                    extrinsic_hash=EXTRINSIC_HASH,
                )
            ]
        }

    def retrieve_extrinsic_by_hash(self, block_hash: str, extrinsic_hash: str):
        assert self.get_block_number(block_hash) == INCLUSION
        assert extrinsic_hash == EXTRINSIC_HASH
        return SimpleNamespace(is_success=True, error_message=None)


class SubnetChain:
    """One subnet's view of Finney. Touching any other netuid is a failure."""

    def __init__(self, netuid: int) -> None:
        self.netuid = netuid
        self.substrate = _Substrate(self)
        self.finalized = ANCHOR
        self.reads: list[int] = []
        self.sign_calls = 0
        self.signed_kwargs: dict[str, object] = {}

    def read(self, netuid: int) -> None:
        self.reads.append(netuid)
        if netuid != self.netuid:
            raise WrongSubnet(f"read netuid {netuid} on a chain for {self.netuid}")

    def build_call(self, kwargs) -> str:
        self.read(kwargs["netuid"])
        self.signed_kwargs = dict(kwargs)
        return "direct-call"

    def get_block_hash(self, number: int) -> str:
        # bittensor's by-number lookup, which the metagraph read resolves.
        return block_hash(number)

    def metagraph(self, netuid: int, *, block: int) -> _Metagraph:
        self.read(netuid)
        return _Metagraph(block)

    def get_metagraph_info(self, netuid: int, mechid: int, *, block: int):
        self.read(netuid)
        assert mechid == MECID
        graph = _Metagraph(block)
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
            num_uids=size,
            hotkeys=hotkeys,
            validator_permit=permits,
            total_stake=stakes,
        )

    def weights_rate_limit(self, netuid: int, *, block: int) -> int:
        # The validator last wrote exactly one cooldown ago, well past its era.
        self.read(netuid)
        return BLOCKS_SINCE_UPDATE

    def blocks_since_last_update(self, netuid: int, uid: int, *, block: int) -> int:
        self.read(netuid)
        assert uid == VALIDATOR_UID
        return BLOCKS_SINCE_UPDATE

    def min_allowed_weights(self, *, netuid: int, block: int) -> int:
        self.read(netuid)
        return MIN_ALLOWED_WEIGHTS

    def max_weight_limit(self, *, netuid: int, block: int) -> float:
        self.read(netuid)
        return MAX_WEIGHT_LIMIT

    def commit_reveal_enabled(self, *, netuid: int, block: int) -> bool:
        self.read(netuid)
        return COMMIT_REVEAL_ENABLED

    def get_mechanism_count(self, netuid: int, *, block: int) -> int:
        self.read(netuid)
        return MECID + 1


# Journal compatibility -------------------------------------------------------


def test_compiled_netuid_journal_is_byte_identical_to_where_hosts_keep_it() -> None:
    """Existing hosts hold their journal, and the updater its cycle lock, here.

    The updater and the status tool still spell the directory out by hand, so
    they are independent witnesses of the path every earlier release wrote.
    """

    status = _module(
        "cathedral_test_netuid_status",
        "deploy/validator-update/cathedral-validator-status",
    )
    scope = direct_state_scope(NETUID)
    assert scope == updater.DEFAULT_DIRECT_JOURNAL_SCOPE_ROOT.name
    assert scope == status.DIRECT_SCOPE.name

    homes = [
        line.removeprefix("Environment=HOME=")
        for line in UNIT.read_text(encoding="utf-8").splitlines()
        if line.startswith("Environment=HOME=")
    ]
    assert len(homes) == 1
    service_root = Path(homes[0]) / writer_runtime.DIRECT_STATE_ROOT.relative_to(
        Path.home()
    )
    relative = canonical_state_path(VALIDATOR).relative_to(
        writer_runtime.DIRECT_STATE_ROOT
    )
    journal = service_root / relative
    assert os.fsencode(journal) == os.fsencode(
        updater.direct_writer_journal_path(VALIDATOR.ss58_address)
    )
    assert os.fsencode(journal.parent.parent) == os.fsencode(status.DIRECT_SCOPE)


def test_explicit_compiled_netuid_and_no_netuid_share_one_journal(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    implicit = DirectWeightWriter(subtensor=object(), keypair=VALIDATOR)
    explicit = DirectWeightWriter(subtensor=object(), keypair=VALIDATOR, netuid=NETUID)

    assert implicit.netuid == explicit.netuid == NETUID
    assert implicit.state_path == explicit.state_path
    assert implicit.state_path == canonical_state_path(VALIDATOR, netuid=NETUID)


@NETUIDS
def test_journal_scope_changes_only_in_its_netuid(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    compiled = direct_state_scope(NETUID)
    assert direct_state_scope(netuid) == compiled.replace(
        f"sn{NETUID}-", f"sn{netuid}-", 1
    )
    writer = DirectWeightWriter(subtensor=object(), keypair=VALIDATOR, netuid=netuid)

    assert writer.netuid == netuid
    assert writer.state_path == (
        tmp_path / direct_state_scope(netuid) / VALIDATOR.ss58_address / "state.json"
    )
    assert writer.state_path == canonical_state_path(VALIDATOR, netuid=netuid)


@pytest.mark.parametrize(
    "value",
    (True, -(NETUID + 1), MAX_NETUID + 1, str(NETUID), float(NETUID)),
    ids=("bool", "negative", "past-u16", "string", "float"),
)
def test_every_layer_refuses_a_value_that_cannot_name_a_subnet(value) -> None:
    with pytest.raises(DirectValidatorError, match="netuid"):
        require_netuid(value)
    with pytest.raises(DirectValidatorError, match="netuid"):
        direct_state_scope(value)
    with pytest.raises(DirectValidatorError, match="netuid"):
        DirectWeightWriter(subtensor=object(), keypair=VALIDATOR, netuid=value)
    # Refused before the genesis read, which object() could not answer.
    with pytest.raises(DirectValidatorError, match="netuid"):
        finalized_serving_miners_snapshot(object(), VALIDATOR, value)
    with pytest.raises(IndependentLiveError, match="netuid"):
        fleet_score.score_multicompute_round(
            axons=(MINER,),
            keypair=_runtime_keypair(),
            anchor_hash=WINDOW,
            verifier_adapter=_runtime_adapter(),
            netuid=value,
        )
    with pytest.raises(BroadcastDisabled):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=value, expected_netuid=value
        )


# Submit layer ----------------------------------------------------------------


@NETUIDS
def test_call_kwargs_name_the_netuid_they_were_given(netuid: int) -> None:
    assert build_mechanism_weights_kwargs(
        dests=[MINER.uid], weights=[W], netuid=netuid, expected_netuid=netuid
    ) == {
        "netuid": netuid,
        "mecid": MECID,
        "dests": [MINER.uid],
        "weights": [W],
        "version_key": VERSION_KEY,
    }


@NETUIDS
def test_submit_refuses_a_call_for_another_netuid_than_its_signer(netuid: int) -> None:
    other = netuid + 1
    with pytest.raises(BroadcastDisabled, match="composes for netuid"):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=other, expected_netuid=netuid
        )
    with pytest.raises(BroadcastDisabled, match="composes for netuid"):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=netuid, expected_netuid=other
        )


def test_submit_refuses_a_bool_even_where_it_equals_the_expected_netuid() -> None:
    with pytest.raises(BroadcastDisabled):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=True, expected_netuid=int(True)
        )
    with pytest.raises(BroadcastDisabled):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=int(True), expected_netuid=True
        )


def test_callers_that_pass_no_netuid_stay_pinned_to_the_compiled_one() -> None:
    kwargs = build_mechanism_weights_kwargs(dests=[MINER.uid], weights=[W])
    assert kwargs["netuid"] == NETUID
    with pytest.raises(BroadcastDisabled):
        build_mechanism_weights_kwargs(
            dests=[MINER.uid], weights=[W], netuid=OTHER_NETUID
        )


# Snapshot and plan -----------------------------------------------------------


@NETUIDS
def test_snapshot_reads_the_metagraph_of_the_netuid_it_was_given(netuid: int) -> None:
    chain = SubnetChain(netuid)

    observed = finalized_serving_miners_snapshot(chain, VALIDATOR, netuid)

    assert observed.netuid == netuid
    assert observed.miners == (MINER,)
    assert chain.reads == [netuid]


@NETUIDS
def test_plan_takes_its_netuid_from_the_snapshot_it_was_built_on(netuid: int) -> None:
    plan = _plan(netuid)

    assert plan.netuid == netuid
    assert plan.kwargs()["netuid"] == netuid
    assert plan.identity()["kwargs"]["netuid"] == netuid


def test_netuid_changes_nothing_in_a_plan_identity_but_its_call() -> None:
    compiled, other = _plan(NETUID), _plan(OTHER_NETUID)

    assert compiled.snapshot.identity() == other.snapshot.identity()
    assert compiled.evidence_digest == other.evidence_digest
    compiled_identity, other_identity = compiled.identity(), other.identity()
    assert compiled_identity["kwargs"].pop("netuid") == NETUID
    assert other_identity["kwargs"].pop("netuid") == OTHER_NETUID
    assert compiled_identity == other_identity


# Writer ----------------------------------------------------------------------


@NETUIDS
def test_writer_signs_confirms_and_journals_only_on_its_own_netuid(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    chain = SubnetChain(netuid)
    plan = build_direct_plan(
        finalized_serving_miners_snapshot(chain, VALIDATOR, netuid), _round()
    )
    chain.finalized = FRESH
    # The default snapshot reader is used, so the fresh read is the writer's.
    writer = DirectWeightWriter(
        subtensor=chain,
        keypair=VALIDATOR,
        call_builder=chain.build_call,
        netuid=netuid,
    )

    receipt = writer.submit(plan, cycle_deadline_monotonic=time.monotonic() + 600.0)

    assert receipt.status == STATUS_CONFIRMED
    assert chain.sign_calls == 1
    assert chain.signed_kwargs == plan.kwargs()
    assert chain.signed_kwargs["netuid"] == netuid
    assert chain.reads and set(chain.reads) == {netuid}
    assert writer.state_path.parent.parent.name == direct_state_scope(netuid)
    state = json.loads(writer.state_path.read_text(encoding="ascii"))
    assert state["pending"] is None
    assert state["last_attempt"]["intent"]["kwargs"]["netuid"] == netuid
    assert state["last_attempt"]["identity"]["kwargs"]["netuid"] == netuid
    assert writer.recover() is None


@NETUIDS
def test_writer_refuses_a_plan_read_on_another_netuid_before_any_chain_access(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    writer = DirectWeightWriter(subtensor=object(), keypair=VALIDATOR, netuid=netuid)

    with pytest.raises(DirectValidatorError, match="another netuid"):
        writer.submit(
            _plan(netuid + 1), cycle_deadline_monotonic=time.monotonic() + 600.0
        )
    assert not writer.state_path.parent.exists()


@NETUIDS
def test_writer_refuses_a_fresh_snapshot_from_another_netuid_before_signing(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    chain = SubnetChain(netuid)
    plan = build_direct_plan(
        finalized_serving_miners_snapshot(chain, VALIDATOR, netuid), _round()
    )
    chain.finalized = FRESH
    fresh = finalized_serving_miners_snapshot(chain, VALIDATOR, netuid)
    writer = DirectWeightWriter(
        subtensor=chain,
        keypair=VALIDATOR,
        snapshot_reader=lambda _subtensor, _keypair: replace(fresh, netuid=netuid + 1),
        call_builder=chain.build_call,
        netuid=netuid,
    )

    with pytest.raises(DirectValidatorError, match="another netuid than the plan"):
        writer.submit(plan, cycle_deadline_monotonic=time.monotonic() + 600.0)
    assert chain.sign_calls == 0


@NETUIDS
def test_recovery_treats_an_intent_for_another_netuid_as_a_contradiction(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    """Why the netuid may only change while the journal is idle."""

    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    foreign = netuid + 1
    chain = SubnetChain(foreign)
    plan = build_direct_plan(
        finalized_serving_miners_snapshot(chain, VALIDATOR, foreign), _round()
    )
    chain.finalized = FRESH
    chain.substrate.lose_response = True
    signer = DirectWeightWriter(
        subtensor=chain,
        keypair=VALIDATOR,
        call_builder=chain.build_call,
        netuid=foreign,
    )
    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        signer.submit(plan, cycle_deadline_monotonic=time.monotonic() + 600.0)

    # The same journal bytes under this writer's scope: an intent that was
    # signed for another subnet and is still unresolved.
    writer = DirectWeightWriter(subtensor=object(), keypair=VALIDATOR, netuid=netuid)
    writer.state_path.parent.mkdir(mode=0o700, parents=True)
    writer.state_path.write_bytes(signer.state_path.read_bytes())
    writer.state_path.chmod(0o600)

    # object() has no chain: the refusal comes before any finalized-history read.
    with pytest.raises(DirectSubmissionContradiction, match="intent is invalid"):
        writer.recover()


# Signed requests -------------------------------------------------------------


@NETUIDS
def test_request_header_names_the_netuid_it_was_given(netuid: int) -> None:
    header = build_validator_request_header(
        keypair=alice(),
        worker_hotkey=bob().ss58_address,
        method="POST",
        path="/v1/sat-work",
        body=b"{}",
        channel_binding=BINDING,
        nonce=b"n" * 32,
        issued_at=NOW,
        expires_at=NOW.replace(second=59),
        netuid=netuid,
    )

    assert decode_header(header)["netuid"] == netuid


@NETUIDS
def test_signed_transport_signs_every_post_for_its_netuid(netuid: int) -> None:
    base = StubHttps(200, b"{}")
    transport = SignedValidatorTransport(
        base,
        keypair=alice(),
        worker_hotkey=bob().ss58_address,
        clock=lambda: NOW,
        nonce_factory=lambda size: b"n" * size,
        netuid=netuid,
    )

    transport.post(PRIMARY + "/v1/sat-work", {})

    ((_url, _body, header),) = base.authorized
    assert decode_header(header)["netuid"] == netuid


@NETUIDS
def test_scoring_round_hands_its_netuid_to_every_signed_request(
    monkeypatch, netuid: int
) -> None:
    seen: list[tuple[str, int]] = []
    root = "https://1.1.1.1:8081"

    def collect(*, evidence_url, sat_url, hotkey, validator_ss58, keypair, netuid):
        del evidence_url, sat_url, validator_ss58, keypair
        seen.append(("evidence", netuid))
        return {
            "hotkey": hotkey,
            "sat_url": root + "/v1/sat-work",
            "collected": _runtime_collected(hotkey, marker=1, spki=b"a" * 32),
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        seen.append(("fleet", transport.netuid))
        return FleetDiscovery(worker_hotkey, (primary_origin,), False)

    def units(*, anchor_hash, collected, sat_url, keypair, netuid):
        del anchor_hash, collected, sat_url, keypair
        seen.append(("sat", netuid))
        return 20

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)

    result = fleet_score.score_multicompute_round(
        axons=(ServingAxon(8, BOB, "1.1.1.1", 8081),),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_runtime_adapter(),
        netuid=netuid,
    )

    assert seen == [("evidence", netuid), ("fleet", netuid), ("sat", netuid)]
    assert result.verified_units == {BOB: 20}


class _PerMachineVerifier:
    """QVL double that passes each quote with the platform its marker names."""

    def verify(self, quote, *, expected_report_data):
        del quote, expected_report_data
        return QuoteVerdict.PASS

    def verify_with_identity(
        self, quote, *, expected_report_data, deadline_monotonic=None
    ):
        del expected_report_data, deadline_monotonic
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS, "tdx-platform-sha256:" + f"{quote[-1]:064x}", True
        )


@NETUIDS
@pytest.mark.parametrize("bounded", (False, True), ids=("unbounded", "bounded"))
def test_scoring_round_challenges_every_fleet_machine_for_its_netuid(
    monkeypatch, netuid: int, bounded: bool
) -> None:
    """A declared fleet machine is challenged for the round's netuid too.

    The chain axon's requests alone would not show it: the fleet loop builds
    each further machine's evidence request itself, in the bounded worker and
    in the unbounded preview path alike.
    """

    seen: list[tuple[str, str, int]] = []
    root = "https://1.1.1.1:8081"
    second = "https://8.8.8.8:8081"
    evidence = {
        root: _runtime_collected(BOB, marker=1, spki=b"a" * 32),
        second: _runtime_collected(BOB, marker=2, spki=b"b" * 32),
    }

    def collect(
        *,
        evidence_url,
        sat_url,
        hotkey,
        validator_ss58,
        keypair,
        netuid,
        deadline_monotonic=None,
    ):
        del sat_url, validator_ss58, keypair, deadline_monotonic
        endpoint = evidence_url.removesuffix("/v1/evidence")
        seen.append(("evidence", endpoint, netuid))
        return {
            "hotkey": hotkey,
            "sat_url": endpoint + "/v1/sat-work",
            "collected": evidence[endpoint],
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        seen.append(("fleet", primary_origin, transport.netuid))
        return FleetDiscovery(worker_hotkey, (primary_origin, second), False)

    def units(
        *, anchor_hash, collected, sat_url, keypair, netuid, deadline_monotonic=None
    ):
        del anchor_hash, collected, keypair, deadline_monotonic
        seen.append(("sat", sat_url.removesuffix("/v1/sat-work"), netuid))
        return 20

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)

    result = fleet_score.score_multicompute_round(
        axons=(ServingAxon(8, BOB, "1.1.1.1", 8081),),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=ComputeAdapter(
            _PerMachineVerifier(),
            collateral_base_url=INTEL_COLLATERAL,
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST,
        ),
        cycle_deadline_monotonic=time.monotonic() + 600.0 if bounded else None,
        netuid=netuid,
    )

    assert result.verified_units == {BOB: 40}
    assert sorted(seen) == sorted(
        [
            ("evidence", root, netuid),
            ("fleet", root, netuid),
            ("evidence", second, netuid),
            ("sat", root, netuid),
            ("sat", second, netuid),
        ]
    )


class _RefusingHttps(HttpsEvidenceTransport):
    def observe_binding(self, url: str):
        del url
        raise IndependentLiveError("no network in this test")


@NETUIDS
def test_fleet_helpers_build_their_signed_transports_for_their_netuid(
    monkeypatch, netuid: int
) -> None:
    built: list[int] = []
    signed_transport = fleet_score.SignedValidatorTransport

    def recording(*args, **kwargs):
        transport = signed_transport(*args, **kwargs)
        built.append(transport.netuid)
        return transport

    monkeypatch.setattr(fleet_score, "SignedValidatorTransport", recording)
    monkeypatch.setattr(fleet_score, "_transport", lambda _deadline: _RefusingHttps())

    row = fleet_score._try_collect(
        evidence_url=PRIMARY + "/v1/evidence",
        sat_url=PRIMARY + "/v1/sat-work",
        hotkey=BOB,
        validator_ss58=_runtime_keypair().ss58_address,
        keypair=_runtime_keypair(),
        netuid=netuid,
    )
    assert row["ok"] is False
    with pytest.raises(Exception, match="no network in this test"):
        fleet_score._units_after_quote(
            anchor_hash=WINDOW,
            collected=_runtime_collected(BOB, marker=1, spki=b"a" * 32),
            sat_url=PRIMARY + "/v1/sat-work",
            keypair=_runtime_keypair(),
            netuid=netuid,
        )
    assert built == [netuid, netuid]


# Telemetry -------------------------------------------------------------------


@NETUIDS
def test_telemetry_names_the_plan_netuid_and_a_spool_refuses_any_other(
    tmp_path: Path, netuid: int
) -> None:
    event = build_telemetry_snapshot(
        result_rows=(_machine_row(),),
        plan=_plan(netuid),
        receipt=_receipt(),
        keypair=VALIDATOR,
    )

    assert event["netuid"] == netuid
    assert validate_public_telemetry_event(event, netuid=netuid) == event
    with pytest.raises(TelemetryError, match="identity is invalid"):
        validate_public_telemetry_event(event, netuid=netuid + 1)
    TelemetrySpool(tmp_path / "own" / "events.jsonl", netuid=netuid).append(event)
    with pytest.raises(TelemetryError, match="identity is invalid"):
        TelemetrySpool(tmp_path / "other" / "events.jsonl", netuid=netuid + 1).append(
            event
        )


@NETUIDS
def test_pending_telemetry_is_bound_to_its_spool_netuid(
    tmp_path: Path, netuid: int
) -> None:
    plan = _plan(netuid)
    candidate = build_telemetry_candidate(result_rows=(_machine_row(),), plan=plan)
    assert candidate["netuid"] == netuid

    own = PendingTelemetryStore(
        TelemetrySpool(tmp_path / "own" / "events.jsonl", netuid=netuid)
    )
    own.prepare(candidate, plan, _receipt())
    event = own.finalize(keypair=VALIDATOR)
    assert event is not None and event["netuid"] == netuid

    other = PendingTelemetryStore(
        TelemetrySpool(tmp_path / "other" / "events.jsonl", netuid=netuid + 1)
    )
    with pytest.raises(TelemetryError, match="another netuid"):
        other.prepare(candidate, plan, _receipt())
    assert not other.path.exists()


# Full cycle ------------------------------------------------------------------


class _PlatformVerifier:
    """QVL double that passes every quote with one stable platform identity."""

    def verify(self, quote, *, expected_report_data):
        del quote, expected_report_data
        return QuoteVerdict.PASS

    def verify_with_identity(
        self, quote, *, expected_report_data, deadline_monotonic=None
    ):
        del quote, expected_report_data, deadline_monotonic
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS, "tdx-platform-sha256:" + "1" * 64, True
        )


def _direct_adapter() -> ComputeAdapter:
    return ComputeAdapter(
        _PlatformVerifier(),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST,
    )


def no_expired_recovery(event: dict[str, object]) -> None:
    pytest.fail(f"cycle reported an unexpected expired recovery: {event}")


@NETUIDS
def test_cycle_reads_challenges_and_writes_on_one_netuid(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    """One cycle through the real scoring round and the real writer.

    The chain answers for one subnet only, and every signed miner request
    records the netuid it was built for. A cycle that dropped its netuid on the
    way to the snapshot or to the scoring round fails the "next" case.
    """

    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    chain = SubnetChain(netuid)
    root = f"https://{MINER.ip}:{MINER.port}"
    requests: list[tuple[str, int]] = []

    def collect(
        *,
        evidence_url,
        sat_url,
        hotkey,
        validator_ss58,
        keypair,
        netuid,
        deadline_monotonic,
    ):
        del evidence_url, sat_url, validator_ss58, keypair, deadline_monotonic
        requests.append(("evidence", netuid))
        return {
            "hotkey": hotkey,
            "sat_url": root + "/v1/sat-work",
            "collected": _runtime_collected(hotkey, marker=1, spki=b"a" * 32),
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        requests.append(("fleet", transport.netuid))
        return FleetDiscovery(worker_hotkey, (primary_origin,), False)

    def units(*, anchor_hash, collected, sat_url, keypair, netuid, deadline_monotonic):
        del anchor_hash, collected, sat_url, keypair, deadline_monotonic
        requests.append(("sat", netuid))
        # The chain finalizes one more block while the miner is being scored.
        chain.finalized = FRESH
        return 20

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)
    writer = DirectWeightWriter(
        subtensor=chain,
        keypair=VALIDATOR,
        call_builder=chain.build_call,
        netuid=netuid,
    )

    event = runtime.run_direct_cycle(
        subtensor=chain,
        keypair=VALIDATOR,
        verifier_adapter=_direct_adapter(),
        writer=writer,
        report_recovery=no_expired_recovery,
        netuid=netuid,
    )

    assert event["status"] == STATUS_CONFIRMED
    assert event["wire_uids"] == [MINER.uid]
    assert requests == [("evidence", netuid), ("fleet", netuid), ("sat", netuid)]
    assert chain.reads and set(chain.reads) == {netuid}
    assert chain.signed_kwargs["netuid"] == netuid


@NETUIDS
def test_cycle_refuses_a_writer_for_another_netuid_before_recovery_or_any_miner(
    tmp_path: Path, monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: pytest.fail("the chain was read for a mismatched writer"),
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: pytest.fail("miners were challenged for a mismatched writer"),
    )
    installed = DirectWeightWriter(
        subtensor=object(), keypair=VALIDATOR, netuid=netuid + 1
    )
    double = SimpleNamespace(
        netuid=netuid + 1,
        recover=lambda: pytest.fail("recovery ran for a mismatched writer"),
    )

    for writer in (installed, double):
        with pytest.raises(
            DirectValidatorError, match="another netuid than this cycle"
        ):
            runtime.run_direct_cycle(
                subtensor=object(),
                keypair=VALIDATOR,
                verifier_adapter=_direct_adapter(),
                writer=writer,
                report_recovery=no_expired_recovery,
                netuid=netuid,
            )
    assert not installed.state_path.parent.exists()


def test_cycle_refuses_a_writer_whose_netuid_is_a_bool() -> None:
    writer = SimpleNamespace(
        netuid=True, recover=lambda: pytest.fail("recovery ran for a bool netuid")
    )

    with pytest.raises(DirectValidatorError, match="another netuid than this cycle"):
        runtime.run_direct_cycle(
            subtensor=object(),
            keypair=VALIDATOR,
            verifier_adapter=_direct_adapter(),
            writer=writer,
            report_recovery=no_expired_recovery,
            netuid=int(True),
        )


@NETUIDS
def test_cycle_refuses_a_snapshot_from_another_netuid_before_any_miner(
    monkeypatch, netuid: int
) -> None:
    monkeypatch.setattr(
        runtime,
        "finalized_serving_miners_snapshot",
        lambda *_args: _snapshot(netuid + 1),
    )
    monkeypatch.setattr(
        runtime,
        "score_multicompute_round",
        lambda **_kwargs: pytest.fail("miners were challenged for another netuid"),
    )
    writer = SimpleNamespace(
        netuid=netuid,
        recover=lambda: None,
        submit=lambda *_args, **_kwargs: pytest.fail("a foreign plan reached submit"),
    )

    with pytest.raises(DirectValidatorError, match="snapshot was read on another"):
        runtime.run_direct_cycle(
            subtensor=object(),
            keypair=VALIDATOR,
            verifier_adapter=_direct_adapter(),
            writer=writer,
            report_recovery=no_expired_recovery,
            netuid=netuid,
        )


# Command line ----------------------------------------------------------------


def _stub_cli(monkeypatch, tmp_path: Path, seen: dict[str, int]) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
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
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=VALIDATOR),
    )
    # The validator bounds the client's two RPC wait settings before recovery.
    monkeypatch.setattr(
        runtime,
        "make_subtensor",
        lambda *_args, **_kwargs: SimpleNamespace(
            substrate=SimpleNamespace(retry_timeout=60.0, max_retries=5)
        ),
    )
    monkeypatch.setattr(
        runtime.grp, "getgrnam", lambda _group: SimpleNamespace(gr_gid=os.getegid())
    )

    def writer(**kwargs):
        seen["writer"] = kwargs["netuid"]
        return SimpleNamespace(recover=lambda: None)

    def spool(path, *, reader_gid, netuid):
        del reader_gid
        seen["spool"] = netuid
        return SimpleNamespace(path=path, reader_gid=None, netuid=netuid)

    def cycle(**kwargs):
        seen["cycle"] = kwargs["netuid"]
        return {"status": STATUS_CONFIRMED}

    monkeypatch.setattr(writer_runtime, "DirectWeightWriter", writer)
    monkeypatch.setattr(runtime, "TelemetrySpool", spool)
    monkeypatch.setattr(runtime, "run_direct_cycle", cycle)


@pytest.mark.parametrize(
    "flag",
    ((), (f"--netuid={NETUID}",), ("--netuid", str(NETUID))),
    ids=("absent", "equals-compiled", "separate-compiled"),
)
def test_cli_runs_the_compiled_netuid_when_the_flag_is_absent_or_equal(
    tmp_path: Path, monkeypatch, flag: tuple[str, ...]
) -> None:
    seen: dict[str, int] = {}
    _stub_cli(monkeypatch, tmp_path, seen)

    assert (
        runtime.main(
            [
                *CLI_ARGS,
                f"--telemetry-spool={tmp_path / 'telemetry' / 'events.jsonl'}",
                "--telemetry-reader-group=cathedral-telemetry",
                *flag,
            ]
        )
        == 0
    )
    assert seen == {"writer": NETUID, "spool": NETUID, "cycle": NETUID}


def _refuse_any_runtime_work(monkeypatch) -> None:
    for name in ("load_direct_validator_verifier", "make_wallet", "make_subtensor"):
        monkeypatch.setattr(
            runtime,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"{_name} ran before the netuid gate"
            ),
        )


def test_cli_refuses_another_netuid_before_any_verifier_wallet_or_chain(
    monkeypatch,
) -> None:
    _refuse_any_runtime_work(monkeypatch)

    with pytest.raises(SystemExit) as refused:
        runtime.main([*CLI_ARGS, f"--netuid={OTHER_NETUID}"])

    # A message, not an integer: the interpreter exits with status 1, which the
    # unit restarts, like every other configuration refusal in main().
    message = refused.value.code
    assert isinstance(message, str)
    assert message.startswith(
        f"--netuid {OTHER_NETUID} is not the netuid this release was built for "
        f"({NETUID}); non-default netuids arrive with a later release"
    )


@pytest.mark.parametrize(
    "value",
    (
        "",
        "netuid",
        f"+{NETUID}",
        f"-{NETUID}",
        f" {NETUID}",
        f"0{NETUID}",
        f"{NETUID}.0",
        str(MAX_NETUID + 1),
        "".join(chr(0x0660 + int(digit)) for digit in str(NETUID)),
    ),
    ids=(
        "empty",
        "word",
        "plus",
        "minus",
        "space",
        "leading-zero",
        "decimal-point",
        "past-u16",
        "non-ascii-digits",
    ),
)
def test_cli_refuses_a_malformed_netuid_as_configuration(
    monkeypatch, value: str
) -> None:
    _refuse_any_runtime_work(monkeypatch)

    with pytest.raises(SystemExit, match="canonical decimal u16") as refused:
        runtime.main([*CLI_ARGS, f"--netuid={value}"])
    assert isinstance(refused.value.code, str)


def test_cli_refuses_a_repeated_netuid(monkeypatch) -> None:
    _refuse_any_runtime_work(monkeypatch)

    with pytest.raises(SystemExit, match="only once") as refused:
        runtime.main([*CLI_ARGS, f"--netuid={NETUID}", f"--netuid={NETUID}"])
    assert isinstance(refused.value.code, str)


RECORD_ARGS = (
    runtime.RECORD_FAILED_WRITE_COMMAND,
    f"--expected-hotkey={VALIDATOR.ss58_address}",
)


@pytest.mark.parametrize(
    "flag",
    ((), (f"--netuid={NETUID}",), ("--netuid", str(NETUID))),
    ids=("absent", "equals-compiled", "separate-compiled"),
)
def test_record_command_hands_the_configured_netuid_to_its_writer(
    monkeypatch, capsys, flag: tuple[str, ...]
) -> None:
    """The record command finds the journal the validator's writer keeps.

    It takes ``--netuid`` exactly as the validator does, so the writer it
    proves and records with is scoped to the same subnet.
    """

    seen: list[int] = []

    class Writer:
        def __init__(self, *, subtensor, keypair, netuid) -> None:
            del subtensor
            assert keypair.ss58_address == VALIDATOR.ss58_address
            seen.append(netuid)

        def record_finalized_failure(self) -> dict[str, object]:
            return {}

    monkeypatch.setattr(
        record_cli,
        "make_subtensor",
        lambda *_args, **_kwargs: SimpleNamespace(
            substrate=SimpleNamespace(retry_timeout=60.0, max_retries=5)
        ),
    )
    monkeypatch.setattr(record_cli, "DirectWeightWriter", Writer)

    assert runtime.main([*RECORD_ARGS, *flag]) == record_cli.EXIT_RECORDED
    assert seen == [NETUID]
    assert json.loads(capsys.readouterr().out)["status"] == record_cli.STATUS_RECORDED


@pytest.mark.parametrize(
    ("value", "message"),
    (
        (str(OTHER_NETUID), "not the netuid this release was built for"),
        (f"0{NETUID}", "canonical decimal u16"),
    ),
    ids=("another", "malformed"),
)
def test_record_command_refuses_another_netuid_before_chain_access(
    monkeypatch, value: str, message: str
) -> None:
    monkeypatch.setattr(
        record_cli,
        "make_subtensor",
        lambda *_args, **_kwargs: pytest.fail("record command reached the chain"),
    )

    with pytest.raises(SystemExit, match=message) as refused:
        runtime.main([*RECORD_ARGS, f"--netuid={value}"])
    assert isinstance(refused.value.code, str)


def test_refused_netuid_exits_with_the_restartable_status_not_the_argparse_one() -> (
    None
):
    """The unit never restarts status 2, so a configuration refusal avoids it."""

    assert "RestartPreventExitStatus=2" in UNIT.read_text(encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "from cathedral_thin.independent_runtime.direct_validator import main\n"
            "sys.exit(main(sys.argv[1:]))\n",
            *CLI_ARGS,
            f"--netuid={OTHER_NETUID}",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 1, completed.stderr
    assert "non-default netuids arrive with a later release" in completed.stderr


def test_telemetry_arguments_file_warns_against_carrying_the_netuid() -> None:
    """That file reaches the command line even after a rollback to a runtime
    that would exit 2 on the flag, so it must never carry it."""

    example = (ROOT / "deploy/validator-update/direct-telemetry.env.example").read_text(
        encoding="utf-8"
    )
    lines = example.splitlines()
    settings = [line for line in lines if line and not line.startswith("#")]
    assert len(settings) == 1
    assert settings[0].startswith("CATHEDRAL_VALIDATOR_TELEMETRY_ARGS=")
    assert "--netuid" not in settings[0]
    comments = " ".join(line.lstrip("# ") for line in lines if line.startswith("#"))
    assert "Never add --netuid here" in comments
    assert "status 2" in comments
