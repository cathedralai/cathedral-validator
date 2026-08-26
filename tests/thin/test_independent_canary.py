"""The one-write canary fires only on COMPOSED with a funded Compute row.

Four separate claims:

1. a synthetic ``COMPOSED`` vector with a funded Compute row, the dedicated
   canary hotkey, matching u16 kwargs, and an injected transport submits
   exactly once and records an opaque receipt on ``independent-canary.json``;
2. burn-only ``DEGRADED`` and a funded Compute row that is still
   ``BROADCAST_BLOCKED`` are ineligible, so the transport is never called;
3. a real compose that binds pinned-QVL verified mass is ``COMPOSED`` and CAN
   spend the slot through the injected transport;
4. the live relay identity, the burn destination, a permitted-but-not-canary
   hotkey, a missing transport, a u16 mismatch, and a second call are all
   refusals, and nothing on this path opens a socket or names a chain writer.

Treating burn-only as the first on-chain write is still forbidden.
"""

from __future__ import annotations

import json
import os
import socket
import stat
from pathlib import Path

import pytest

from _independent_fixtures import (
    ALICE,
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    COMPUTE_LANE,
    CYBERGYM_LANE,
    EPOCH_OPEN,
    burn_only_view,
    commitment_for,
    economics_document,
    lane_row,
    signed_bundle,
)
from cathedral_thin.independent import canary as canary_module
from cathedral_thin.independent.canary import (
    CanaryReceipt,
    load_canary_state,
    require_canary_hotkey,
    submit_canary_once,
)
from cathedral_thin.independent.compose import (
    STATUS_BROADCAST_BLOCKED,
    STATUS_COMPOSED,
    STATUS_DEGRADED,
    ComposeResult,
    EpochAnchor,
    compose_dry_run,
)
from cathedral_thin.independent.compute import ComputeAdapter
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    CANARY_HOTKEY,
    H,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    NETUID,
    REFUSE_HOTKEYS,
    W,
)
from cathedral_thin.independent.errors import (
    BroadcastDisabled,
    CanaryIneligible,
    CanarySpent,
    CanaryStateError,
    CanaryTransportError,
    RefuseListError,
)
from cathedral_thin.independent.hamilton import HamiltonResult
from cathedral_thin.independent.inclusion import InclusionOutcome, MetagraphView
from cathedral_thin.independent.policy import LaneContractId
from cathedral_thin.independent.submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
    prepare_mechanism_weights,
)
from test_independent_compute import MockQuoteVerifier

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)

MINER_UID = 7
PAYABLE_WEIGHTS = (32767, 32768)
PAYABLE_DESTS = (MINER_UID, BURN_UID)
RECEIPT = "0x" + "ab" * 16


class FakeTransport:
    """Records the kwargs it was asked to submit and returns a canned receipt."""

    def __init__(self, receipt: str = RECEIPT) -> None:
        self.calls: list[dict] = []
        self.receipt = receipt
        self.error: BaseException | None = None

    def submit_mechanism_weights(self, kwargs):
        self.calls.append(dict(kwargs))
        if self.error is not None:
            raise self.error
        return self.receipt


def canary_path(tmp_path) -> Path:
    return tmp_path / INDEPENDENT_CANARY_FILE.name


def journal_path(tmp_path) -> Path:
    return tmp_path / INDEPENDENT_STATE_FILE.name


def funded_compute_bundle():
    economics = economics_document(
        burn_amount=H - 10**11,
        allocations=[lane_row(COMPUTE_LANE, 10**11)],
        explicit_burn_only=False,
    )
    return signed_bundle(economics=economics)


def funded_cybergym_bundle():
    economics = economics_document(
        burn_amount=H - 10**11,
        allocations=[lane_row(CYBERGYM_LANE, 10**11)],
        explicit_burn_only=False,
    )
    return signed_bundle(economics=economics)


def synthetic_composed(
    *,
    dests=PAYABLE_DESTS,
    weights=PAYABLE_WEIGHTS,
    status=STATUS_COMPOSED,
    blocks=(),
    burn_uid=BURN_UID,
):
    """A ComposeResult that did not come from compose_dry_run.

    Real compose emits COMPOSED when a contributing Compute adapter binds
    pinned-QVL verified mass. The gate is also testable from a synthetic
    payable mix so the one-write lock can be proven without a live machine.
    """
    return ComposeResult(
        status=status,
        dests=dests,
        weights=weights,
        reason="synthetic payable mix for canary tests",
        broadcast_eligible=False,
        blocks=blocks,
        inclusion=InclusionOutcome(
            dests=(),
            forfeits=(),
            burn_uid=burn_uid,
            burn_mass=H // 2,
            degraded=False,
            reason="",
        ),
        hamilton=HamiltonResult(
            dests=dests,
            weights=weights,
            masses={uid: 1 for uid in dests},
            base={uid: 1 for uid in dests},
            rem={uid: 0 for uid in dests},
            remainder_bonuses=0,
        ),
        record={"netuid": NETUID, "status": status, "broadcast": False},
        journal_path=None,
    )


def run_canary(
    tmp_path,
    *,
    result=None,
    kwargs=None,
    bundle=None,
    hotkey=None,
    transport=None,
):
    if bundle is None:
        bundle, _registry = funded_compute_bundle()
    if result is None:
        result = synthetic_composed()
    if kwargs is None:
        kwargs = build_mechanism_weights_kwargs(
            dests=result.dests, weights=result.weights
        )
    if hotkey is None:
        hotkey = CANARY_HOTKEY
    if transport is None:
        transport = FakeTransport()
    return (
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=hotkey,
            transport=transport,
            state_path=canary_path(tmp_path),
        ),
        transport,
    )


def compose_real(tmp_path, bundle, registry, **kwargs):
    params = dict(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=journal_path(tmp_path),
    )
    params.update(kwargs)
    return compose_dry_run(**params)


def test_the_dedicated_canary_hotkey_is_bob_and_is_not_refused():
    assert CANARY_HOTKEY == BOB
    assert CANARY_HOTKEY not in REFUSE_HOTKEYS
    assert require_canary_hotkey(CANARY_HOTKEY) == CANARY_HOTKEY


def test_a_synthetic_composed_vector_submits_once_through_the_transport(tmp_path):
    receipt, transport = run_canary(tmp_path)
    assert isinstance(receipt, CanaryReceipt)
    assert receipt.hotkey == CANARY_HOTKEY
    assert receipt.call == MECHANISM_WEIGHTS_CALL
    assert receipt.receipt == RECEIPT
    assert receipt.kwargs == {
        "netuid": 39,
        "mecid": 0,
        "dests": [MINER_UID, BURN_UID],
        "weights": [32767, 32768],
        "version_key": 10005000,
    }
    assert transport.calls == [dict(receipt.kwargs)]

    record = load_canary_state(canary_path(tmp_path))
    assert record["lineage"] == "independent_v1"
    assert record["kind"] == "canary"
    assert record["status"] == "submitted"
    assert record["broadcast"] is False
    assert record["hotkey"] == CANARY_HOTKEY
    assert record["call"] == MECHANISM_WEIGHTS_CALL
    assert record["kwargs"] == receipt.kwargs
    assert record["receipt"] == RECEIPT
    for field in ("signed_vector", "signature", "extrinsic"):
        assert field not in record
    assert not (tmp_path / INDEPENDENT_STATE_FILE.name).exists()


def test_a_second_call_is_spent_and_does_not_touch_the_transport(tmp_path):
    first, _transport = run_canary(tmp_path)
    transport = FakeTransport()
    with pytest.raises(CanarySpent, match="already spent"):
        run_canary(tmp_path, transport=transport)
    assert transport.calls == []
    assert load_canary_state(canary_path(tmp_path))["receipt"] == first.receipt


def test_a_real_burn_only_compose_cannot_be_the_canary(tmp_path):
    bundle, registry = signed_bundle()
    result = compose_real(tmp_path, bundle, registry)
    assert result.status == STATUS_DEGRADED
    kwargs = prepare_mechanism_weights(
        result=result, journal_path=journal_path(tmp_path)
    )
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="funded Compute row"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=transport,
            state_path=canary_path(tmp_path),
        )
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_degraded_status_is_refused_even_with_a_funded_compute_bundle(tmp_path):
    bundle, _registry = funded_compute_bundle()
    result = synthetic_composed(dests=(BURN_UID,), weights=(W,), status=STATUS_DEGRADED)
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="DEGRADED is not a canary"):
        run_canary(tmp_path, result=result, bundle=bundle, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_real_funded_compute_compose_cannot_be_the_canary(tmp_path):
    bundle, registry = funded_compute_bundle()
    result = compose_real(tmp_path, bundle, registry)
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert result.dests == (BURN_UID,)
    assert result.weights == (W,)
    transport = FakeTransport()
    kwargs = build_mechanism_weights_kwargs(dests=result.dests, weights=result.weights)
    with pytest.raises(CanaryIneligible, match="blocked composition is not a write"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=transport,
            state_path=canary_path(tmp_path),
        )
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_real_composed_compute_vector_can_be_the_canary(tmp_path):
    """Pinned QVL + verified mass composes COMPOSED; the canary may fire."""
    bundle, registry = funded_compute_bundle()
    miner_uid = 7
    view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, miner_uid: BOB})
    paying = ComputeAdapter(
        MockQuoteVerifier(),
        collateral_base_url=(
            "https://api.trustedservices.intel.com/sgx/certification/v4/"
        ),
        qvl_digest="ab" * 32,
        verified_mass={BOB: 10**11},
    )
    result = compose_real(
        tmp_path,
        bundle,
        registry,
        adapters={LaneContractId(**COMPUTE_LANE): paying},
        anchor_view=view,
        inclusion_view=view,
        journal_path=journal_path(tmp_path),
    )
    assert result.status == STATUS_COMPOSED
    assert miner_uid in result.dests
    assert BURN_UID in result.dests
    kwargs = prepare_mechanism_weights(
        result=result, journal_path=journal_path(tmp_path)
    )
    receipt, transport = run_canary(
        tmp_path, result=result, kwargs=kwargs, bundle=bundle
    )
    assert transport.calls == [dict(kwargs)]
    assert receipt.kwargs["dests"] == list(result.dests)
    assert receipt.kwargs["weights"] == list(result.weights)


def test_prepare_still_refuses_a_broadcast_flag_on_a_degraded_vector(tmp_path):
    bundle, registry = signed_bundle()
    result = compose_real(tmp_path, bundle, registry)
    with pytest.raises(BroadcastDisabled, match="never sent"):
        prepare_mechanism_weights(
            result=result,
            journal_path=journal_path(tmp_path),
            broadcast=True,
        )


@pytest.mark.parametrize("ss58", sorted(REFUSE_HOTKEYS))
def test_a_refuse_listed_hotkey_cannot_be_the_canary(tmp_path, ss58):
    transport = FakeTransport()
    with pytest.raises(RefuseListError, match="refuse-list"):
        run_canary(tmp_path, hotkey=ss58, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_permitted_hotkey_that_is_not_the_canary_is_refused(tmp_path):
    assert CHARLIE != CANARY_HOTKEY
    assert CHARLIE not in REFUSE_HOTKEYS
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="dedicated canary identity"):
        run_canary(tmp_path, hotkey=CHARLIE, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_alice_is_also_not_the_canary(tmp_path):
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="dedicated canary identity"):
        run_canary(tmp_path, hotkey=ALICE, transport=transport)
    assert transport.calls == []


def test_a_funded_cybergym_row_without_compute_is_not_this_canary(tmp_path):
    bundle, _registry = funded_cybergym_bundle()
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="funded Compute row"):
        run_canary(tmp_path, bundle=bundle, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_allocation_zero_compute_is_not_a_funded_row(tmp_path):
    bundle, _registry = signed_bundle()
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="funded Compute row"):
        run_canary(tmp_path, bundle=bundle, transport=transport)
    assert transport.calls == []


def test_a_burn_only_composed_vector_is_refused_even_if_status_is_composed(tmp_path):
    result = synthetic_composed(dests=(BURN_UID,), weights=(W,))
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="burn-only is not a canary"):
        run_canary(tmp_path, result=result, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_vector_that_dropped_burn_is_refused(tmp_path):
    result = synthetic_composed(dests=(MINER_UID,), weights=(W,))
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="dropped the burn destination"):
        run_canary(tmp_path, result=result, transport=transport)
    assert transport.calls == []


def test_a_u16_mismatch_is_refused(tmp_path):
    kwargs = build_mechanism_weights_kwargs(dests=[BURN_UID], weights=[W])
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="dry-run u16 does not match"):
        run_canary(tmp_path, kwargs=kwargs, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_missing_transport_is_refused(tmp_path):
    bundle, _registry = funded_compute_bundle()
    result = synthetic_composed()
    kwargs = build_mechanism_weights_kwargs(dests=result.dests, weights=result.weights)
    with pytest.raises(CanaryTransportError, match="injected CanaryTransport"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=None,
            state_path=canary_path(tmp_path),
        )
    assert not canary_path(tmp_path).exists()


def test_an_object_without_the_submit_method_is_not_a_transport(tmp_path):
    with pytest.raises(CanaryTransportError, match="injected CanaryTransport"):
        run_canary(tmp_path, transport=object())
    assert not canary_path(tmp_path).exists()


def test_the_compose_journal_name_is_refused_as_the_canary_lock(tmp_path):
    bundle, _registry = funded_compute_bundle()
    result = synthetic_composed()
    kwargs = build_mechanism_weights_kwargs(dests=result.dests, weights=result.weights)
    with pytest.raises(CanaryStateError, match="must be named"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=FakeTransport(),
            state_path=tmp_path / INDEPENDENT_STATE_FILE.name,
        )
    assert not (tmp_path / INDEPENDENT_STATE_FILE.name).exists()


def test_the_thin_journal_name_is_refused_as_the_canary_lock(tmp_path):
    bundle, _registry = funded_compute_bundle()
    result = synthetic_composed()
    kwargs = build_mechanism_weights_kwargs(dests=result.dests, weights=result.weights)
    with pytest.raises(CanaryStateError, match="must be named"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=FakeTransport(),
            state_path=tmp_path / "thin-state.json",
        )
    assert not (tmp_path / "thin-state.json").exists()


def test_omitting_the_lock_path_is_refused():
    bundle, _registry = funded_compute_bundle()
    result = synthetic_composed()
    kwargs = build_mechanism_weights_kwargs(dests=result.dests, weights=result.weights)
    with pytest.raises(CanaryStateError, match="explicit lock path"):
        submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=CANARY_HOTKEY,
            transport=FakeTransport(),
            state_path=None,
        )


def test_a_transport_failure_still_spends_the_slot(tmp_path):
    transport = FakeTransport()
    transport.error = RuntimeError("rpc down")
    with pytest.raises(CanaryTransportError, match="after the slot was claimed"):
        run_canary(tmp_path, transport=transport)
    assert transport.calls == [
        build_mechanism_weights_kwargs(dests=PAYABLE_DESTS, weights=PAYABLE_WEIGHTS)
    ]
    record = load_canary_state(canary_path(tmp_path))
    assert record["status"] == "pending"
    assert record["receipt"] is None
    retry = FakeTransport()
    with pytest.raises(CanarySpent, match="already spent"):
        run_canary(tmp_path, transport=retry)
    assert retry.calls == []


def test_a_non_string_receipt_spends_the_slot(tmp_path):
    transport = FakeTransport(receipt=None)  # type: ignore[arg-type]
    with pytest.raises(CanaryTransportError, match="receipt string"):
        run_canary(tmp_path, transport=transport)
    assert canary_path(tmp_path).exists()
    with pytest.raises(CanarySpent):
        run_canary(tmp_path)


def test_nothing_on_the_canary_path_opens_a_socket(monkeypatch, tmp_path):
    def deny(*args, **kwargs):
        raise AssertionError("the canary path must not dial anything")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    receipt, transport = run_canary(tmp_path)
    assert receipt.receipt == RECEIPT
    assert len(transport.calls) == 1


def test_claim_and_replace_fsync_the_parent_directory(tmp_path, monkeypatch):
    modes: list[int] = []
    real = os.fsync

    def spy(fd):
        modes.append(os.fstat(fd).st_mode)
        return real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    run_canary(tmp_path)
    directory_syncs = [mode for mode in modes if stat.S_ISDIR(mode)]
    file_syncs = [mode for mode in modes if stat.S_ISREG(mode)]
    assert len(file_syncs) >= 2
    assert len(directory_syncs) >= 2


def test_a_directory_fsync_failure_on_claim_does_not_call_the_transport(
    tmp_path, monkeypatch
):
    real = os.fsync

    def boom(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("dirsync failed")
        return real(fd)

    monkeypatch.setattr(os, "fsync", boom)
    transport = FakeTransport()
    with pytest.raises(CanaryStateError, match="directory could not be fsynced"):
        run_canary(tmp_path, transport=transport)
    assert transport.calls == []
    assert canary_path(tmp_path).exists()
    monkeypatch.setattr(os, "fsync", real)
    retry = FakeTransport()
    with pytest.raises(CanarySpent, match="already spent"):
        run_canary(tmp_path, transport=retry)
    assert retry.calls == []


def test_the_canary_module_names_no_writer():
    source = Path(canary_module.__file__).read_text(encoding="utf-8")
    for needle in (
        "set_weights_on_chain",
        "fetch_vector",
        "bittensor",
        "substrateinterface",
        "thin-state.json",
        "weights/next",
        "api.cathedral.computer",
        "SatLane",
        "neuron.validator",
        "import random",
    ):
        assert needle not in source, needle


def test_the_lock_file_on_disk_is_strict_json(tmp_path):
    run_canary(tmp_path)
    raw = canary_path(tmp_path).read_text(encoding="utf-8")
    document = json.loads(raw)
    assert document["broadcast"] is False
    assert document["kwargs"]["dests"] == [MINER_UID, BURN_UID]
    assert sum(document["kwargs"]["weights"]) == W
    assert BURN_HOTKEY not in raw
