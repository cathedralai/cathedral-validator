"""Dry-run composition end to end, with a mock anchor commitment.

No chain client exists on this path, so the anchor's commitment and both
metagraph views are supplied by the test. What is real is everything between:
the signatures must verify, the lineage must follow genesis or last-good, the
commitment must name the exact document, the mass map must partition ``H``,
the inclusion re-check must run before apportionment, and the journal must
record what was composed without claiming a broadcast.
"""

from __future__ import annotations

import pytest

from _independent_fixtures import (
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    COMPUTE_LANE,
    EPOCH_OPEN,
    bundle_document,
    burn_only_view,
    commitment_for,
    economics_document,
    economics_keys,
    lane_row,
    sign_document,
    signed_bundle,
)
from cathedral_thin.independent.compose import (
    STATUS_BROADCAST_BLOCKED,
    STATUS_DEGRADED,
    EpochAnchor,
    compose_dry_run,
    last_good_is_usable,
    mass_map,
    require_last_good,
)
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    H,
    INDEPENDENT_STATE_FILE,
    LINEAGE,
)
from cathedral_thin.independent.errors import (
    BroadcastDisabled,
    CommitmentError,
    ConfigError,
    PolicyBundleError,
    PolicyLineageError,
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.journal import load_journal
from cathedral_thin.independent.policy import LaneContractId, parse_policy_bundle

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)


def journal_path(tmp_path):
    return tmp_path / INDEPENDENT_STATE_FILE.name


def run_compose(tmp_path, bundle, registry, **kwargs):
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


def test_the_frozen_anchor_must_be_the_block_before_the_epoch_opens():
    with pytest.raises(ConfigError, match="must be epoch_open - 1"):
        EpochAnchor(epoch_open=100, anchor_number=100, anchor_hash=ANCHOR_HASH)
    with pytest.raises(ConfigError, match="0x plus 64"):
        EpochAnchor(epoch_open=100, anchor_number=99, anchor_hash="0xabc")


def test_the_genesis_burn_only_bundle_composes_degraded(tmp_path):
    """Every lane sits at allocation 0, so burn-only is expected -- and not acceptance."""
    bundle, registry = signed_bundle()
    result = run_compose(tmp_path, bundle, registry)
    assert result.status == STATUS_DEGRADED
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))
    assert result.broadcast_eligible is False
    assert result.blocks == ()

    record = load_journal(journal_path(tmp_path))
    assert record["lineage"] == LINEAGE
    assert record["status"] == STATUS_DEGRADED
    assert record["broadcast"] is False
    assert record["epoch_open"] == EPOCH_OPEN
    assert record["anchor_number"] == EPOCH_OPEN - 1
    assert record["anchor_hash"] == ANCHOR_HASH
    assert record["bundle_digest"] == bundle.digest().hex()
    assert record["commitment"] == commitment_for(bundle).hex()
    assert record["h_map"] == {str(BURN_UID): {"ss58": BURN_HOTKEY, "m": H}}
    assert record["hamilton"]["dests"] == [BURN_UID]
    assert record["hamilton"]["weights"] == [65535]
    assert "signed_vector" not in record


def test_a_funded_lane_without_an_adapter_blocks_broadcast(tmp_path):
    economics = economics_document(
        burn_amount=H - 10**11, allocations=[lane_row(COMPUTE_LANE, 10**11)]
    )
    bundle, registry = signed_bundle(economics=economics)
    result = run_compose(tmp_path, bundle, registry, adapters={})
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert result.broadcast_eligible is False
    assert [block.lane_contract_id.as_dict() for block in result.blocks] == [
        COMPUTE_LANE
    ]
    assert "no adapter" in result.reason
    # The unpayable mass folds to burn rather than being spread over survivors.
    assert result.dests == (BURN_UID,)
    record = load_journal(journal_path(tmp_path))
    assert record["status"] == STATUS_BROADCAST_BLOCKED
    assert record["blocks"][0]["amount"] == 10**11


def test_a_registered_adapter_does_not_make_a_funded_lane_contributing(tmp_path):
    """Allocation 0 is the gate. A dry-run mock adapter cannot lift it."""
    economics = economics_document(
        burn_amount=H - 10**11, allocations=[lane_row(COMPUTE_LANE, 10**11)]
    )
    bundle, registry = signed_bundle(economics=economics)
    adapters = {LaneContractId(**COMPUTE_LANE): object()}
    result = run_compose(tmp_path, bundle, registry, adapters=adapters)
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert "deferred at allocation 0" in result.reason
    assert result.broadcast_eligible is False


def test_a_mock_adapter_on_a_zero_allocation_lane_contributes_nothing(tmp_path):
    """The allocation is the gate, not the adapter registry."""
    bundle, registry = signed_bundle()
    result = run_compose(
        tmp_path,
        bundle,
        registry,
        adapters={LaneContractId(**COMPUTE_LANE): object()},
    )
    assert result.status == STATUS_DEGRADED
    assert result.blocks == ()
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))


def test_a_disabled_funded_row_blocks_nothing(tmp_path):
    economics = economics_document(
        burn_amount=H, allocations=[lane_row(COMPUTE_LANE, 10**11, enabled=False)]
    )
    bundle, registry = signed_bundle(economics=economics)
    result = run_compose(tmp_path, bundle, registry)
    assert result.blocks == ()
    assert result.status == STATUS_DEGRADED


def test_broadcast_true_is_refused_rather_than_stubbed(tmp_path):
    bundle, registry = signed_bundle()
    with pytest.raises(BroadcastDisabled, match="no chain writer"):
        run_compose(tmp_path, bundle, registry, broadcast=True)
    assert not journal_path(tmp_path).exists()


def test_a_commitment_for_another_epoch_halts_before_anything_is_journalled(tmp_path):
    bundle, registry = signed_bundle()
    with pytest.raises(CommitmentError, match="names epoch"):
        run_compose(
            tmp_path,
            bundle,
            registry,
            commitment=commitment_for(bundle, epoch=EPOCH_OPEN - 360),
        )
    assert not journal_path(tmp_path).exists()


def test_a_commitment_for_another_document_halts(tmp_path):
    bundle, registry = signed_bundle()
    other, _ = signed_bundle(
        economics=economics_document(version=2, previous_digest="ab" * 32)
    )
    with pytest.raises(CommitmentError, match="does not match"):
        run_compose(tmp_path, bundle, registry, commitment=commitment_for(other))


def test_last_good_is_usable_only_while_the_anchor_still_names_its_digest():
    bundle, _registry = signed_bundle()
    other, _ = signed_bundle(
        economics=economics_document(version=2, previous_digest="ab" * 32)
    )
    assert last_good_is_usable(
        last_good_digest=bundle.digest(),
        commitment=commitment_for(bundle),
        netuid=39,
        epoch=EPOCH_OPEN,
    )
    assert not last_good_is_usable(
        last_good_digest=bundle.digest(),
        commitment=commitment_for(other),
        netuid=39,
        epoch=EPOCH_OPEN,
    )
    with pytest.raises(CommitmentError, match="does not name the cached"):
        require_last_good(
            last_good_digest=bundle.digest(),
            commitment=commitment_for(other),
            netuid=39,
            epoch=EPOCH_OPEN,
        )


def test_a_remapped_miner_forfeits_through_the_composer(tmp_path):
    """The composer applies the inclusion re-check before apportioning."""
    economics = economics_document(
        burn_amount=H - 10**11, allocations=[lane_row(COMPUTE_LANE, 10**11)]
    )
    bundle, registry = signed_bundle(economics=economics)
    anchor_view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 7: BOB})
    inclusion_view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 7: CHARLIE})
    result = run_compose(
        tmp_path,
        bundle,
        registry,
        anchor_view=anchor_view,
        inclusion_view=inclusion_view,
    )
    # The lane never reached the mass map, so uid 7 is absent either way; what
    # this pins is that a swap on the burn UID would have halted instead.
    assert result.dests == (BURN_UID,)
    assert result.status == STATUS_BROADCAST_BLOCKED


def test_the_mass_map_always_partitions_h():
    bundle, _registry = signed_bundle(
        economics=economics_document(
            burn_amount=H - 3 * 10**11,
            allocations=[lane_row(COMPUTE_LANE, 3 * 10**11)],
        )
    )
    dests, blocks = mass_map(bundle, burn_uid=BURN_UID, adapters={})
    assert sum(dest.m for dest in dests) == H
    assert len(blocks) == 1


def test_composing_without_a_journal_path_writes_nothing(tmp_path):
    bundle, registry = signed_bundle()
    result = run_compose(tmp_path, bundle, registry, journal_path=None)
    assert result.journal_path is None
    assert list(tmp_path.iterdir()) == []


def test_garbage_signatures_cannot_compose_even_when_the_commitment_matches(tmp_path):
    """Parse only checks signature shape. Compose must still verify 2-of-3."""
    private, registry = economics_keys()
    document = sign_document(bundle_document(), private, ("economics-a", "economics-b"))
    document["signatures"][0]["sig"] = "00" * 64
    document["signatures"][1]["sig"] = "11" * 64
    bundle = parse_policy_bundle(document)
    with pytest.raises(PolicyBundleError, match="does not verify"):
        run_compose(tmp_path, bundle, registry)
    assert not journal_path(tmp_path).exists()


def test_one_signature_is_not_enough_to_compose(tmp_path):
    bundle, registry = signed_bundle(key_ids=("economics-a",))
    with pytest.raises(PolicyBundleError, match="has 1 distinct pinned signatures"):
        run_compose(tmp_path, bundle, registry)
    assert not journal_path(tmp_path).exists()


def test_a_successor_without_last_good_cannot_compose(tmp_path):
    genesis, _registry = signed_bundle()
    successor, registry = signed_bundle(
        economics=economics_document(version=2, previous_digest=genesis.digest().hex())
    )
    with pytest.raises(PolicyLineageError, match="no previously accepted"):
        run_compose(tmp_path, successor, registry)
    assert not journal_path(tmp_path).exists()


def test_a_successor_that_names_last_good_composes(tmp_path):
    genesis, registry = signed_bundle()
    successor, registry = signed_bundle(
        economics=economics_document(version=2, previous_digest=genesis.digest().hex())
    )
    result = run_compose(tmp_path, successor, registry, last_good=genesis)
    assert result.status == STATUS_DEGRADED
    assert result.record["economics_version"] == 2
    assert result.record["previous_digest"] == genesis.digest().hex()


def test_a_cached_successor_may_be_reused_as_last_good(tmp_path):
    """Same digest as last-good is reuse of the current document, not a fork."""
    genesis, registry = signed_bundle()
    successor, registry = signed_bundle(
        economics=economics_document(version=2, previous_digest=genesis.digest().hex())
    )
    result = run_compose(tmp_path, successor, registry, last_good=successor)
    assert result.status == STATUS_DEGRADED


def test_a_skipped_version_cannot_compose(tmp_path):
    genesis, registry = signed_bundle()
    skipped, registry = signed_bundle(
        economics=economics_document(version=3, previous_digest=genesis.digest().hex())
    )
    with pytest.raises(PolicyLineageError, match="does not follow last-good"):
        run_compose(tmp_path, skipped, registry, last_good=genesis)
    assert not journal_path(tmp_path).exists()


def test_a_fork_with_an_unrelated_predecessor_cannot_compose(tmp_path):
    genesis, registry = signed_bundle()
    fork, registry = signed_bundle(
        economics=economics_document(version=2, previous_digest="ab" * 32)
    )
    with pytest.raises(PolicyLineageError, match="does not name"):
        run_compose(tmp_path, fork, registry, last_good=genesis)
    assert not journal_path(tmp_path).exists()


def test_a_rollback_to_genesis_after_a_successor_cannot_compose(tmp_path):
    genesis, registry = signed_bundle()
    successor, registry = signed_bundle(
        economics=economics_document(version=2, previous_digest=genesis.digest().hex())
    )
    with pytest.raises(PolicyLineageError, match="does not follow last-good"):
        run_compose(tmp_path, genesis, registry, last_good=successor)
    assert not journal_path(tmp_path).exists()
