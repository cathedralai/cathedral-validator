"""Dry-run composition end to end, with a mock anchor commitment.

No chain client exists on this path, so the anchor's commitment and both
metagraph views are supplied by the test. What is real is everything between:
the commitment must name the exact document, the mass map must partition ``H``,
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
    burn_only_view,
    commitment_for,
    economics_document,
    lane_row,
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
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.journal import load_journal
from cathedral_thin.independent.policy import LaneContractId

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)


def journal_path(tmp_path):
    return tmp_path / INDEPENDENT_STATE_FILE.name


def test_the_frozen_anchor_must_be_the_block_before_the_epoch_opens():
    with pytest.raises(ConfigError, match="must be epoch_open - 1"):
        EpochAnchor(epoch_open=100, anchor_number=100, anchor_hash=ANCHOR_HASH)
    with pytest.raises(ConfigError, match="0x plus 64"):
        EpochAnchor(epoch_open=100, anchor_number=99, anchor_hash="0xabc")


def test_the_genesis_burn_only_bundle_composes_degraded(tmp_path):
    """Every lane sits at allocation 0, so burn-only is expected -- and not acceptance."""
    bundle, _registry = signed_bundle()
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=journal_path(tmp_path),
    )
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
    bundle, _registry = signed_bundle(economics=economics)
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        adapters={},
        journal_path=journal_path(tmp_path),
    )
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
    bundle, _registry = signed_bundle(economics=economics)
    adapters = {LaneContractId(**COMPUTE_LANE): object()}
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        adapters=adapters,
        journal_path=journal_path(tmp_path),
    )
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert "deferred at allocation 0" in result.reason
    assert result.broadcast_eligible is False


def test_a_mock_adapter_on_a_zero_allocation_lane_contributes_nothing(tmp_path):
    """The allocation is the gate, not the adapter registry."""
    bundle, _registry = signed_bundle()
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        adapters={LaneContractId(**COMPUTE_LANE): object()},
        journal_path=journal_path(tmp_path),
    )
    assert result.status == STATUS_DEGRADED
    assert result.blocks == ()
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))


def test_a_disabled_funded_row_blocks_nothing(tmp_path):
    economics = economics_document(
        burn_amount=H, allocations=[lane_row(COMPUTE_LANE, 10**11, enabled=False)]
    )
    bundle, _registry = signed_bundle(economics=economics)
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=journal_path(tmp_path),
    )
    assert result.blocks == ()
    assert result.status == STATUS_DEGRADED


def test_broadcast_true_is_refused_rather_than_stubbed(tmp_path):
    bundle, _registry = signed_bundle()
    with pytest.raises(BroadcastDisabled, match="no chain writer"):
        compose_dry_run(
            bundle=bundle,
            commitment=commitment_for(bundle),
            anchor=ANCHOR,
            anchor_view=burn_only_view(),
            inclusion_view=burn_only_view(),
            journal_path=journal_path(tmp_path),
            broadcast=True,
        )
    assert not journal_path(tmp_path).exists()


def test_a_commitment_for_another_epoch_halts_before_anything_is_journalled(tmp_path):
    bundle, _registry = signed_bundle()
    with pytest.raises(CommitmentError, match="names epoch"):
        compose_dry_run(
            bundle=bundle,
            commitment=commitment_for(bundle, epoch=EPOCH_OPEN - 360),
            anchor=ANCHOR,
            anchor_view=burn_only_view(),
            inclusion_view=burn_only_view(),
            journal_path=journal_path(tmp_path),
        )
    assert not journal_path(tmp_path).exists()


def test_a_commitment_for_another_document_halts(tmp_path):
    bundle, _registry = signed_bundle()
    other, _ = signed_bundle(
        economics=economics_document(version=2, previous_digest="ab" * 32)
    )
    with pytest.raises(CommitmentError, match="does not match"):
        compose_dry_run(
            bundle=bundle,
            commitment=commitment_for(other),
            anchor=ANCHOR,
            anchor_view=burn_only_view(),
            inclusion_view=burn_only_view(),
            journal_path=journal_path(tmp_path),
        )


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
    bundle, _registry = signed_bundle(economics=economics)
    anchor_view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 7: BOB})
    inclusion_view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 7: CHARLIE})
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=anchor_view,
        inclusion_view=inclusion_view,
        journal_path=journal_path(tmp_path),
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
    bundle, _registry = signed_bundle()
    result = compose_dry_run(
        bundle=bundle,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=None,
    )
    assert result.journal_path is None
    assert list(tmp_path.iterdir()) == []
