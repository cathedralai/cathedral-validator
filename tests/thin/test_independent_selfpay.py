"""No self-payment: the canary and the relay are never paid destinations.

The burn destination has always had this rule -- ``REFUSE_HOTKEYS`` exists so a
runtime cannot boot as the address it pays to. The canary is the same problem
wearing a different hat: it is the identity that SIGNS the vector, so a vector
that pays it is the composer paying itself.

Two independent gates, because they fail differently:

* at compose time, a refuse-listed or canary destination forfeits its mass to
  burn and is dropped from the vector, exactly like an inclusion-time remap.
  Halting the whole epoch instead would let any hotkey that lands on the
  refuse-list stop the subnet from paying anybody;
* at the canary gate, a vector that still carries such a destination is
  ``CanaryIneligible`` and the transport is never touched. A vector that got
  there did not come from ``compose_dry_run``, which is precisely the vector
  worth refusing.

The burn destination itself must survive both gates. It is on ``REFUSE_HOTKEYS``
because nothing may RUN as it, not because it is unpayable.
"""

from __future__ import annotations

import pytest

from _independent_fixtures import (
    BOB,
    BURN_UID,
    COMPUTE_LANE,
    burn_only_view,
    commitment_for,
    economics_document,
    lane_row,
    signed_bundle,
)
from cathedral_thin.independent.compose import (
    STATUS_COMPOSED,
    STATUS_DEGRADED,
    compose_dry_run,
)
from cathedral_thin.independent.compute import ComputeAdapter
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    CANARY_HOTKEY,
    H,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    REFUSE_HOTKEYS,
    W,
    WELL_KNOWN_DEV_HOTKEYS,
)
from cathedral_thin.independent.errors import CanaryIneligible
from cathedral_thin.independent.inclusion import (
    FORFEIT_REFUSED,
    FORFEIT_REMAPPED,
    MetagraphView,
)
from cathedral_thin.independent.policy import LaneContractId
from cathedral_thin.independent.refuse import is_refused_destination
from cathedral_thin.independent.submit import build_mechanism_weights_kwargs
from test_independent_canary import (
    ANCHOR,
    MINER_UID,
    SECOND_MINER_UID,
    FakeTransport,
    canary_path,
    funded_compute_bundle,
    journal_path,
    run_canary,
    synthetic_composed,
)
from test_independent_compute import INTEL_COLLATERAL, PINNED_QVL, MockQuoteVerifier

RELAY_HOTKEY = sorted(REFUSE_HOTKEYS - {BURN_HOTKEY})[0]
CANARY_UID = 11
COMPUTE_AMOUNT = 10**11


def compute_bundle_with(allocations):
    economics = economics_document(
        burn_amount=H - COMPUTE_AMOUNT,
        allocations=allocations,
        explicit_burn_only=False,
    )
    return signed_bundle(economics=economics)


def paying_adapter(verified_mass):
    return ComputeAdapter(
        MockQuoteVerifier(),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=PINNED_QVL,
        verified_mass=verified_mass,
    )


def compose_with(tmp_path, *, view, verified_mass):
    bundle, registry = compute_bundle_with([lane_row(COMPUTE_LANE, COMPUTE_AMOUNT)])
    return bundle, compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=view,
        inclusion_view=view,
        adapters={LaneContractId(**COMPUTE_LANE): paying_adapter(verified_mass)},
        journal_path=journal_path(tmp_path),
    )


def test_the_refuse_list_is_still_exactly_the_relay_and_the_burn_dest():
    """A payable-destination rule is not an excuse to grow the refuse-list."""
    assert REFUSE_HOTKEYS == {RELAY_HOTKEY, BURN_HOTKEY}
    assert CANARY_HOTKEY not in REFUSE_HOTKEYS
    assert not (WELL_KNOWN_DEV_HOTKEYS & REFUSE_HOTKEYS)


def test_the_burn_dest_is_payable_and_the_canary_and_relay_are_not():
    assert is_refused_destination(BURN_HOTKEY) is False
    assert is_refused_destination(BOB) is False
    assert is_refused_destination(CANARY_HOTKEY) is True
    assert is_refused_destination(RELAY_HOTKEY) is True


@pytest.mark.parametrize("value", [None, "", 7, b"5G246", object()])
def test_an_unidentified_destination_is_refused(value):
    assert is_refused_destination(value) is True


@pytest.mark.parametrize("hotkey", [CANARY_HOTKEY, RELAY_HOTKEY])
def test_a_synthetic_vector_that_pays_a_refused_hotkey_cannot_spend_the_slot(
    tmp_path, hotkey
):
    result = synthetic_composed(
        dests=(MINER_UID, BURN_UID),
        uid_hotkeys={MINER_UID: hotkey, BURN_UID: BURN_HOTKEY},
    )
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="this lineage never pays"):
        run_canary(tmp_path, result=result, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_vector_whose_burn_uid_is_bound_to_another_hotkey_is_refused(tmp_path):
    result = synthetic_composed(
        uid_hotkeys={MINER_UID: BOB, BURN_UID: BOB},
    )
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="not the pinned burn hotkey"):
        run_canary(tmp_path, result=result, transport=transport)
    assert transport.calls == []
    assert not canary_path(tmp_path).exists()


def test_a_vector_whose_bindings_do_not_cover_its_destinations_is_refused(tmp_path):
    result = synthetic_composed(uid_hotkeys={BURN_UID: BURN_HOTKEY})
    transport = FakeTransport()
    with pytest.raises(CanaryIneligible, match="unidentified destination"):
        run_canary(tmp_path, result=result, transport=transport)
    assert transport.calls == []


def test_a_named_but_payable_pair_still_spends_the_slot(tmp_path):
    """The new gate refuses refused hotkeys, not every synthetic vector."""
    receipt, transport = run_canary(tmp_path)
    assert receipt.kwargs["dests"] == [MINER_UID, BURN_UID]
    assert len(transport.calls) == 1


def test_compose_forfeits_a_canary_destination_to_burn(tmp_path):
    """The canary's mass goes to burn, and its uid leaves the vector."""
    view = MetagraphView.from_uid_map(
        {BURN_UID: BURN_HOTKEY, CANARY_UID: CANARY_HOTKEY}
    )
    _bundle, result = compose_with(
        tmp_path, view=view, verified_mass={CANARY_HOTKEY: COMPUTE_AMOUNT}
    )
    assert CANARY_UID not in result.dests
    assert result.dests == (BURN_UID,)
    assert result.weights == (W,)
    assert result.status == STATUS_DEGRADED
    assert [forfeit.uid for forfeit in result.inclusion.forfeits] == [CANARY_UID]
    assert result.inclusion.forfeits[0].reason == FORFEIT_REFUSED
    assert result.inclusion.burn_mass == H
    assert result.inclusion.uid_hotkeys == {BURN_UID: BURN_HOTKEY}


def test_compose_pays_a_real_miner_and_omits_the_canary_beside_it(tmp_path):
    """One refused destination does not stop the epoch paying everybody else."""
    view = MetagraphView.from_uid_map(
        {
            BURN_UID: BURN_HOTKEY,
            MINER_UID: BOB,
            CANARY_UID: CANARY_HOTKEY,
        }
    )
    _bundle, result = compose_with(
        tmp_path,
        view=view,
        verified_mass={
            BOB: COMPUTE_AMOUNT // 2,
            CANARY_HOTKEY: COMPUTE_AMOUNT // 2,
        },
    )
    assert result.status == STATUS_COMPOSED
    assert CANARY_UID not in result.dests
    assert set(result.dests) == {MINER_UID, BURN_UID}
    assert sum(result.weights) == W
    assert result.inclusion.uid_hotkeys == {
        BURN_UID: BURN_HOTKEY,
        MINER_UID: BOB,
    }
    assert result.record["h_map"][str(BURN_UID)]["m"] == H - COMPUTE_AMOUNT // 2
    assert str(CANARY_UID) not in result.record["h_map"]


def test_the_forfeit_journal_names_why_each_destination_lost_its_mass(tmp_path):
    anchor = MetagraphView.from_uid_map(
        {
            BURN_UID: BURN_HOTKEY,
            MINER_UID: BOB,
            CANARY_UID: CANARY_HOTKEY,
        }
    )
    inclusion = MetagraphView.from_uid_map(
        {
            BURN_UID: BURN_HOTKEY,
            SECOND_MINER_UID: BOB,
            CANARY_UID: CANARY_HOTKEY,
        }
    )
    bundle, registry = compute_bundle_with([lane_row(COMPUTE_LANE, COMPUTE_AMOUNT)])
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=anchor,
        inclusion_view=inclusion,
        adapters={
            LaneContractId(**COMPUTE_LANE): paying_adapter(
                {
                    BOB: COMPUTE_AMOUNT // 2,
                    CANARY_HOTKEY: COMPUTE_AMOUNT // 2,
                }
            )
        },
        journal_path=journal_path(tmp_path),
    )
    reasons = {forfeit.uid: forfeit.reason for forfeit in result.inclusion.forfeits}
    assert reasons == {MINER_UID: FORFEIT_REMAPPED, CANARY_UID: FORFEIT_REFUSED}
    journalled = result.record["inclusion"]
    assert {row["uid"]: row["reason"] for row in journalled["forfeits"]} == reasons
    assert journalled["uid_hotkeys"] == {str(BURN_UID): BURN_HOTKEY}
    assert result.status == STATUS_DEGRADED


def test_the_burn_destination_survives_both_gates(tmp_path):
    """BURN_HOTKEY is refuse-listed as an identity, never as a destination."""
    bundle, registry = signed_bundle()
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=journal_path(tmp_path),
    )
    assert result.dests == (BURN_UID,)
    assert result.inclusion.uid_hotkeys == {BURN_UID: BURN_HOTKEY}
    assert result.inclusion.forfeits == ()

    payable = synthetic_composed()
    receipt, transport = run_canary(
        tmp_path,
        result=payable,
        kwargs=build_mechanism_weights_kwargs(
            dests=payable.dests, weights=payable.weights
        ),
        bundle=funded_compute_bundle()[0],
    )
    assert BURN_UID in receipt.kwargs["dests"]
    assert len(transport.calls) == 1
    assert (tmp_path / INDEPENDENT_CANARY_FILE.name).exists()
    assert (tmp_path / INDEPENDENT_STATE_FILE.name).exists()
