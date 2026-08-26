"""The submission is built and journalled. Nothing here can send it.

These tests pin the shape of the call an independent composer WOULD make -- the
netuid, the mechanism id, the version key, and a strictly increasing u16 vector
summing to 65535 -- and they pin that asking for a broadcast raises instead of
finding a stub to call.
"""

from __future__ import annotations

import pytest

from _independent_fixtures import (
    ANCHOR_HASH,
    BURN_UID,
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
    EpochAnchor,
    compose_dry_run,
)
from cathedral_thin.independent.constants import H, INDEPENDENT_STATE_FILE
from cathedral_thin.independent.errors import (
    BroadcastBlocked,
    BroadcastDisabled,
    HamiltonError,
)
from cathedral_thin.independent.journal import load_journal
from cathedral_thin.independent.submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
    prepare_mechanism_weights,
)

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)


def composed(tmp_path, *, economics=None):
    bundle, registry = signed_bundle(economics=economics)
    return compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        journal_path=tmp_path / INDEPENDENT_STATE_FILE.name,
    )


def test_the_call_shape_is_pinned():
    assert build_mechanism_weights_kwargs(dests=[136], weights=[65535]) == {
        "netuid": 39,
        "mecid": 0,
        "dests": [136],
        "weights": [65535],
        "version_key": 10005000,
    }
    assert MECHANISM_WEIGHTS_CALL == "SubtensorModule.set_mechanism_weights"


@pytest.mark.parametrize(
    "dests,weights,reason",
    [
        ([136, 7], [30000, 35535], "strictly increasing"),
        ([7, 136], [30000, 30000], "sum to 60000"),
        ([7, 136], [0, 65535], r"outside \(0, 65535]"),
        ([7], [65535, 0], "differ in length"),
        ([], [], "is empty"),
        ([True], [65535], "not a u16 uid"),
        ([7], [True], "not an integer"),
    ],
)
def test_a_malformed_vector_is_refused(dests, weights, reason):
    with pytest.raises(HamiltonError, match=reason):
        build_mechanism_weights_kwargs(dests=dests, weights=weights)


@pytest.mark.parametrize(
    "field,value",
    [("netuid", 1), ("mecid", 1), ("version_key", 1)],
)
def test_a_call_off_the_pins_is_refused(field, value):
    with pytest.raises(BroadcastDisabled):
        build_mechanism_weights_kwargs(dests=[136], weights=[65535], **{field: value})


def test_a_composed_vector_is_journalled_not_sent(tmp_path):
    result = composed(tmp_path)
    kwargs = prepare_mechanism_weights(
        result=result, journal_path=tmp_path / INDEPENDENT_STATE_FILE.name
    )
    assert kwargs["dests"] == [BURN_UID]
    assert kwargs["weights"] == [65535]
    record = load_journal(tmp_path / INDEPENDENT_STATE_FILE.name)
    assert record["submission"]["call"] == MECHANISM_WEIGHTS_CALL
    assert record["submission"]["kwargs"] == kwargs
    assert record["submission"]["broadcast"] is False
    assert record["broadcast"] is False
    assert "signed_vector" not in record


def test_asking_for_a_broadcast_raises_instead_of_finding_a_writer(tmp_path):
    result = composed(tmp_path)
    with pytest.raises(BroadcastDisabled, match="never sent"):
        prepare_mechanism_weights(
            result=result,
            journal_path=tmp_path / INDEPENDENT_STATE_FILE.name,
            broadcast=True,
        )


def test_a_blocked_composition_leaves_no_journalled_submission(tmp_path):
    result = composed(
        tmp_path,
        economics=economics_document(
            burn_amount=H - 10**11, allocations=[lane_row(COMPUTE_LANE, 10**11)]
        ),
    )
    assert result.status == STATUS_BROADCAST_BLOCKED
    with pytest.raises(BroadcastBlocked, match="leaves no journalled submission"):
        prepare_mechanism_weights(
            result=result, journal_path=tmp_path / INDEPENDENT_STATE_FILE.name
        )
    assert "submission" not in load_journal(tmp_path / INDEPENDENT_STATE_FILE.name)
