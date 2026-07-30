"""The canonical evidence manifest: pinned so three repositories cannot drift apart.

The producer (cathedral-distill), the intake contract (cathedral) and this validator
each build this structure independently, because no import spans the repositories. If
any of them changes the schema string, the field set, the ordering or the number
formatting, the digests stop matching and every funded epoch burns. So the literals are
pinned here rather than merely computed.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cathedral_thin import cybergym_evidence_manifest as ev


def test_the_schema_string_is_pinned():
    # Domain separation: the schema is inside the digested body, so a digest over some
    # other structure cannot collide with one over this by construction.
    assert ev.SCHEMA == "cathedral_cybergym_evidence_manifest_v1"


def test_the_empty_manifest_digest_is_deterministic():
    a = ev.empty_digest(network="finney", netuid=39, source_epoch=11)
    b = ev.empty_digest(network="finney", netuid=39, source_epoch=11)
    assert a == b
    expected = hashlib.sha256(
        json.dumps(
            {
                "schema": ev.SCHEMA,
                "network": "finney",
                "netuid": 39,
                "source_epoch": 11,
                "entries": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert a == expected


def test_entry_order_does_not_change_the_digest():
    rows = [
        {"miner_hotkey": "5B", "receipt_id": "r2", "work_units": "3"},
        {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "12"},
    ]
    forward = ev.manifest_digest(
        network="finney", netuid=39, source_epoch=11, entries=rows
    )
    backward = ev.manifest_digest(
        network="finney", netuid=39, source_epoch=11, entries=list(reversed(rows))
    )
    assert forward == backward


@pytest.mark.parametrize(
    "a,b", [("12", 12), ("12", 12.0), ("12", "12.000"), ("0", 0.0)]
)
def test_equivalent_amounts_digest_identically(a, b):
    # work_units is a canonical decimal string, so float formatting cannot change the
    # digest and the two sides cannot disagree over 12 vs 12.0.
    left = ev.manifest_digest(
        network="finney",
        netuid=39,
        source_epoch=11,
        entries=[{"miner_hotkey": "5A", "receipt_id": "r1", "work_units": a}],
    )
    right = ev.manifest_digest(
        network="finney",
        netuid=39,
        source_epoch=11,
        entries=[{"miner_hotkey": "5A", "receipt_id": "r1", "work_units": b}],
    )
    assert left == right


@pytest.mark.parametrize(
    "field,value",
    [("network", "test"), ("netuid", 1), ("source_epoch", 12)],
)
def test_the_digest_is_audience_and_epoch_bound(field, value):
    base = dict(network="finney", netuid=39, source_epoch=11)
    rows = [{"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "12"}]
    other = dict(base)
    other[field] = value
    assert ev.manifest_digest(entries=rows, **base) != ev.manifest_digest(
        entries=rows, **other
    )


@pytest.mark.parametrize(
    "row",
    [
        {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "-1"},
        {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "nan"},
        {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "inf"},
        {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "abc"},
    ],
)
def test_an_unusable_amount_is_refused(row):
    with pytest.raises(ev.EvidenceManifestError):
        ev.manifest_digest(network="finney", netuid=39, source_epoch=11, entries=[row])


def test_a_duplicate_entry_is_refused():
    row = {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "12"}
    with pytest.raises(ev.EvidenceManifestError):
        ev.manifest_digest(
            network="finney", netuid=39, source_epoch=11, entries=[row, dict(row)]
        )


def test_changing_any_committed_field_changes_the_digest():
    base = [{"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "12"}]
    d0 = ev.manifest_digest(network="finney", netuid=39, source_epoch=11, entries=base)
    for field, value in (
        ("miner_hotkey", "5B"),
        ("receipt_id", "r2"),
        ("work_units", "13"),
    ):
        changed = [dict(base[0], **{field: value})]
        assert (
            ev.manifest_digest(
                network="finney", netuid=39, source_epoch=11, entries=changed
            )
            != d0
        ), f"{field} must be committed"
