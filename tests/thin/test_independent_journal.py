"""The independent journal writes its own file and records no signed vector.

Two claims, both load-bearing for the separation this lineage exists to keep:

1. the record lands on the independent path and nothing lands on the thin
   validator's durable journal, whose reservation fence must not be satisfied
   by another lineage's writes;
2. the record carries no signed vector, because this path has no writer and a
   journalled signature nothing can redeem is indistinguishable from a real one.
"""

from __future__ import annotations

import json

import pytest

from cathedral_thin.independent.constants import INDEPENDENT_STATE_FILE, LINEAGE
from cathedral_thin.independent.errors import JournalError
from cathedral_thin.independent.journal import load_journal, write_journal

THIN_JOURNAL_NAME = "thin-state.json"


def record(**overrides) -> dict:
    base = {
        "lineage": LINEAGE,
        "netuid": 39,
        "epoch_open": 6_120_000,
        "anchor_number": 6_119_999,
        "anchor_hash": "0x" + "ab" * 32,
        "bundle_digest": "cd" * 32,
        "commitment": "ef" * 25,
        "h_map": {"136": {"ss58": "5GP", "m": 10**12}},
        "hamilton": {"dests": [136], "weights": [65535]},
        "status": "DEGRADED",
        "broadcast": False,
    }
    base.update(overrides)
    return base


def test_the_record_lands_on_the_independent_path(tmp_path):
    target = tmp_path / INDEPENDENT_STATE_FILE.name
    assert write_journal(record(), target) == target
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["lineage"] == "independent_v1"
    assert document["broadcast"] is False
    assert "signed_vector" not in document
    assert load_journal(target) == document


def test_nothing_is_written_to_the_thin_validator_journal(tmp_path):
    write_journal(record(), tmp_path / INDEPENDENT_STATE_FILE.name)
    assert not (tmp_path / THIN_JOURNAL_NAME).exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        INDEPENDENT_STATE_FILE.name
    ]


def test_the_thin_journal_name_is_refused_outright(tmp_path):
    with pytest.raises(JournalError, match="must be named"):
        write_journal(record(), tmp_path / THIN_JOURNAL_NAME)
    assert not (tmp_path / THIN_JOURNAL_NAME).exists()


def test_the_default_path_is_not_the_thin_journal():
    assert INDEPENDENT_STATE_FILE.name == "independent-state.json"
    assert INDEPENDENT_STATE_FILE.name != THIN_JOURNAL_NAME
    assert (
        str(INDEPENDENT_STATE_FILE)
        != f"/var/lib/cathedral-validator/{THIN_JOURNAL_NAME}"
    )


@pytest.mark.parametrize("field", ["signed_vector", "signature", "extrinsic"])
def test_a_record_claiming_a_signature_is_refused(tmp_path, field):
    with pytest.raises(JournalError, match="never records"):
        write_journal(
            record(**{field: "0x" + "00" * 64}), tmp_path / INDEPENDENT_STATE_FILE.name
        )


def test_a_record_claiming_broadcast_is_refused(tmp_path):
    with pytest.raises(JournalError, match="broadcast = false"):
        write_journal(record(broadcast=True), tmp_path / INDEPENDENT_STATE_FILE.name)


def test_a_record_from_another_lineage_is_refused(tmp_path):
    with pytest.raises(JournalError, match="lineage"):
        write_journal(
            record(lineage="thin_relay_v3"), tmp_path / INDEPENDENT_STATE_FILE.name
        )


def test_a_record_missing_the_frozen_epoch_boundary_is_refused(tmp_path):
    incomplete = record()
    del incomplete["anchor_hash"]
    with pytest.raises(JournalError, match="missing anchor_hash"):
        write_journal(incomplete, tmp_path / INDEPENDENT_STATE_FILE.name)


def test_the_write_is_atomic_and_leaves_no_temporary_behind(tmp_path):
    target = tmp_path / INDEPENDENT_STATE_FILE.name
    write_journal(record(), target)
    write_journal(record(status="BROADCAST_BLOCKED"), target)
    assert [path.name for path in tmp_path.iterdir()] == [target.name]
    assert load_journal(target)["status"] == "BROADCAST_BLOCKED"
    assert target.stat().st_mode & 0o777 == 0o600


def test_a_journal_with_duplicate_keys_is_refused_on_load(tmp_path):
    target = tmp_path / INDEPENDENT_STATE_FILE.name
    target.write_text('{"status":"DEGRADED","status":"COMPOSED"}', encoding="utf-8")
    with pytest.raises(JournalError, match="duplicate key 'status'"):
        load_journal(target)


def test_a_journal_on_disk_claiming_a_signed_vector_is_not_trusted(tmp_path):
    target = tmp_path / INDEPENDENT_STATE_FILE.name
    target.write_text('{"signed_vector":"0xdead"}', encoding="utf-8")
    with pytest.raises(JournalError, match="refusing to trust it"):
        load_journal(target)


def test_a_missing_journal_reads_as_a_refusal_not_an_empty_record(tmp_path):
    with pytest.raises(JournalError, match="could not be read"):
        load_journal(tmp_path / INDEPENDENT_STATE_FILE.name)
