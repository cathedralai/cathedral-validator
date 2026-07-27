"""The event-log permission and sanitization contract.

Two properties, both load-bearing for the SN39 deploy contract:

1. The raw validator journal is private. It carries `hotkey` and arbitrary
   caller-supplied fields, so a reader group on it would expose whatever an
   emitter happened to pass.
2. The status surface a publisher reads is a strict projection. It is
   group-readable precisely because it cannot carry those fields.

These replace the previous arrangement, where the publisher read the raw
journal through a shared group and the validator refused to open a
group-readable journal, which could not both hold.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from scaffold.events import STATUS_FIELDS, EventLogger, sanitized_status_record


def _modes(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_raw_journal_is_private_and_status_surface_is_sanitized(tmp_path):
    raw = tmp_path / "validator-events.jsonl"
    status = tmp_path / "status-events.jsonl"

    logger = EventLogger(
        mode="thin",
        jsonl_path=str(raw),
        jsonl_group=None,
        status_path=str(status),
        status_group=None,
    )
    logger.event(
        "CHAIN_SUBMITTED",
        stage="submit",
        status="PASS",
        hotkey="5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw",
        artifact="sha256:" + "a" * 64,
        detail="uids=2",
        receipt_body="SECRET-RECEIPT-PAYLOAD",
        evidence_blob="SECRET-EVIDENCE",
    )
    logger.close()

    assert _modes(raw) == 0o600, "raw journal must not be group or world readable"
    assert _modes(status) == 0o600

    raw_record = json.loads(raw.read_text().strip())
    status_record = json.loads(status.read_text().strip())

    # The raw journal is the complete record; that is exactly why it is private.
    assert raw_record["hotkey"].startswith("5FF6Ft")
    assert raw_record["receipt_body"] == "SECRET-RECEIPT-PAYLOAD"

    # The sanitized surface carries operational shape and nothing else.
    assert set(status_record) <= set(STATUS_FIELDS)
    for leaked in ("hotkey", "receipt_body", "evidence_blob"):
        assert leaked not in status_record
    blob = json.dumps(status_record)
    assert "SECRET-RECEIPT-PAYLOAD" not in blob
    assert "SECRET-EVIDENCE" not in blob
    assert "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw" not in blob
    assert status_record["event"] == "CHAIN_SUBMITTED"
    assert status_record["status"] == "PASS"


def test_a_group_readable_raw_journal_is_refused(tmp_path):
    raw = tmp_path / "validator-events.jsonl"
    raw.touch()
    os.chmod(raw, 0o640)
    with pytest.raises(ValueError, match="private \\(0600\\) without a reader group"):
        EventLogger(mode="thin", jsonl_path=str(raw), jsonl_group=None)


def test_projection_drops_unknown_fields_by_construction():
    # A denylist would miss a field nobody named; assert the allowlist shape.
    projected = sanitized_status_record(
        {
            "ts": "2026-07-27T00:00:00.000Z",
            "event": "X",
            "stage": "s",
            "mode": "thin",
            "status": "INFO",
            "hotkey": "5xxxx",
            "some_future_field": "leak",
        }
    )
    assert projected == {
        "ts": "2026-07-27T00:00:00.000Z",
        "event": "X",
        "stage": "s",
        "mode": "thin",
        "status": "INFO",
    }
