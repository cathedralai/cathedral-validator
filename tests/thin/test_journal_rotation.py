"""Rotation must bound the journal without ever hiding the newest record.

`/var/log/cathedral-validator` had no cap at all: 888 KB of append-only JSONL
in nine days on the live SN39 box, and nothing to stop it filling the disk the
validator needs in order to write weights.

Adding rotation is the easy half. The hard half is that rotation is exactly the
operation that can turn the liveness alert red on a healthy validator, or blind
it outright, because both monitors — `deploy/sn39/cathedral-mismatch-check` and
`scaffold.health` behind `cathedral-validator status` — decide from the newest
record they can see, and rotation empties the file that holds it.

Two shipped properties make that safe, and both are pinned here:

* `copytruncate`, because `scaffold.events` holds the journal descriptor open
  with `O_APPEND` for the life of the process. Anything that replaces the inode
  leaves the validator writing somewhere nobody is looking. The first test
  below proves the writer really does survive an in-place truncation.
* `delaycompress`, because both readers fall back to exactly one uncompressed
  rotated generation for the minutes after a rotation when the live journal is
  genuinely empty.

The tests simulate a rotation the way logrotate performs it — copy, then
truncate in place — rather than trusting a comment about what logrotate does.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scaffold import events as events_module
from scaffold import health

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_SCRIPT = REPO_ROOT / "deploy" / "sn39" / "cathedral-mismatch-check"
FRAGMENT = REPO_ROOT / "deploy" / "sn39" / "cathedral-validator.logrotate"
TICK = 1500.0


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _record(event: str, *, ago_secs: float, status: str = "PASS", **fields) -> dict:
    return {
        "ts": _stamp(datetime.now(UTC) - timedelta(seconds=ago_secs)),
        "event": event,
        "stage": "result",
        "mode": "shadow",
        "status": status,
        **fields,
    }


def _alive(ago_secs: float = 60.0) -> list[dict]:
    """A journal that proves the loop is running, with nothing else wrong."""
    return [
        _record("STARTUP", ago_secs=ago_secs + 4 * TICK, status="INFO"),
        _record("VECTOR_ACCEPTED", ago_secs=ago_secs + 5),
        _record("WEIGHTS_SUBMITTED", ago_secs=ago_secs, uid_count=42),
        _record("PROVENANCE_AUDIT_PASS", ago_secs=ago_secs),
    ]


def _write(path: Path, records) -> Path:
    path.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records),
        encoding="utf-8",
    )
    return path


def _rotate(path: Path) -> Path:
    """Exactly what `copytruncate` does: copy the bytes, truncate in place."""
    rotated = path.with_name(path.name + ".1")
    shutil.copy2(path, rotated)
    with open(path, "r+b") as handle:
        handle.truncate(0)
    return rotated


def _run_alert(journal: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(ALERT_SCRIPT), str(journal)],
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=60,
    )


# -- copytruncate is the only rotation this writer survives ------------------


def test_the_event_writer_keeps_writing_through_an_in_place_truncation(tmp_path):
    """Why the fragment says `copytruncate` and never `create`.

    `EventLogger` opens the journal once and holds it. Truncating that inode is
    survivable — O_APPEND puts the next write back at offset 0, with no sparse
    hole — while replacing the inode would not be: the descriptor would still
    point at the old file and the live path would stay empty until restart.
    """
    journal = tmp_path / "validator-events.jsonl"
    logger = events_module.EventLogger(mode="thin", jsonl_path=str(journal), tty=None)
    try:
        logger.event("STARTUP", stage="boot", status=events_module.INFO)
        assert journal.stat().st_size > 0
        before = journal.stat().st_ino

        with open(journal, "r+b") as handle:
            handle.truncate(0)
        assert journal.stat().st_size == 0

        logger.event("WEIGHTS_SUBMITTED", stage="submit", status=events_module.PASS)
    finally:
        logger.close()

    assert journal.stat().st_ino == before, "copytruncate must reuse the inode"
    lines = journal.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["WEIGHTS_SUBMITTED"], (
        "an O_APPEND descriptor must resume at offset 0, not leave a sparse hole"
    )


# -- the alert stays green across a rotation ---------------------------------


def test_the_shell_alert_survives_a_rotation_that_empties_the_journal(tmp_path):
    """The regression this guards: a daily rotation paging the operator.

    Without the rotated-generation fallback the live journal is 0 bytes and
    rule 1 declares the check blind, which is a failed unit — the alert — for a
    validator that is doing nothing wrong.
    """
    journal = _write(tmp_path / "validator-events.jsonl", _alive())
    _rotate(journal)

    result = _run_alert(journal)
    assert result.returncode == 0, result.stdout
    assert "validator alive" in result.stdout


def test_the_status_command_survives_a_rotation_that_empties_the_journal(tmp_path):
    journal = _write(tmp_path / "validator-events.jsonl", _alive())
    _rotate(journal)

    report = health.evaluate(journal, interval_secs=TICK)
    assert report.ok, report.problems


def test_a_stale_validator_still_alerts_after_a_rotation(tmp_path):
    """The fallback must not become a way to look alive on old records.

    Rotation makes the newest record reachable again; it must not make an OLD
    newest record acceptable. A journal whose last tick predates the liveness
    window alerts whether or not it has been rotated.
    """
    journal = _write(tmp_path / "validator-events.jsonl", _alive(ago_secs=9 * TICK))
    _rotate(journal)

    result = _run_alert(journal)
    assert result.returncode == 1
    assert "has not grown since" in result.stdout
    assert not health.evaluate(journal, interval_secs=TICK).ok


def test_an_empty_journal_with_no_rotated_generation_is_still_blind(tmp_path):
    """Fail-closed is unchanged where there is genuinely nothing to read."""
    journal = tmp_path / "validator-events.jsonl"
    journal.write_text("", encoding="utf-8")

    result = _run_alert(journal)
    assert result.returncode == 1
    assert "is empty" in result.stdout
    assert "blind" in result.stdout

    report = health.evaluate(journal, interval_secs=TICK)
    assert not report.ok
    assert report.rows[0] == ("journal", "EMPTY — this check is blind")


def test_a_missing_journal_is_still_an_alert_even_beside_a_rotated_one(tmp_path):
    """A rotated file is a supplement, never a substitute for the live path.

    If the live journal has vanished, the validator is not writing where anyone
    is looking, and yesterday's records must not paper over that.
    """
    journal = tmp_path / "validator-events.jsonl"
    _write(journal.with_name(journal.name + ".1"), _alive())

    result = _run_alert(journal)
    assert result.returncode == 1
    assert "does not exist" in result.stdout

    with pytest.raises(health.JournalUnreadable):
        health.read_tail(journal)


# -- rule 5's streak still reads the two files in the right order ------------


def test_an_audit_recovery_after_a_rotation_still_clears_the_failure_streak(tmp_path):
    """Rotated records are older, so they must be read FIRST.

    Rule 5 alerts on the unbroken run of FAILs at the END of the window. Two
    failures before the rotation, then a completed audit after it, is a
    recovered validator. Reading the live file first would put the recovery at
    the start of the timeline and leave a two-FAIL streak at the end — an alert
    for a validator that already recovered.
    """
    journal = tmp_path / "validator-events.jsonl"
    _write(
        journal.with_name(journal.name + ".1"),
        [
            *_alive(ago_secs=2400),
            _record("PROVENANCE_AUDIT_FAIL", ago_secs=3000, status="FAIL"),
            _record("PROVENANCE_AUDIT_FAIL", ago_secs=1800, status="FAIL"),
        ],
    )
    _write(
        journal,
        [
            _record("PROVENANCE_AUDIT_NOT_PROVEN", ago_secs=600, status="NOT_PROVEN"),
            _record("WEIGHTS_SUBMITTED", ago_secs=60, uid_count=42),
        ],
    )

    result = _run_alert(journal)
    assert result.returncode == 0, result.stdout


def test_a_failure_streak_spanning_the_rotation_boundary_still_alerts(tmp_path):
    """The fallback must not hide a streak by splitting it across two files."""
    journal = tmp_path / "validator-events.jsonl"
    _write(
        journal.with_name(journal.name + ".1"),
        [
            *_alive(ago_secs=2400),
            _record("PROVENANCE_AUDIT_FAIL", ago_secs=1800, status="FAIL"),
        ],
    )
    _write(
        journal,
        [
            _record("PROVENANCE_AUDIT_FAIL", ago_secs=600, status="FAIL"),
            _record("WEIGHTS_SUBMITTED", ago_secs=60, uid_count=42),
        ],
    )

    result = _run_alert(journal)
    assert result.returncode == 1
    assert "consecutive audits" in result.stdout


# -- read_tail's own contract ------------------------------------------------


def test_read_tail_merges_the_rotated_generation_oldest_first(tmp_path):
    journal = tmp_path / "validator-events.jsonl"
    _write(
        journal.with_name(journal.name + ".1"),
        [_record("STARTUP", ago_secs=3000, status="INFO")],
    )
    _write(journal, [_record("WEIGHTS_SUBMITTED", ago_secs=60)])

    assert [row["event"] for row in health.read_tail(journal)] == [
        "STARTUP",
        "WEIGHTS_SUBMITTED",
    ]


def test_read_tail_ignores_the_rotated_generation_once_the_budget_is_spent(tmp_path):
    """A long-running validator pays nothing for the fallback."""
    journal = tmp_path / "validator-events.jsonl"
    _write(
        journal.with_name(journal.name + ".1"),
        [_record("STARTUP", ago_secs=3000, status="INFO")],
    )
    _write(journal, [_record("WEIGHTS_SUBMITTED", ago_secs=60)] * 40)

    events = [
        row["event"]
        for row in health.read_tail(journal, tail_bytes=journal.stat().st_size)
    ]
    assert "STARTUP" not in events


def test_an_unreadable_rotated_generation_is_not_itself_an_alert(tmp_path):
    journal = _write(tmp_path / "validator-events.jsonl", _alive())
    rotated = journal.with_name(journal.name + ".1")
    rotated.write_text("{ not json\n", encoding="utf-8")

    assert health.evaluate(journal, interval_secs=TICK).ok
    assert _run_alert(journal).returncode == 0


# -- the fragment itself -----------------------------------------------------


def _fragment_body() -> str:
    text = FRAGMENT.read_text(encoding="utf-8")
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_the_fragment_rotates_the_log_directory_and_nothing_durable():
    body = _fragment_body()
    assert re.search(r"^/var/log/cathedral-validator/\*\.jsonl \{", body, re.M)
    assert "/var/lib/cathedral-validator" not in body, (
        "the submission fences and the signed-attempt journal live there; "
        "rotating or truncating one of those is how a validator double-submits"
    )


def test_the_fragment_uses_copytruncate_and_never_create():
    """`scaffold.events` holds the descriptor open, so the inode must survive."""
    body = _fragment_body()
    assert re.search(r"^\s*copytruncate$", body, re.M)
    assert not re.search(r"^\s*create\b", body, re.M)
    assert not re.search(r"^\s*(sharedscripts|postrotate)\b", body, re.M)


def test_the_fragment_leaves_one_generation_uncompressed_for_the_readers():
    """Both monitors read `<journal>.1` as plain text; compressing it blinds them."""
    body = _fragment_body()
    assert re.search(r"^\s*delaycompress$", body, re.M)
    assert re.search(r"^\s*(maxsize|size)\s+\d+[kKmMgG]?$", body, re.M)
    assert re.search(r"^\s*rotate\s+\d+$", body, re.M)
    assert re.search(r"^\s*notifempty$", body, re.M)
    assert re.search(r"^\s*missingok$", body, re.M)


def test_the_fragment_drops_to_the_identity_that_owns_the_log_directory():
    """/var/log/cathedral-validator is not root-owned, so `su` is required."""
    body = _fragment_body()
    assert re.search(
        r"^\s*su\s+cathedral-validator\s+cathedral-validator-log$", body, re.M
    )


def test_the_readme_relay_install_installs_the_rotation_fragment():
    """An operator who follows README top to bottom must actually get it."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Supported systemd install (relay)")
    end = readme.index("## What it does", start)
    section = readme[start:end]
    for line in (
        '"$release/deploy/sn39/cathedral-validator.logrotate"',
        "/etc/logrotate.d/cathedral-validator",
    ):
        assert line in section, line
