"""Rule 2 of the shadow-audit alert must de-noise on a THIRD-PARTY relay too.

``deploy/sn39/cathedral-mismatch-check`` rule 2 exists to page an operator when
the shadow audit stops recovering. Its documented de-noising was keyed on
``PROVENANCE_AUDIT_PASS``: one FAIL alerted unless a PASS followed it.

That is inoperative on a relay. ``PROVENANCE_AUDIT_PASS`` is emitted only when
the audit reaches ``min_assurance`` (default ``rewarded_set_proven``), and the
shipped relay profile is ``receipts_only`` BY DESIGN — no controlled evidence
package, no evidence group on its unit, no ``min_assurance`` override. Its
steady state is ``PROVENANCE_AUDIT_NOT_PROVEN`` on every tick, forever, and it
never emits a PASS at all. So rule 2 collapsed to "any single
``PROVENANCE_AUDIT_FAIL`` in 90 minutes alerts" — and since any exception in
the audit becomes FAIL, one 60-second hiccup on the publisher's evidence
endpoint paged the operator for 90 minutes with a sentence ("failing for 90m
with no PASS") that was not true. Operators silence timers that lie, and rule 1
— the mismatch alarm that actually matters — goes with it.

Recovery is now "the next audit completed with any outcome other than FAIL",
and it takes two consecutive FAILs to alert. These tests pin both the relay's
steady state and the operator's, and that the real alarms still fire.
"""

from __future__ import annotations

import datetime
import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "sn39" / "cathedral-mismatch-check"

# One audit cycle. The thin tick is ~1500s, so 90 minutes is ~3 cycles.
CYCLE_MINUTES = 25


def _write_journal(path: Path, events: list[tuple[int, str]]) -> Path:
    """Write a journal in the exact on-disk shape ``scaffold.events`` emits.

    Compact separators, ``ts`` first, ``event`` second — see
    ``EventLogger.event``. ``test_the_script_parses_a_really_emitted_line``
    below pins that this shape is not drifting from the emitter.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    def _stamp(minutes_ago: float) -> str:
        at = now - datetime.timedelta(minutes=minutes_ago)
        return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"

    lines = []
    for minutes_ago, code in events:
        # Each real tick both COMPLETES and produces an audit outcome. Emitting
        # the completion is what keeps these fixtures about rule 5: the alert's
        # liveness rules (1-3) run first and would otherwise fire on every
        # fixture here for having no completed tick at all, masking the rule
        # actually under test. See test_liveness_alert.py for rules 1-3.
        lines.append(
            json.dumps(
                {
                    "ts": _stamp(minutes_ago + 0.1),
                    "event": "WEIGHT_COOLDOWN_SKIPPED",
                    "stage": "weights",
                    "status": "INFO",
                },
                separators=(",", ":"),
            )
        )
        lines.append(
            json.dumps(
                {
                    "ts": _stamp(minutes_ago),
                    "event": code,
                    "stage": "provenance",
                    "mode": "shadow",
                    "status": "FAIL" if code.endswith("FAIL") else "NOT_PROVEN",
                },
                separators=(",", ":"),
            )
        )
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def _check(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def _relay_ticks(count: int, *, newest_minutes_ago: int = 5) -> list[tuple[int, str]]:
    """A receipts-only relay's steady state: NOT_PROVEN on every tick."""
    return [
        (newest_minutes_ago + CYCLE_MINUTES * i, "PROVENANCE_AUDIT_NOT_PROVEN")
        for i in reversed(range(count))
    ]


# -- the relay's steady state is not an alert -------------------------------


def test_a_relays_permanent_not_proven_steady_state_never_alerts(tmp_path):
    journal = _write_journal(tmp_path / "events.jsonl", _relay_ticks(4))
    result = _check(journal)
    assert result.returncode == 0, result.stdout


def test_one_transient_fail_between_relay_heartbeats_does_not_alert(tmp_path):
    """The regression this file exists for.

    Before the fix this exited 1 and printed "failing for 90m with no PASS",
    which was false in every particular: one audit failed, the next one
    completed, and no PASS was ever expected on this runtime.
    """
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (80, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (55, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (30, "PROVENANCE_AUDIT_FAIL"),
            (5, "PROVENANCE_AUDIT_NOT_PROVEN"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 0, result.stdout
    assert "failing for 90m" not in result.stdout


def test_a_lone_most_recent_fail_does_not_alert(tmp_path):
    """The threshold itself, pinned.

    Every other non-alerting case here puts a completed audit AFTER the FAIL, so
    the trailing streak is 0 and the rule would pass at any threshold >= 1. This
    is the one shape that distinguishes them: the FAIL is the newest outcome, so
    the streak is exactly 1. Two consecutive is the bar because a single failed
    audit has not yet had a cycle to recover, and paging on it is what made the
    old rule cry wolf on every relay. Mutating the threshold to 1 must fail here
    and nowhere else.
    """
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (80, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (55, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (30, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (5, "PROVENANCE_AUDIT_FAIL"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 0, result.stdout
    assert "consecutive" not in result.stdout


def test_a_completed_audit_after_two_fails_clears_the_streak(tmp_path):
    """Recovery is 'the next audit completed', not 'a PASS' — pinned.

    Counts the run of FAILs at the END of the window, so a relay that failed
    twice and then completed an audit is recovering and must stop paging. On a
    relay that recovery arrives as NOT_PROVEN, never as PASS, which is the whole
    reason this rule was rewritten. Deleting the reset in the streak counter
    must fail here.
    """
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (80, "PROVENANCE_AUDIT_FAIL"),
            (55, "PROVENANCE_AUDIT_FAIL"),
            (30, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (5, "PROVENANCE_AUDIT_NOT_PROVEN"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 0, result.stdout
    assert "consecutive" not in result.stdout


def test_a_relay_that_stops_recovering_still_alerts(tmp_path):
    """De-noising is not silencing: two consecutive FAILs page the operator."""
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (80, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (55, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (30, "PROVENANCE_AUDIT_FAIL"),
            (5, "PROVENANCE_AUDIT_FAIL"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 1
    assert "2 consecutive" in result.stdout


# -- the operator profile's behaviour is unchanged where it mattered --------


def test_a_transient_fail_followed_by_a_pass_does_not_alert(tmp_path):
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (55, "PROVENANCE_AUDIT_PASS"),
            (30, "PROVENANCE_AUDIT_FAIL"),
            (5, "PROVENANCE_AUDIT_PASS"),
        ],
    )
    assert _check(journal).returncode == 0


def test_a_persistently_failing_audit_alerts(tmp_path):
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (80, "PROVENANCE_AUDIT_PASS"),
            (55, "PROVENANCE_AUDIT_FAIL"),
            (30, "PROVENANCE_AUDIT_FAIL"),
            (5, "PROVENANCE_AUDIT_FAIL"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 1
    assert "3 consecutive" in result.stdout


# -- window and event-name boundaries ---------------------------------------


def test_an_empty_journal_alerts_because_the_check_is_blind(tmp_path):
    """Rule 1 owns this now, and it alerts on purpose.

    This rule used to exit 0 on an empty journal, on the reasoning that an
    empty window is not evidence of a problem. It is evidence that this check
    cannot see the validator, which #98 established must never be reported the
    same way as "the validator is fine". Rule 5 still does not alert on an
    empty window — it never gets to run.
    """
    journal = _write_journal(tmp_path / "events.jsonl", [])
    result = _check(journal)
    assert result.returncode == 1
    assert "blind" in result.stdout
    assert "consecutive" not in result.stdout


def test_a_missing_journal_alerts_because_the_check_is_blind(tmp_path):
    """Same inversion, and the one that actually bit us.

    A missing journal used to print "no recent mismatch; shadow audit not
    persistently failing" and exit 0 — a crashed validator, a wrong path, or
    twelve hours of no weights all left the alert green.
    """
    result = _check(tmp_path / "absent.jsonl")
    assert result.returncode == 1
    assert "does not exist" in result.stdout


def test_consecutive_fails_older_than_the_window_do_not_alert(tmp_path):
    """Rule 5 looks back 90 minutes and no further.

    The recent NOT_PROVEN pair is what keeps the validator live for rules 1-3,
    so the only thing left that could alert is the old FAIL pair — and it is
    outside the window.
    """
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (300, "PROVENANCE_AUDIT_FAIL"),
            (275, "PROVENANCE_AUDIT_FAIL"),
            (30, "PROVENANCE_AUDIT_NOT_PROVEN"),
            (5, "PROVENANCE_AUDIT_NOT_PROVEN"),
        ],
    )
    assert _check(journal).returncode == 0


def test_the_stale_epoch_event_is_still_not_an_audit_outcome(tmp_path):
    """PROVENANCE_VECTOR_STALE_EPOCH must not be read as a FAIL or a recovery."""
    journal = _write_journal(
        tmp_path / "events.jsonl",
        [
            (30, "PROVENANCE_VECTOR_STALE_EPOCH"),
            (5, "PROVENANCE_AUDIT_NOT_PROVEN"),
        ],
    )
    result = _check(journal)
    assert result.returncode == 0, result.stdout


def test_rule_1_still_fires_on_a_recent_mismatch(tmp_path):
    journal = _write_journal(
        tmp_path / "events.jsonl", [(5, "PROVENANCE_VECTOR_MISMATCH")]
    )
    result = _check(journal)
    assert result.returncode == 1
    assert "PROVENANCE_VECTOR_MISMATCH" in result.stdout


def test_a_stale_mismatch_does_not_borrow_rule_2s_window(tmp_path):
    """Rule 1's window is 30 minutes and rule 2 does not read mismatches."""
    journal = _write_journal(
        tmp_path / "events.jsonl", [(75, "PROVENANCE_VECTOR_MISMATCH")]
    )
    assert _check(journal).returncode == 0


# -- the parser is pinned to what the emitter really writes -----------------


def test_the_script_parses_a_really_emitted_line(tmp_path):
    """Emit through ``scaffold.events`` itself, not a hand-built line.

    Rule 2 reads the journal with grep/sed. If the record shape ever drifts —
    field order, separators, timestamp format — the rule would silently stop
    seeing audits and stop alerting. Two real FAILs must alert.
    """
    events = pytest.importorskip("scaffold.events")
    journal = tmp_path / "emitted.jsonl"
    logger = events.EventLogger(mode="shadow", jsonl_path=str(journal))
    try:
        for _ in range(2):
            # A completed tick alongside each audit, emitted through the same
            # logger, so the liveness rules are satisfied by real records and
            # this test is about rule 5's parsing rather than rule 3's.
            logger.event(
                "WEIGHT_COOLDOWN_SKIPPED", stage="weights", status=events.INFO
            )
            logger.event(
                "PROVENANCE_AUDIT_FAIL",
                stage="provenance",
                status=events.FAIL,
                detail="EvidenceError: evidence index is stale",
            )
    finally:
        logger.close()

    result = _check(journal)
    assert result.returncode == 1, result.stdout
    assert "2 consecutive" in result.stdout


def test_the_documented_relay_profile_really_is_receipts_only():
    """The premise of the fix, pinned in the config the third party installs.

    If a future relay profile ever sets ``min_assurance = "receipts_only"`` or
    ships a controlled evidence package, its steady state becomes PASS and this
    file's reasoning would need revisiting — but the de-noising stays correct
    either way, so this only has to stay TRUE, not stay unchanged.
    """
    relay = (REPO / "config" / "validator-thin-sn39-relay.toml").read_text(
        encoding="utf-8"
    )
    assert "min_assurance" not in relay
    assert "controlled_dir" not in relay.replace(
        "# controlled_dir and verifier_binary are deliberately absent", ""
    )
