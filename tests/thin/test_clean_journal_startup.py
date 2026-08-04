"""Clean-journal startup is the ONLY path into attestation-verified/thin.

Encodes the pitfall learned the hard way: attestation-verified must be reachable
from a CLEAN validator deploy with a fresh journal, and NEVER by hand-editing
live state. A stale ``submission_active_lane="authority"`` trips the persistent
authority->thin fence; a ``submission_finalized_id`` trips the "recovery record
is contradictory" check. Both WEDGE startup. These tests lock:

  (a) a clean journal (absent / ``{}``) admits a first thin reservation cleanly;
  (b) a journal pre-seeded with an authority lane REJECTS a thin reservation
      (the wedge you get by editing live state — must fail, not silently flip);
  (c) a journal carrying a half-written finalized record trips the contradiction
      check rather than being silently accepted;
  (d) deploy/publisher/init-clean-journal.sh REFUSES to run against an existing
      journal (forcing the archive-not-edit migration), and provisions a clean
      one on an absent file.
"""

from __future__ import annotations

import getpass
import pathlib
import subprocess
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as vt


ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy" / "publisher" / "init-clean-journal.sh"

_ATTEMPT = "sha256:" + "0" * 64


def _thin_reservation_updates(policy_version: int = 1) -> dict:
    """Minimal valid first thin pre-sign reservation for _write_state_fenced."""
    return {
        "submission_pending_id": _ATTEMPT,
        "_provisional_submission": True,
        "submission_pending_lane": "thin",
        "submission_pending_identity": {"validator_hotkey": "5Test"},
        "submission_highest_policy_version": policy_version,
    }


# -- (a) clean journal admits a first thin reservation ----------------------


def test_absent_journal_admits_first_thin_reservation(tmp_path) -> None:
    state_file = tmp_path / "thin-state.json"
    # Absent file == "no fence yet"; the reservation must land.
    vt._write_state_fenced(state_file, _thin_reservation_updates())
    doc = vt._read_state(state_file)
    assert doc["submission_pending_lane"] == "thin"
    assert doc["submission_pending_phase"] == "unsigned_reserved"


def test_empty_object_journal_admits_first_thin_reservation(tmp_path) -> None:
    state_file = tmp_path / "thin-state.json"
    vt._write_state(state_file, {})  # literal {} clean shape
    assert vt._read_state(state_file) == {}
    vt._write_state_fenced(state_file, _thin_reservation_updates())
    assert vt._read_state(state_file)["submission_pending_lane"] == "thin"


# -- (b) an authority-seeded journal WEDGES a thin reservation --------------


def test_authority_lane_journal_rejects_a_thin_reservation(tmp_path) -> None:
    state_file = tmp_path / "thin-state.json"
    # Simulate the wedged live-edit: a stale authority lane pinned in state.
    vt._write_state(state_file, {"submission_active_lane": "authority"})
    with pytest.raises(
        ValueError, match="lane changed without explicit operator reconciliation"
    ):
        vt._write_state_fenced(state_file, _thin_reservation_updates())


# -- (c) a half-written finalized record trips the contradiction check ------


def test_clean_journal_does_not_trip_finalized_recovery() -> None:
    # attempt_id absent -> nothing to recover, returns None (not a raise).
    assert vt._recover_common_finalized_submission(SimpleNamespace(), {}) is None


def test_contradictory_finalized_record_is_rejected() -> None:
    # A finalized id + lane with none of the paired pending/receipt fields is
    # exactly the "recovery record is contradictory" wedge.
    state = {
        "submission_finalized_id": "sha256:" + "a" * 64,
        "submission_finalized_lane": "thin",
    }
    with pytest.raises(vt._PostSignedSubmissionMismatch, match="contradictory"):
        vt._recover_common_finalized_submission(SimpleNamespace(), state)


# -- (d) the init helper enforces archive-not-edit --------------------------


def test_helper_refuses_an_existing_journal(tmp_path) -> None:
    state_file = tmp_path / "thin-state.json"
    state_file.write_text("{}", encoding="utf-8")
    result = subprocess.run(
        [str(HELPER), "--state-file", str(state_file), "--owner", getpass.getuser()],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "REFUSING" in result.stderr


def test_helper_provisions_a_clean_empty_journal(tmp_path) -> None:
    runtime_root = tmp_path / "cathedral-validator"
    state_file = runtime_root / "thin-state.json"
    result = subprocess.run(
        [
            str(HELPER),
            "--mode",
            "empty",
            "--state-file",
            str(state_file),
            "--owner",
            getpass.getuser(),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert state_file.read_text(encoding="utf-8") == "{}"
    # And that clean journal loads + admits a thin reservation.
    assert vt._read_state(state_file) == {}
    vt._write_state_fenced(state_file, _thin_reservation_updates())
    assert vt._read_state(state_file)["submission_pending_lane"] == "thin"


def test_helper_absent_mode_leaves_no_journal(tmp_path) -> None:
    runtime_root = tmp_path / "cathedral-validator"
    state_file = runtime_root / "thin-state.json"
    result = subprocess.run(
        [str(HELPER), "--state-file", str(state_file), "--owner", getpass.getuser()],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not state_file.exists()
    assert runtime_root.is_dir()
