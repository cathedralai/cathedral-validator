"""The signed-attempt journal is bounded, and bounding it costs no protection.

``submission_attempt_ids`` used to be append-only forever. On the live SN39 box
it reached 77 entries (5775 bytes) in nine days inside a document that is read,
re-serialized and fsynced IN FULL on every state write while the submission
lock is held, so the cost of the journal is paid by the write path itself and
grows without limit.

Bounding a replay-protection structure is only safe if something else already
excludes what it drops, and here something does. Every entry is a SIGNED
attempt whose id is ``sha256(dedup_identity)``, and that identity carries the
lane's monotone field — ``policy_version`` for thin, ``source_epoch`` for
authority. The commit that appends the id writes the matching high-water in the
same atomic fsync, and no path ever lowers or deletes it. Re-deriving an
evicted id therefore needs a reservation whose policy version is at once equal
to and greater than the stored fence, which is refused BEFORE the membership
test is ever consulted.

That is what the tests below pin: the journal stops growing, an id it evicted
is still refused, the two ids a reader looks up are never dropped, and the
lifetime counter keeps telling the truth about how many attempts there were.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as vt


def _args(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        netuid=39,
        offline=False,
        runtime_root=str(tmp_path),
        max_submissions=0,
        require_full_provenance_for_broadcast=False,
        _submission_validator_hotkey="validator",
        _submission_genesis_hash=vt.FINNEY_GENESIS_HASH,
    )


def _identity(policy_version: int) -> dict:
    return {
        "policy_version": policy_version,
        "uid_weights": [[7, 0.9], [241, 0.1]],
        "uid_hotkeys": [[7, "worker"], [241, "burn"]],
    }


def _attempt_id(policy_version: int) -> str:
    return "sha256:" + f"{policy_version:064x}"


def _signed_attempt(args: SimpleNamespace, policy_version: int) -> str:
    """Drive one attempt through the real reserve -> sign -> retire lifecycle."""
    attempt_id = _attempt_id(policy_version)
    vt._reserve_common_submission(
        args,
        lane="thin",
        attempt_id=attempt_id,
        identity=_identity(policy_version),
    )
    vt._record_pending_broadcast_intent(
        args,
        attempt_id=attempt_id,
        extrinsic_hash="0x" + "a" * 64,
        nonce=policy_version,
        era_reference_block=100 + policy_version,
        mortal_period_blocks=vt.SN39_MORTAL_PERIOD_BLOCKS,
        version_key=vt._weight_version_key(),
        wire_uids=[7, 241],
        wire_weights=[65535, 7282],
    )
    # Retire it so the next reservation sees no pending fence. Expiry keeps the
    # attempt permanently ineligible, which is exactly the state the journal is
    # supposed to remember.
    vt._expire_pending_common_submission(args, attempt_id=attempt_id)
    return attempt_id


def _journal(args: SimpleNamespace) -> dict:
    return vt._read_state(vt._submission_state_path(args))


# -- the window itself -------------------------------------------------------


def test_the_signed_attempt_journal_stops_growing_without_bound(tmp_path, monkeypatch):
    """Six signed attempts, a window of three, three retained — newest last."""
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 3)
    args = _args(tmp_path)
    minted = [_signed_attempt(args, version) for version in range(1, 7)]

    assert _journal(args)["submission_attempt_ids"] == minted[-3:]


def test_the_default_window_is_wide_enough_for_the_readers_that_look_ids_up():
    """A regression guard on the constant, not on the mechanism.

    ``_recover_common_finalized_submission`` resolves ``submission_finalized_id``
    against this journal, and that id trails the tail by however many signed
    attempts were committed since the last proven inclusion. Each one consumes a
    slot from a continuous authorization, and one authorization is capped at 96
    attempts. Anything at or below that ceiling would put a real recovery inside
    the eviction window.
    """
    assert vt.SUBMISSION_ATTEMPT_ID_WINDOW >= 5 * 96


# -- the property that makes the window safe ---------------------------------


def test_an_evicted_attempt_is_still_refused_by_the_monotone_fence(
    tmp_path, monkeypatch
):
    """The money test: eviction must not reopen a retry window.

    The first attempt is pushed out of the journal, so the membership check can
    no longer see it. Replaying it is still refused — by the durable policy
    high-water the commit wrote in the same fsync that appended the id — and the
    refusal names that fence rather than the journal, which is the proof that
    the fence, not the list, is what closes this door.
    """
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 3)
    args = _args(tmp_path)
    replayed = _signed_attempt(args, 1)
    for version in range(2, 7):
        _signed_attempt(args, version)

    journal = _journal(args)
    assert replayed not in journal["submission_attempt_ids"]
    assert journal["submission_highest_policy_version"] == 6

    with pytest.raises(ValueError, match="common thin policy rollback 1 <= 6"):
        vt._reserve_common_submission(
            args,
            lane="thin",
            attempt_id=replayed,
            identity=_identity(1),
        )
    # And nothing was reserved on the way to that refusal.
    assert _journal(args)["submission_pending_id"] is None


def test_an_id_the_journal_still_holds_is_refused_by_the_journal(tmp_path, monkeypatch):
    """The membership check keeps working for everything inside the window."""
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 3)
    args = _args(tmp_path)
    for version in range(1, 4):
        _signed_attempt(args, version)

    # Same id, a policy version high enough to clear the fence: only the
    # journal can refuse this one, and it must.
    with pytest.raises(ValueError, match="already attempted"):
        vt._reserve_common_submission(
            args,
            lane="thin",
            attempt_id=_attempt_id(2),
            identity=_identity(9),
        )


# -- what the window must never drop -----------------------------------------


def test_the_finalized_id_a_recovery_resolves_is_never_evicted(tmp_path, monkeypatch):
    """``_recover_common_finalized_submission`` refuses a journal missing it."""
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 2)
    args = _args(tmp_path)
    finalized = _signed_attempt(args, 1)
    vt._write_state(
        vt._submission_state_path(args), {"submission_finalized_id": finalized}
    )
    for version in range(2, 8):
        _signed_attempt(args, version)

    retained = _journal(args)["submission_attempt_ids"]
    assert retained[0] == finalized
    assert len(retained) == 3, "the pinned id rides alongside the window, not in it"


def test_the_pending_signed_id_an_expiry_resolves_is_never_evicted(
    tmp_path, monkeypatch
):
    """A window of one still leaves ``_expire_pending_common_submission`` an id."""
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 1)
    args = _args(tmp_path)
    for version in range(1, 5):
        # _signed_attempt expires each attempt, which reads the journal back and
        # raises if the id it just signed is not there.
        _signed_attempt(args, version)

    assert _journal(args)["submission_attempt_ids"] == [_attempt_id(4)]


def test_the_lifetime_attempt_count_does_not_shrink_when_entries_are_evicted(
    tmp_path, monkeypatch
):
    """``count - len(ids)`` must keep naming how many were dropped."""
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 3)
    args = _args(tmp_path)
    for version in range(1, 10):
        _signed_attempt(args, version)

    journal = _journal(args)
    assert journal["submission_attempt_count"] == 9
    assert len(journal["submission_attempt_ids"]) == 3


# -- the helper's own contract -----------------------------------------------


def test_the_window_keeps_order_and_returns_a_copy(monkeypatch):
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 3)
    history = [_attempt_id(version) for version in range(1, 6)]
    bounded = vt._bounded_attempt_journal(history, ())
    assert bounded == history[2:]
    assert history == [_attempt_id(version) for version in range(1, 6)]


def test_a_journal_shorter_than_the_window_is_untouched(monkeypatch):
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 8)
    history = [_attempt_id(version) for version in range(1, 6)]
    assert vt._bounded_attempt_journal(history, ()) == history


def test_pinned_ids_are_kept_in_place_and_never_duplicated(monkeypatch):
    monkeypatch.setattr(vt, "SUBMISSION_ATTEMPT_ID_WINDOW", 2)
    history = [_attempt_id(version) for version in range(1, 6)]
    bounded = vt._bounded_attempt_journal(history, (history[0], history[4], None))
    assert bounded == [history[0], history[3], history[4]]
