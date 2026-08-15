"""The external-score epoch fence must not be poisonable by one oversized epoch.

``store_report`` refuses any epoch below the highest already stored for a
source/audience (anti-rollback). Nothing bounded the epoch a producer could
declare, so a single accepted 2**63-1 sets that high-water mark forever: every
later honest report is refused as ``epoch_too_old``, the poisoned snapshot ages
out of the freshness window, the confidential primary degrades, and the lane
collapses to burn. No code path deletes ``external_score_reports`` rows, so the
only recovery is a hand DB edit.

``cybergym_ingest`` already bounds its own producer counter for exactly this
reason; the same fence needs the same bound.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from scaffold.publisher import external_scores
from scaffold.publisher.store import Store

# 2**63-1 binds cleanly to SQLite INTEGER and Postgres BIGINT, so it is the
# largest value an attacker can actually get persisted.
POISON_EPOCH = 2**63 - 1


def _iso(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{dt.microsecond // 1000:03d}Z"
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "test.db"))


def _payload(epoch, now: datetime) -> dict:
    return {
        "source": "violet_audio",
        "epoch": epoch,
        "complete": True,
        "generated_at": _iso(now),
        "scores": [{"miner_hotkey": "5A", "score": 0.5}],
    }


def _store(store: Store, epoch, now: datetime) -> dict:
    report = external_scores.normalize_report(_payload(epoch, now), now=now)
    return external_scores.store_report(store, report)


def test_oversized_epoch_does_not_wedge_later_honest_reports(store):
    """One absurd epoch must not leave the fence above every real epoch."""
    now = _now()
    try:
        _store(store, POISON_EPOCH, now)
    except external_scores.ExternalScoreError as exc:
        assert exc.reason == "invalid_epoch"

    # The source must still be usable: honest epochs land and keep advancing.
    assert _store(store, 7, now)["status"] == "accepted"
    assert _store(store, 8, now)["status"] == "accepted"


@pytest.mark.parametrize(
    "epoch",
    [
        POISON_EPOCH,
        2**31,       # first value above the bound
        -1,          # negative
        True,        # bool is an int subclass
        1.5,         # float
        "7",         # numeric string
    ],
)
def test_out_of_contract_epoch_rejected(epoch):
    now = _now()
    with pytest.raises(external_scores.ExternalScoreError, match="invalid_epoch"):
        external_scores.normalize_report(_payload(epoch, now), now=now)


@pytest.mark.parametrize("epoch", [0, 1, 2**31 - 1])
def test_in_contract_epoch_accepted(epoch):
    now = _now()
    report = external_scores.normalize_report(_payload(epoch, now), now=now)
    assert report["epoch"] == epoch


def test_missing_epoch_still_defaults_to_zero():
    """Legacy producers omit epoch entirely; that contract is unchanged."""
    now = _now()
    payload = _payload(1, now)
    del payload["epoch"]
    assert external_scores.normalize_report(payload, now=now)["epoch"] == 0

    payload = _payload(None, now)
    assert external_scores.normalize_report(payload, now=now)["epoch"] == 0


def test_epoch_bound_matches_cybergym_ingest():
    """Both fences are the same mechanism; they must not drift apart."""
    from scaffold.publisher import cybergym_ingest

    assert external_scores._MAX_EPOCH == cybergym_ingest._MAX_SOURCE_EPOCH
