"""Every external score source is bound to one audience, and so is its fence.

An external report is only meaningful for the exact (network, netuid) this
publisher signs weights for. Accepting a foreign or absent audience for any
source, or fencing epochs on ``source`` alone, lets one audience's report
decide another audience's payout: a testnet report at a high epoch locks the
mainnet source out of its own fence.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from scaffold.publisher import external_scores
from scaffold.publisher.store import Store

NETWORK = "finney"
NETUID = 39


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def _report(source: str, *, epoch: int = 1, **overrides) -> dict:
    report = {
        "source": source,
        "generated_at": _now_iso(),
        "scores": [{"miner_hotkey": "5Alice", "score": 0.5}],
        "complete": True,
        "epoch": epoch,
        "network": NETWORK,
        "netuid": NETUID,
    }
    report.update(overrides)
    return report


@pytest.fixture(autouse=True)
def _local_audience(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETWORK", NETWORK)
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETUID", str(NETUID))


@pytest.fixture
def store(tmp_path) -> Store:
    return Store(str(tmp_path / "publisher.sqlite"), prefer_env_database_url=False)


@pytest.mark.parametrize("source", sorted(external_scores.ALLOWED_ENDPOINT_SOURCES))
def test_every_source_rejects_a_foreign_audience(source):
    with pytest.raises(external_scores.ExternalScoreError) as exc:
        external_scores.normalize_report(
            _report(source, network="test", netuid=1),
            default_source=source,
        )
    assert exc.value.reason == "score_audience_mismatch"


@pytest.mark.parametrize("source", sorted(external_scores.ALLOWED_ENDPOINT_SOURCES))
def test_every_source_rejects_a_missing_audience(source):
    payload = _report(source)
    del payload["network"]
    del payload["netuid"]
    with pytest.raises(external_scores.ExternalScoreError) as exc:
        external_scores.normalize_report(payload, default_source=source)
    assert exc.value.reason == "invalid_score_audience"


@pytest.mark.parametrize("source", sorted(external_scores.ALLOWED_ENDPOINT_SOURCES))
def test_foreign_audience_row_cannot_move_the_local_fence(store, source):
    """A stored report for another audience must not fence this audience."""

    foreign_json = json.dumps(
        _report(source, epoch=999, network="test", netuid=1),
        sort_keys=True,
        separators=(",", ":"),
    )

    def insert_foreign(conn):
        conn.execute(
            "INSERT INTO external_score_reports"
            "(id, source, network, netuid, epoch, generated_at_iso, received_at_iso, "
            "report_sha256, score_count, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"foreign-{source}",
                source,
                "test",
                1,
                999,
                _now_iso(),
                _now_iso(),
                "0" * 64,
                1,
                foreign_json,
            ),
        )

    store.write(insert_foreign)
    local = external_scores.normalize_report(_report(source, epoch=5), default_source=source)
    local = external_scores.bind_authenticated_body(local, b"{}")
    accepted = external_scores.store_report(store, local)
    assert accepted["epoch"] == 5


@pytest.mark.parametrize("source", sorted(external_scores.ALLOWED_ENDPOINT_SOURCES))
def test_unaudienced_row_cannot_move_the_local_fence(store, source):
    """A legacy row written before audiences existed must not fence either."""

    legacy_json = json.dumps(
        {
            "source": source,
            "epoch": 999,
            "complete": True,
            "generated_at": _now_iso(),
            "scores": [{"miner_hotkey": "5Legacy", "score": 1.0}],
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    def insert_legacy(conn):
        conn.execute(
            "INSERT INTO external_score_reports"
            "(id, source, epoch, generated_at_iso, received_at_iso, "
            "report_sha256, score_count, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"legacy-{source}",
                source,
                999,
                _now_iso(),
                _now_iso(),
                "0" * 64,
                1,
                legacy_json,
            ),
        )

    store.write(insert_legacy)
    local = external_scores.normalize_report(_report(source, epoch=5), default_source=source)
    local = external_scores.bind_authenticated_body(local, b"{}")
    accepted = external_scores.store_report(store, local)
    assert accepted["epoch"] == 5
    assert external_scores.latest_snapshot_scores(store, source=source) == {"5Alice": 0.5}


class _EmptyCursor:
    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _RecordingPostgresStore:
    """Enough of Store to observe what the epoch fence actually serialises."""

    backend = "postgres"

    def __init__(self):
        self.statements: list[tuple[str, tuple]] = []

    def write(self, fn):
        return fn(self)

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        return _EmptyCursor()


@pytest.mark.parametrize("source", sorted(external_scores.ALLOWED_ENDPOINT_SOURCES))
def test_epoch_fence_lock_and_gate_serialise_the_same_audience(source):
    """The advisory lock is keyed on the audience, so the gate must be too."""

    store = _RecordingPostgresStore()
    report = external_scores.normalize_report(_report(source), default_source=source)
    report = external_scores.bind_authenticated_body(report, b"{}")
    external_scores.store_report(store, report)

    locks = [p for sql, p in store.statements if "pg_advisory_xact_lock" in sql]
    assert locks == [(external_scores._audience_lock_key(source, NETWORK, NETUID),)]

    fences = [
        (sql, p)
        for sql, p in store.statements
        if sql.startswith("SELECT epoch, report_sha256 FROM external_score_reports")
    ]
    assert len(fences) == 1
    fence_sql, fence_params = fences[0]
    assert "network=?" in fence_sql and "netuid=?" in fence_sql
    assert fence_params == (source, NETWORK, NETUID)
