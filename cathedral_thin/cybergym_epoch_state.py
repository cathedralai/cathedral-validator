"""Durable per-audience epoch state: a monotonic high-water mark and a conflict digest.

Why this exists. Verifying that a proof names the epoch being composed is a
same-request check: it cannot see what any EARLIER authoritative pass composed. So a
validator would accept an authoritative pass for epoch 12 and then another for epoch
11, because each proof correctly named its own epoch and each burned a distinct
per-epoch replay token. Both earned. Reproduced before this module existed.

That is an epoch ROLLBACK, and it is the reward-relevant one: a producer (or an
operator replaying an old bundle) can re-run a superseded epoch's scores after a
later epoch has already paid, crediting a set the current epoch had moved past.

Two properties, both keyed by audience so two subnets on one host cannot interfere:

  * a monotonic high-water mark, so an epoch strictly below the highest already
    composed is refused;
  * a per-epoch proof digest, so re-running the SAME epoch is allowed (that is how a
    crashed pass recovers) but only with byte-identical evidence. A second, different
    proof for an epoch already composed is a conflict and is refused.

Durability is the whole point, so this is a file-backed SQLite database and an
in-memory path is refused, exactly as ``cathedral_distill.consumption_ledger`` does:
state that forgets on restart fails OPEN, which would let a restart erase the
high-water mark and re-admit the rollback this module exists to stop.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BUSY_TIMEOUT_MS = 5_000


class EpochStateError(RuntimeError):
    """The epoch could not be admitted, or the state could not be recorded.

    Raised for a refusal AND for an unrecordable write, because a high-water mark
    that was not durably recorded is indistinguishable from one that never existed.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class AudienceEpochState:
    network: str
    netuid: int
    high_water: int | None
    proof_digest: str | None


class CyberGymEpochState:
    """File-backed monotonic epoch state, one row per (network, netuid, epoch)."""

    def __init__(self, db_path: str, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS):
        if not isinstance(db_path, str) or not db_path.strip():
            raise EpochStateError(
                "not_durable",
                "epoch state requires a durable database path (no default)",
            )
        if db_path == ":memory:" or "mode=memory" in db_path:
            # An in-memory high-water mark forgets on restart, which fails OPEN: the
            # rollback this class refuses would be re-admitted by a bounce.
            raise EpochStateError(
                "not_durable",
                f"{db_path!r} is not durable; a forgotten high-water mark fails open",
            )
        self._path = db_path
        self._busy_timeout_ms = int(busy_timeout_ms)
        parent = Path(db_path).expanduser().parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=self._busy_timeout_ms / 1000)
        conn.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cybergym_epoch_state (
                    network      TEXT    NOT NULL,
                    netuid       INTEGER NOT NULL,
                    source_epoch INTEGER NOT NULL,
                    proof_digest TEXT    NOT NULL,
                    recorded_at  TEXT    NOT NULL,
                    PRIMARY KEY (network, netuid, source_epoch)
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def state(self, *, network: str, netuid: int) -> AudienceEpochState:
        """The highest epoch composed for this audience, and its proof digest."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT source_epoch, proof_digest FROM cybergym_epoch_state "
                "WHERE network=? AND netuid=? ORDER BY source_epoch DESC LIMIT 1",
                (str(network), int(netuid)),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return AudienceEpochState(str(network), int(netuid), None, None)
        return AudienceEpochState(str(network), int(netuid), int(row[0]), str(row[1]))

    def admit(
        self,
        *,
        network: str,
        netuid: int,
        source_epoch: int,
        proof_digest: str,
        recorded_at: str,
    ) -> None:
        """Admit and durably record this epoch, or raise ``EpochStateError``.

        Refuses an epoch below the high-water mark (a rollback), and refuses a second
        DIFFERENT proof for an epoch already recorded (a conflict). Re-running the
        same epoch with byte-identical evidence is permitted and is a no-op, because
        that is how a pass that crashed after recording recovers.
        """
        network = str(network)
        netuid = int(netuid)
        source_epoch = int(source_epoch)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT source_epoch FROM cybergym_epoch_state "
                "WHERE network=? AND netuid=? ORDER BY source_epoch DESC LIMIT 1",
                (network, netuid),
            ).fetchone()
            high_water = None if row is None else int(row[0])
            if high_water is not None and source_epoch < high_water:
                raise EpochStateError(
                    "epoch_rollback",
                    f"epoch {source_epoch} is below the high-water mark {high_water} "
                    f"for {network}/{netuid}; a superseded epoch cannot compose again",
                )
            existing = conn.execute(
                "SELECT proof_digest FROM cybergym_epoch_state "
                "WHERE network=? AND netuid=? AND source_epoch=?",
                (network, netuid, source_epoch),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != str(proof_digest):
                    raise EpochStateError(
                        "epoch_proof_conflict",
                        f"epoch {source_epoch} was already composed for "
                        f"{network}/{netuid} with different evidence",
                    )
                conn.commit()
                return
            conn.execute(
                "INSERT INTO cybergym_epoch_state"
                "(network, netuid, source_epoch, proof_digest, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (network, netuid, source_epoch, str(proof_digest), str(recorded_at)),
            )
            conn.commit()
        except EpochStateError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            # An unrecordable high-water mark must not be treated as recorded.
            conn.rollback()
            raise EpochStateError("not_recorded", str(exc)) from exc
        finally:
            conn.close()


__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "AudienceEpochState",
    "CyberGymEpochState",
    "EpochStateError",
]
