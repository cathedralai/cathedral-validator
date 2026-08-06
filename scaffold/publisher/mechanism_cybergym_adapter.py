"""CyberGym mechanism adapter — plugs verified PoC scores into the router.

A sibling of ``mechanism_sat_adapter.py``. The router is workload-agnostic
(``deploy/MECHANISM_ROUTER_CONTRACT.md``: "SAT now; Hermes/Secure-Compute
later"), so CyberGym integrates as a *new mechanism*, not a router change. This
adapter turns the CyberGym validator's verified per-miner scores into a router
``ScoreVector`` keyed by miner UID.

Tier is ``artifact`` (proof-backed), not ``signed`` (a claim): a CyberGym score
is the level-weighted sum of *verified* PoC solves — each a differential crash
test (the PoC crashes the vulnerable build and not the patched one), which the
validator re-derives and never trusts a worker to report. That is the same
proof-backed posture as the SAT mechanism.

Score semantics mirror SAT: emission is **proportional to verified work**, not
winner-take-all. The CyberGym king-of-the-hill frontier is a separate
leaderboard/corpus-lineage concept (who is the reference model); emission
rewards every miner in proportion to the verified solves it produced this cycle.
A deployment that wants winner-take-all can write only the champion's row.

Reading contract (this is the part that has to be exactly right)
----------------------------------------------------------------
The adapter reads EXACTLY ONE report: the newest COMPLETE report for the
configured ``(network, netuid)`` audience, from the tables store.py migration
``0048_cybergym_scores`` creates and the authenticated ``cybergym_ingest`` route
populates. Two properties follow, and both are load-bearing:

  * **No epoch mixing.** Scores come from that one report's rows
    (``cybergym_scores.report_id``), never from a per-miner maximum epoch across
    reports. A complete report is the full truth at its epoch, so a miner
    omitted from it scores zero (revoked) instead of keeping an older value.
  * **Freshness comes from the authenticated ``generated_at``, never from read
    time.** ``ScoreVectorMeta.signed_at_ms`` is derived from the report's
    producer-generated timestamp, so a dead producer's frozen report ages out
    of the router's staleness gate instead of looking freshly signed on every
    read. The adapter additionally refuses a report older than
    ``CATHEDRAL_CYBERGYM_MAX_SCORE_AGE_SECS`` (default 3600s) so a caller that
    passes no ``max_score_age_ms`` still cannot be served stale scores. A
    future-dated report is refused too: a negative age can never exceed the
    maximum, so without that check it would read as fresh indefinitely.

``sig_ok`` is a VERIFICATION, not a column check. Before a report contributes,
the adapter re-derives the digest of the stored raw authenticated body,
re-verifies its HMAC against the configured producer secret, independently
normalizes it, and requires that result to equal the stored canonical semantic
body. It then re-derives the semantic report digest and cross-checks every
derived column and every score row. See
``cybergym_contract.verify_stored_report``, which also states
plainly what this does and does not prove: it detects rows written without the
secret and any later tampering, and it does not establish producer identity
beyond possession of a shared secret. With no secret configured nothing can be
verified, so the lane contributes nothing and its share burns.

An earlier revision of this module checked only that the ``body_sha256`` column
held 64 hex characters, which a hand-inserted row satisfies trivially. That was
a presence check wearing the name of an authentication check.

``hotkey -> uid`` mapping comes from the ``metagraph_hotkeys`` snapshot table,
exactly as the SAT adapter and ``mechanism_eligibility`` use it.

Guardrails (identical to the SAT adapter):
  - Read-only: writes no table, modifies no write path.
  - Default off: nothing calls this until a ``MechanismSpec`` wires it into the
    router; it has no effect on any live weight vector on its own.
  - Deterministic: no randomness, and no dependence on read time for any value
    that reaches the router.
  - No secrets: reads the same two network/netuid env vars weights.py uses.
  - Unmapped hotkeys are dropped (logged), never zeroed into another UID; a
    missing, incomplete, stale, unverifiable, tampered, or empty report returns
    ``({}, meta)``, the router's documented "contributes nothing this cycle"
    shape, never an exception.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from decimal import Decimal

from . import cybergym_attestation, cybergym_contract, cybergym_tournament
from .mechanism_router import ScoreVector, ScoreVectorMeta
from .store import Store
from .weights import NETUID_ENV, NETWORK_ENV

logger = logging.getLogger(__name__)

MECHANISM_ID = "cybergym_v0"
SOURCE = "cybergym_adapter"
# Tier to register the MechanismSpec under (ScoreVectorMeta carries no tier
# field per contract). Proof-backed, like SAT.
TIER = "artifact"

MAX_SCORE_AGE_SECS_ENV = "CATHEDRAL_CYBERGYM_MAX_SCORE_AGE_SECS"
DEFAULT_MAX_SCORE_AGE_SECS = 3600.0
# Same clock-skew allowance the intake route enforces on the way in. Kept as a
# local read of the same env var rather than an import, because this module must
# stay free of the FastAPI-importing ingest module.
MAX_FUTURE_SKEW_SECS_ENV = "CATHEDRAL_CYBERGYM_MAX_FUTURE_SKEW_SECS"
DEFAULT_MAX_FUTURE_SKEW_SECS = 120.0

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Must match cathedral-distill.cybergym_scores.EPOCH_CLOSED byte-for-byte: it is
# compared against a column that repo's writer populates, across a repo boundary
# no import can span. test_epoch_closed_literal_matches_the_writer pins the
# literal so drift fails a test here instead of silently matching no row in prod.
EPOCH_CLOSED = "closed"


class CyberGymEpochNotClosed(RuntimeError):
    """Raised when scores are requested for an epoch that is not safe to publish.

    The artifact refresh loop catches adapter exceptions and skips that
    mechanism, leaving the previous ``put_scores`` row untouched, so a mid-epoch
    refresh cannot wipe a prior closed vector with an empty one. This is why an
    open epoch RAISES rather than returning the empty vector every other
    "contributes nothing" condition returns: empty would be persisted.
    """


def _epoch_state(store: Store, epoch: int) -> str | None:
    """The persisted lifecycle state for ``epoch``, or None if unknown.

    None covers a missing row and a missing ``cybergym_epoch_status`` table:
    both are "not closed". The CyberGym validator creates this table beside
    ``cybergym_scores``; an adapter that cannot see the marker cannot tell
    "nobody solved" from "scoring has not finished / state was lost".
    """
    try:
        rows = store.query(
            "SELECT state FROM cybergym_epoch_status WHERE epoch=?",
            (int(epoch),),
        )
    except Exception:  # noqa: BLE001 - missing table / backend error => not closed
        return None
    if not rows:
        return None
    state = rows[0]["state"]
    return None if state is None else str(state)


def require_closed_epoch(store: Store, epoch: int) -> None:
    """Fail closed unless ``epoch`` is marked ``closed`` in the same database."""
    state = _epoch_state(store, epoch)
    if state == EPOCH_CLOSED:
        return
    detail = "no cybergym_epoch_status row" if state is None else f"state={state!r}"
    raise CyberGymEpochNotClosed(
        f"refusing to publish CyberGym epoch {int(epoch)}: {detail}. "
        "Only epochs marked closed are safe to compose; publishing now would "
        "emit a vector indistinguishable from an epoch nobody solved."
    )


def _load_hotkey_to_uid(store: Store, *, network: str, netuid: int) -> dict[str, int]:
    """hotkey -> uid from the metagraph_hotkeys snapshot table.

    A plain mapping read (no freshness filtering) — the router's ``compose``
    decides staleness for the whole vector via ``meta.signed_at_ms`` /
    ``max_score_age_ms``, mirroring how weights.py and the SAT adapter treat the
    same table.
    """
    rows = store.query(
        "SELECT hotkey, uid FROM metagraph_hotkeys WHERE network=? AND netuid=?",
        (network, netuid),
    )
    mapping: dict[str, int] = {}
    for row in rows:
        uid = row["uid"]
        if uid is None:
            continue
        mapping[str(row["hotkey"])] = int(uid)
    return mapping


def _is_missing_cybergym_table(exc: Exception) -> bool:
    """True iff *exc* is the backend's "CyberGym table does not exist" error.

    SQLite raises ``no such table: cybergym_scores``; Postgres raises
    ``relation "cybergym_scores" does not exist``. Kept deliberately narrow so
    every other database failure still surfaces to the caller.
    """
    msg = str(exc).lower()
    return ("cybergym_scores" in msg or "cybergym_score_reports" in msg) and (
        "no such table" in msg or "does not exist" in msg
    )


def _max_score_age_secs() -> float:
    try:
        raw = os.environ.get(MAX_SCORE_AGE_SECS_ENV, "") or ""
        return max(0.0, float(raw)) if raw.strip() else DEFAULT_MAX_SCORE_AGE_SECS
    except ValueError:
        return DEFAULT_MAX_SCORE_AGE_SECS


def _max_future_skew_secs() -> float:
    raw = (os.environ.get(MAX_FUTURE_SKEW_SECS_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_FUTURE_SKEW_SECS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_MAX_FUTURE_SKEW_SECS


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _latest_complete_report(
    store: Store, *, network: str, netuid: int, epoch: int | None
) -> dict | None:
    """The single newest COMPLETE report header for this audience, or None.

    Deliberately does not import ``cybergym_ingest`` (which pulls in FastAPI);
    this is the same "duplicate one query rather than take a cross-module
    dependency" choice ``mechanism_eligibility._load_hotkey_to_uid`` makes.
    """
    rows = store.query(
        "SELECT id, network, netuid, source_epoch, producer_hotkey, complete, "
        "generated_at_iso, report_sha256, body_sha256, score_count, signature, "
        "authenticated_body, report_json FROM cybergym_score_reports "
        "WHERE network=? AND netuid=? AND complete=1 "
        "ORDER BY source_epoch DESC LIMIT 1",
        (network, netuid),
    )
    if not rows:
        return None
    row = rows[0]
    report = {
        "report_id": str(row["id"]),
        "network": str(row["network"]),
        "netuid": int(row["netuid"]),
        "source_epoch": int(row["source_epoch"]),
        "producer_hotkey": str(row["producer_hotkey"]),
        "complete": bool(row["complete"]),
        "generated_at_iso": str(row["generated_at_iso"]),
        "report_sha256": str(row["report_sha256"]),
        "body_sha256": str(row["body_sha256"] or ""),
        "score_count": int(row["score_count"]),
        "signature": str(row["signature"] or ""),
        "authenticated_body": row["authenticated_body"],
        "report_json": row["report_json"],
    }
    if epoch is not None and report["source_epoch"] != int(epoch):
        # A caller that pins an epoch gets that epoch or nothing: never a
        # different report's scores under the requested epoch's name.
        return None
    return report


def _report_rows(store: Store, *, report_id: str) -> dict[str, float]:
    """Every score row of exactly one report, verbatim.

    Nothing is filtered here: these rows are cross-checked against the
    authenticated document, so silently dropping a row would hide tampering.
    """
    rows = store.query(
        "SELECT miner_hotkey, score FROM cybergym_scores WHERE report_id=?",
        (report_id,),
    )
    out: dict[str, float] = {}
    for row in rows:
        try:
            out[str(row["miner_hotkey"])] = float(row["score"])
        except (TypeError, ValueError):
            # A non-numeric row cannot match the document, so record a value that
            # never compares equal instead of dropping it.
            out[str(row["miner_hotkey"])] = float("nan")
    return out


# --- CyberGym tournament composition (top-5 rank, 5-epoch recency) ------------
#
# When the newest report carries the optional `nonce` + `dispatched_units`, the
# lane is awarded by the rank tournament (`cybergym_tournament`) over the last
# WINDOW epochs, replacing the single-epoch proportional pass-through. This is a
# DELIBERATE relaxation of the "reads EXACTLY ONE report / no epoch mixing" rule
# above — but only for the tournament path, which is a pure function of the last
# ≤5 *authenticated* reports (each still verified), the disclosed nonce, and
# source_epoch, so every validator derives byte-identical standings.

def _empty_result(reason: str, info: dict, *, signed_at_ms: int = 0, sig_ok: bool = False):
    """Module-level empty (vector, meta, info) for the tournament helpers."""
    info["reason"] = reason
    return (
        {},
        ScoreVectorMeta(
            mechanism_id=MECHANISM_ID, signed_at_ms=signed_at_ms, sig_ok=sig_ok, source=SOURCE
        ),
        info,
    )


def _prior_complete_reports(
    store: Store, *, network: str, netuid: int, before_epoch: int, n: int
) -> list[dict]:
    """The up-to-``n`` newest COMPLETE reports strictly older than ``before_epoch``.

    Same columns/shape as ``_latest_complete_report``, newest first — fills the
    tournament's recency window with the epochs preceding the composed one. A
    missing older epoch just shortens the window (it counts as 0).
    """
    rows = store.query(
        "SELECT id, network, netuid, source_epoch, producer_hotkey, complete, "
        "generated_at_iso, report_sha256, body_sha256, score_count, signature, "
        "authenticated_body, report_json FROM cybergym_score_reports "
        "WHERE network=? AND netuid=? AND complete=1 AND source_epoch<? "
        "ORDER BY source_epoch DESC LIMIT ?",
        (network, netuid, int(before_epoch), int(n)),
    )
    out: list[dict] = []
    for row in rows:
        out.append({
            "report_id": str(row["id"]),
            "network": str(row["network"]),
            "netuid": int(row["netuid"]),
            "source_epoch": int(row["source_epoch"]),
            "producer_hotkey": str(row["producer_hotkey"]),
            "complete": bool(row["complete"]),
            "generated_at_iso": str(row["generated_at_iso"]),
            "report_sha256": str(row["report_sha256"]),
            "body_sha256": str(row["body_sha256"] or ""),
            "score_count": int(row["score_count"]),
            "signature": str(row["signature"] or ""),
            "authenticated_body": row["authenticated_body"],
            "report_json": row["report_json"],
        })
    return out


def _verified_doc(store: Store, report: dict) -> dict | None:
    """The authenticated semantic doc for one report, or None if it fails verify.

    A prior-epoch report that no longer verifies is counted as an empty epoch in
    the window rather than trusted — it can never lift a rolling total on bad data.
    """
    rows = _report_rows(store, report_id=report["report_id"])
    try:
        result = cybergym_contract.verify_stored_report(
            report,
            body=report.get("report_json"),
            authenticated_body=report.get("authenticated_body"),
            signature=report.get("signature"),
            rows=rows,
        )
    except cybergym_contract.ReportVerificationError as exc:
        logger.warning(
            "cybergym prior report %s failed verification (%s); counts as an empty "
            "epoch in the tournament window", report["report_id"], exc.reason,
        )
        return None
    return result["document"]


def _epoch_base100(verified: dict) -> dict[str, Decimal]:
    """{hotkey: base-100 score} for one epoch, from its own ``dispatched_units``.

    An epoch with no or zero ``dispatched_units`` contributes 0 for everyone (a
    pre-field or empty epoch does not lift any rolling total). A producer
    over-count (solved > dispatched) is clamped to full completion rather than
    raising, so a malformed older epoch cannot nuke the lane.
    """
    dispatched = verified.get("dispatched_units")
    if not isinstance(dispatched, (int, float)) or isinstance(dispatched, bool):
        return {}
    dispatched_dec = Decimal(str(float(dispatched)))
    if dispatched_dec <= 0:
        return {}
    out: dict[str, Decimal] = {}
    for hotkey, solved in verified.get("scores", {}).items():
        try:
            solved_dec = Decimal(str(float(solved)))
        except (TypeError, ValueError, ArithmeticError):
            continue
        if solved_dec < 0:
            continue
        if solved_dec > dispatched_dec:
            solved_dec = dispatched_dec
        out[str(hotkey)] = cybergym_tournament.epoch_score_base100(solved_dec, dispatched_dec)
    return out


def _compose_tournament(
    store: Store, *, network: str, netuid: int, newest: dict,
    signed_at_ms: int, info: dict,
):
    """Top-5 rank-tournament vector over the recency window ending at ``newest``.

    ``newest`` is the already-verified newest report (carrying ``nonce`` +
    ``dispatched_units``). Reads the preceding ≤``WINDOW-1`` complete reports,
    base-100s each epoch, ranks by rolling total, and awards the CyberGym lane
    shares via ``cybergym_tournament.build_scoreboard`` — read-only throughout.
    """
    newest_epoch = int(newest["source_epoch"])
    prior = _prior_complete_reports(
        store, network=network, netuid=netuid, before_epoch=newest_epoch,
        n=cybergym_tournament.WINDOW - 1,
    )
    # oldest -> latest; the newest carries the 0.50 recency weight.
    window = [d for d in (_verified_doc(store, r) for r in reversed(prior)) if d is not None]
    window.append(newest)
    per_epoch = [_epoch_base100(doc) for doc in window]

    miners = sorted({hk for scores in per_epoch for hk in scores})
    per_miner_scores = {
        hk: [scores.get(hk, Decimal(0)) for scores in per_epoch] for hk in miners
    }
    try:
        board = cybergym_tournament.build_scoreboard(
            newest_epoch, per_miner_scores, nonce=newest["nonce"],
        )
    except cybergym_tournament.TournamentError as exc:
        info["tournament_detail"] = str(exc)
        return _empty_result("tournament_error", info, signed_at_ms=signed_at_ms, sig_ok=True)

    info["tournament"] = True
    info["window_epochs"] = [int(d["source_epoch"]) for d in window]
    info["winners"] = list(board.winners)
    info["lane_burn"] = str(board.lane_burn)
    info["tiebreak_nonce"] = board.tiebreak_nonce

    hotkey_to_uid = _load_hotkey_to_uid(store, network=network, netuid=netuid)
    vector: ScoreVector = {}
    dropped = 0
    for standing in board.standings:
        if standing.lane_share <= 0:
            continue
        uid = hotkey_to_uid.get(standing.miner_hotkey)
        if uid is None:
            dropped += 1
            continue
        vector[uid] = vector.get(uid, 0.0) + float(standing.lane_share)
    info["dropped_unmapped_hotkeys"] = dropped
    if not vector:
        return _empty_result("no_uid_mapping", info, signed_at_ms=signed_at_ms, sig_ok=True)
    info["contributing"] = True
    info["reason"] = "ok_tournament"
    info["n_uids"] = len(vector)
    meta = ScoreVectorMeta(
        mechanism_id=MECHANISM_ID, signed_at_ms=signed_at_ms, sig_ok=True, source=SOURCE,
    )
    return vector, meta, info


def cybergym_score_snapshot(
    store: Store,
    *,
    epoch: int | None = None,
    now: datetime | None = None,
) -> tuple[ScoreVector, ScoreVectorMeta, dict]:
    """``(vector, meta, info)`` for the newest fresh complete CyberGym report.

    ``info`` carries the reason a vector is empty so a composing caller can
    record why the mechanism forfeited its share (and therefore why that share
    burns). Reasons: ``no_report``, ``epoch_not_available``, ``unauthenticated``,
    ``stale``, ``empty_report``, ``no_uid_mapping``, ``table_missing``,
    ``bad_netuid_config``, or ``ok``.

    Nothing here writes, and nothing here uses read time as a score input:
    ``signed_at_ms`` is derived from the report's authenticated ``generated_at``.
    """
    now = now or datetime.now(timezone.utc)
    network = os.environ.get(NETWORK_ENV, "finney")
    try:
        netuid = int(os.environ.get(NETUID_ENV, "39"))
    except (TypeError, ValueError):
        # A malformed NETUID env is a misconfiguration, not a data condition. The
        # adapter's contract is to never raise, so report an empty (share-burning)
        # vector with a reason rather than propagate ValueError into the refresh
        # cycle (the ingest side already fails closed on the same env var).
        return (
            {},
            ScoreVectorMeta(mechanism_id=MECHANISM_ID, signed_at_ms=0, sig_ok=False, source=SOURCE),
            {"network": network, "netuid": None, "requested_epoch": None,
             "contributing": False, "reason": "bad_netuid_config"},
        )
    info: dict = {
        "network": network,
        "netuid": netuid,
        "requested_epoch": None if epoch is None else int(epoch),
        "contributing": False,
        "reason": "no_report",
    }

    def _empty(reason: str, *, signed_at_ms: int = 0, sig_ok: bool = False):
        info["reason"] = reason
        return (
            {},
            ScoreVectorMeta(
                mechanism_id=MECHANISM_ID,
                signed_at_ms=signed_at_ms,
                sig_ok=sig_ok,
                source=SOURCE,
            ),
            info,
        )

    try:
        report = _latest_complete_report(
            store, network=network, netuid=netuid, epoch=epoch
        )
    except Exception as exc:
        if _is_missing_cybergym_table(exc):
            logger.warning(
                "CyberGym tables missing (pre-0048 database?); "
                "returning empty CyberGym score set"
            )
            return _empty("table_missing")
        raise

    if report is None:
        return _empty("no_report" if epoch is None else "epoch_not_available")

    # Closed-epoch gate, reconciled with this branch's transport (see #416).
    #
    # #416 added require_closed_epoch for the shared-database design, where the
    # CyberGym validator writes `cybergym_scores` AND `cybergym_epoch_status` into
    # the publisher database, so the marker is the only completeness signal and an
    # unreadable marker must refuse.
    #
    # This lane does not share a database: cathedral-distill's CyberGymScoreStore
    # writes its own SQLite file on the validator host, and completeness arrives
    # here inside the HMAC-signed report body as `complete: true`, which the intake
    # route requires, `verify_stored_report` re-verifies, and `_latest_complete_report`
    # filters on. That is a stronger completeness proof than an unauthenticated
    # marker row, and nothing writes the marker into the publisher database, so
    # refusing on its ABSENCE would burn this lane permanently rather than fence it.
    #
    # So: refuse when a marker exists and says the epoch is not closed (a
    # deployment that does share the database keeps #416's protection exactly),
    # and rely on the authenticated `complete` flag when no marker exists.
    epoch_state = _epoch_state(store, report["source_epoch"])
    if epoch_state is not None and epoch_state != EPOCH_CLOSED:
        raise CyberGymEpochNotClosed(
            f"refusing to publish CyberGym epoch {report['source_epoch']}: "
            f"state={epoch_state!r}. Only epochs marked closed are safe to compose; "
            "publishing now would emit a vector indistinguishable from an epoch "
            "nobody solved."
        )

    info.update({
        "report_id": report["report_id"],
        "source_epoch": report["source_epoch"],
        "producer_hotkey": report["producer_hotkey"],
        "report_sha256": report["report_sha256"],
        "generated_at_iso": report["generated_at_iso"],
        "score_count": report["score_count"],
    })

    generated_at = _parse_iso(report["generated_at_iso"])
    if generated_at is None:
        return _empty("unauthenticated")
    signed_at_ms = int(generated_at.timestamp() * 1000)
    info["signed_at_ms"] = signed_at_ms

    max_age = _max_score_age_secs()
    max_future_skew = _max_future_skew_secs()
    age_secs = (now - generated_at).total_seconds()
    info["age_secs"] = age_secs
    info["max_age_secs"] = max_age
    info["max_future_skew_secs"] = max_future_skew
    if age_secs < -max_future_skew:
        # Defence in depth against a future-dated report: a negative age can
        # never exceed max_age, so without this check such a report would count
        # as fresh for as long as it sat in the table. The ingest route refuses
        # these, so reaching here means a row arrived by some other means.
        logger.warning(
            "cybergym report %s is dated %.0fs in the future (skew allowance "
            "%.0fs); refusing to treat it as fresh",
            report["report_id"], -age_secs, max_future_skew,
        )
        return _empty("future_dated", signed_at_ms=signed_at_ms, sig_ok=False)
    if age_secs > max_age:
        # A dead producer's last report ages out instead of being restamped.
        return _empty("stale", signed_at_ms=signed_at_ms, sig_ok=True)

    try:
        rows = _report_rows(store, report_id=report["report_id"])
    except Exception as exc:
        if _is_missing_cybergym_table(exc):
            logger.warning(
                "cybergym_scores table missing (pre-0048 database?); "
                "returning empty CyberGym score set"
            )
            return _empty("table_missing")
        raise

    # THE authentication step. Re-derive the stored body digest, re-verify the
    # stored HMAC against the configured producer secret, re-derive the semantic
    # report digest, and cross-check every derived column and every score row
    # against that authenticated body. A row hand-written into the database, or
    # any later edit to the body, the columns, or the rows, fails here.
    try:
        verified = cybergym_contract.verify_stored_report(
            report,
            body=report.get("report_json"),
            authenticated_body=report.get("authenticated_body"),
            signature=report.get("signature"),
            rows=rows,
        )
    except cybergym_contract.ReportVerificationError as exc:
        logger.warning(
            "cybergym report %s failed verification (%s%s); contributing nothing",
            report["report_id"], exc.reason,
            f": {exc.detail}" if exc.detail else "",
        )
        info["verification_detail"] = exc.detail
        return _empty(exc.reason, signed_at_ms=signed_at_ms, sig_ok=False)
    info["verified"] = True

    # Tournament path: when the producer emits the optional recency-window inputs
    # (`nonce` + `dispatched_units`), award the lane by the top-5 rank tournament
    # over the last WINDOW epochs instead of the single-epoch proportional split.
    # A report without them keeps the original behaviour exactly (below).
    newest_doc = verified["document"]

    # DCAP spot-check (distill #115): independently verify the carried representative
    # Intel-TDX receipt — a real Cathedral signature over a receipt whose committed
    # (nonce, miner) is the one the CHAIN named this epoch. #103 requires the receipt's
    # PRESENCE; this verifies it. Advisory by default (records the outcome in `info`);
    # under CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT, a receipt that is absent or
    # does not verify burns the lane rather than paying on an unproven claim. Gating here
    # (before the branch) covers the tournament and legacy paths alike.
    att_receipt = newest_doc.get("attestation_receipt")
    att_nonce = newest_doc.get("nonce")
    if att_nonce is None:
        att_ok, att_reason = True, "no_nonce"  # pre-#114 report: spot-check does not apply
    elif att_receipt is None:
        att_ok, att_reason = False, "absent"  # #114 report that carries no receipt
    else:
        scored = {h for h, v in verified["scores"].items() if v > 0.0}
        att_ok, att_reason = cybergym_attestation.verify_attestation_receipt(
            att_receipt,
            nonce=att_nonce,
            source_epoch=int(report["source_epoch"]),
            scored_hotkeys=scored,
        )
    info["attestation"] = att_reason
    if cybergym_attestation.require_attestation() and not att_ok:
        logger.warning(
            "cybergym report %s attestation not verified (%s) and the require flag is "
            "set; burning the CyberGym lane this epoch",
            report["report_id"], att_reason,
        )
        return _empty("attestation_" + att_reason, signed_at_ms=signed_at_ms, sig_ok=True)

    if "nonce" in newest_doc and "dispatched_units" in newest_doc:
        return _compose_tournament(
            store, network=network, netuid=netuid, newest=newest_doc,
            signed_at_ms=signed_at_ms, info=info,
        )

    # Scores come from the VERIFIED document, not from the projection rows. The
    # rows were only a cross-check; the document is the authenticated truth.
    totals = {
        hotkey: value
        for hotkey, value in verified["scores"].items()
        if value > 0.0
    }
    if not totals:
        return _empty("empty_report", signed_at_ms=signed_at_ms, sig_ok=True)

    hotkey_to_uid = _load_hotkey_to_uid(store, network=network, netuid=netuid)
    vector: ScoreVector = {}
    dropped = 0
    for hotkey, score in totals.items():
        uid = hotkey_to_uid.get(hotkey)
        if uid is None:
            dropped += 1
            continue
        vector[uid] = vector.get(uid, 0.0) + float(score)
    info["dropped_unmapped_hotkeys"] = dropped

    if dropped:
        logger.info(
            "cybergym_mechanism_scores: dropped %d/%d verified hotkeys with no "
            "uid mapping in metagraph_hotkeys (network=%s netuid=%s)",
            dropped, len(totals), network, netuid,
        )

    if not vector:
        return _empty("no_uid_mapping", signed_at_ms=signed_at_ms, sig_ok=True)

    info["contributing"] = True
    info["reason"] = "ok"
    info["n_uids"] = len(vector)
    meta = ScoreVectorMeta(
        mechanism_id=MECHANISM_ID,
        signed_at_ms=signed_at_ms,
        sig_ok=True,
        source=SOURCE,
    )
    return vector, meta, info


def cybergym_mechanism_scores(
    store: Store,
    *,
    epoch: int | None = None,
    now: datetime | None = None,
) -> tuple[ScoreVector, ScoreVectorMeta]:
    """Verified CyberGym scores remapped from miner_hotkey to miner uid.

    Reads exactly one report: the newest COMPLETE report for the configured
    audience. Passing ``epoch`` pins that report to an exact producer epoch and
    yields nothing if the newest complete report is a different one.

    Returns ``({}, meta)`` when the report is missing, incomplete, unverifiable,
    tampered, stale, empty, or maps to no UID: the router's documented fallback,
    never an exception.
    """
    vector, meta, _info = cybergym_score_snapshot(store, epoch=epoch, now=now)
    return vector, meta
