"""Answer "is this validator working right now?" from the event journal alone.

The failure that costs an operator money is not a loud one. A crashed process,
a wedged RPC, a full disk, a deregistered hotkey or a mistyped ``--jsonl`` path
all look identical from outside: the journal simply stops growing. Nothing in
the write path notices, because there is no write path left to notice with.

So this module reads the JSONL journal and nothing else — no chain, no wallet,
no publisher — and applies five rules, in order:

1. the journal must be readable and contain at least one parseable record;
2. its newest record must be younger than ``JOURNAL_STALE_TICKS`` tick
   intervals;
3. a tick-completing event (:data:`LIVENESS_EVENTS`) must have been written
   within ``LIVENESS_TICKS`` tick intervals, unless the process restarted
   inside that window and has not finished its first tick yet;
4. no ``PROVENANCE_VECTOR_MISMATCH`` within :data:`MISMATCH_WINDOW_SECS`; and
5. not (at least one ``PROVENANCE_AUDIT_FAIL`` and zero
   ``PROVENANCE_AUDIT_PASS``) within :data:`AUDIT_FAILURE_WINDOW_SECS`.

Rules 1-3 exist because a monitor that reports success when it cannot see the
thing it monitors is worse than no monitor: it is a green light on a broken
sensor. Every one of them fails CLOSED — an unreadable path is an alert, not a
silent zero. Rules 4 and 5 are the pre-existing shadow-audit alarms, kept
verbatim so ``deploy/sn39/cathedral-mismatch-check`` and
``cathedral-validator status`` cannot disagree about what "healthy" means.

Nothing here reads chain state or holds a lock, so it is safe to run against a
live validator's journal at any time, as often as you like.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# The four events that mean "a tick ran to completion". A submission, a
# submission the subnet's rate limit declined this tick, a dry-run write, and
# the calm passive-listener state are all evidence the loop is alive; only the
# absence of every one of them is evidence it is not.
LIVENESS_EVENTS: tuple[str, ...] = (
    "WEIGHTS_SUBMITTED",
    "WEIGHTS_DRY_RUN",
    "WEIGHT_COOLDOWN_SKIPPED",
    "WAITING_FOR_JOB",
)
# The subset that means weight values actually reached (or would have reached)
# the chain.
WRITE_EVENTS: tuple[str, ...] = ("WEIGHTS_SUBMITTED", "WEIGHTS_DRY_RUN")
VECTOR_EVENTS: tuple[str, ...] = (
    "VECTOR_ACCEPTED",
    "VECTOR_REJECTED",
    "RECOVERED_VECTOR_IDLE",
)
AUDIT_EVENTS: tuple[str, ...] = (
    "PROVENANCE_AUDIT_PASS",
    "PROVENANCE_AUDIT_FAIL",
    "PROVENANCE_AUDIT_NOT_PROVEN",
    "PROVENANCE_AUDIT_UNRESOLVED",
    "PROVENANCE_AUDIT_SKIPPED",
    "PROVENANCE_VECTOR_MISMATCH",
    "PROVENANCE_VECTOR_STALE_EPOCH",
)

# Tick multiples, not absolute seconds: a validator configured with a short
# interval should be declared dead sooner, not later.
JOURNAL_STALE_TICKS = 3.0
LIVENESS_TICKS = 4.0
# The two shadow-audit windows are fixed by the audit's own cadence, not the
# write cadence, so they stay absolute (see VALIDATOR.md).
MISMATCH_WINDOW_SECS = 30 * 60.0
AUDIT_FAILURE_WINDOW_SECS = 90 * 60.0

# Matches the `interval_secs` default in scaffold/cli.py; used only when a
# caller cannot supply one.
DEFAULT_INTERVAL_SECS = 1500.0
# Only the tail is read: the journal is append-only and grows without bound,
# and every rule here is about recent history.
TAIL_BYTES = 512 * 1024


class JournalUnreadable(Exception):
    """The journal could not be opened or read. Always an alert."""


@dataclass(frozen=True)
class Health:
    """The verdict plus the one screen an operator wants beside it."""

    journal: str
    ok: bool
    problems: tuple[str, ...]
    rows: tuple[tuple[str, str], ...]


def parse_ts(value: object) -> datetime | None:
    """Parse an event ``ts`` into an aware UTC datetime, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def read_tail(
    journal: str | os.PathLike[str], *, tail_bytes: int = TAIL_BYTES
) -> list[dict]:
    """Return the parseable JSONL records in the tail of ``journal``.

    Raises :class:`JournalUnreadable` if the path cannot be opened or read.
    A path that exists but holds no parseable record returns an empty list;
    the caller decides what that means.
    """
    path = Path(journal)
    try:
        with open(path, "rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            start = max(0, size - int(tail_bytes))
            handle.seek(start)
            blob = handle.read()
    except OSError as exc:
        code = getattr(exc, "strerror", None) or type(exc).__name__
        raise JournalUnreadable(str(code)) from exc
    lines = blob.decode("utf-8", "replace").splitlines()
    if start > 0 and lines:
        # The first line in a mid-file read is almost certainly a fragment.
        lines = lines[1:]
    records: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _latest(records: list[dict], events: tuple[str, ...] | None = None) -> dict | None:
    """The record with the newest parseable ``ts``, optionally filtered."""
    best: dict | None = None
    best_ts: datetime | None = None
    for record in records:
        if events is not None and record.get("event") not in events:
            continue
        when = parse_ts(record.get("ts"))
        if when is None:
            continue
        if best_ts is None or when > best_ts:
            best, best_ts = record, when
    return best


def _age_secs(record: dict | None, now: datetime) -> float | None:
    if record is None:
        return None
    when = parse_ts(record.get("ts"))
    if when is None:
        return None
    # Clock skew (or a journal written by a host ahead of this one) must not
    # read as a negative age and silently pass a staleness test.
    return max(0.0, (now - when).total_seconds())


def _count_within(records: list[dict], event: str, window: float, now: datetime) -> int:
    total = 0
    for record in records:
        if record.get("event") != event:
            continue
        when = parse_ts(record.get("ts"))
        if when is not None and (now - when).total_seconds() <= window:
            total += 1
    return total


def humanize_secs(seconds: float) -> str:
    """A duration an operator can read at 3am, without importing render."""
    seconds = max(0.0, float(seconds))
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f}m"
    return f"{minutes / 60:.1f}h"


def _detail_field(record: dict | None, key: str) -> str:
    """Pull ``key=value`` out of a record's structured field or detail text."""
    if record is None:
        return ""
    value = record.get(key)
    if value not in (None, ""):
        return str(value)
    detail = record.get("detail")
    if not isinstance(detail, str):
        return ""
    for token in detail.split():
        name, sep, val = token.partition("=")
        if sep and name == key:
            return val
    return ""


def evaluate(
    journal: str | os.PathLike[str],
    *,
    interval_secs: float | None = None,
    now: datetime | None = None,
    tail_bytes: int = TAIL_BYTES,
) -> Health:
    """Apply the five rules to ``journal`` and return the verdict plus rows."""
    now = now.astimezone(UTC) if now is not None else datetime.now(UTC)
    try:
        interval = float(interval_secs)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        interval = DEFAULT_INTERVAL_SECS
    if not interval > 0:
        interval = DEFAULT_INTERVAL_SECS
    stale_after = interval * JOURNAL_STALE_TICKS
    liveness_after = interval * LIVENESS_TICKS
    label = str(journal)

    try:
        records = read_tail(journal, tail_bytes=tail_bytes)
    except JournalUnreadable as exc:
        return Health(
            journal=label,
            ok=False,
            problems=(
                f"journal cannot be read ({exc}) — nothing is being monitored. "
                "Check that this path is the one the validator's --jsonl or "
                "[logs].jsonl actually names, and that this user can read it.",
            ),
            rows=(("journal", "UNREADABLE — this check is blind"),),
        )

    newest = _latest(records)
    newest_age = _age_secs(newest, now)
    if newest_age is None:
        return Health(
            journal=label,
            ok=False,
            problems=(
                "journal holds no parseable event record — nothing is being "
                "monitored. Either the validator has never written here or "
                "this is not the file it writes to.",
            ),
            rows=(("journal", "EMPTY — this check is blind"),),
        )

    problems: list[str] = []
    if newest_age > stale_after:
        problems.append(
            f"journal has not grown in {humanize_secs(newest_age)}, over "
            f"{JOURNAL_STALE_TICKS:.0f} tick intervals "
            f"({humanize_secs(stale_after)}) — the validator is stopped, "
            "wedged, or writing somewhere else. Check "
            "`systemctl status cathedral-validator-sn39`."
        )

    live = _latest(records, LIVENESS_EVENTS)
    live_age = _age_secs(live, now)
    startup = _latest(records, ("STARTUP",))
    startup_age = _age_secs(startup, now)
    # A process that restarted inside the liveness window has not been given a
    # full window to finish a tick yet. Rule 2 above still catches a process
    # that started and then hung, one tick sooner.
    warming_up = (
        startup_age is not None
        and startup_age <= liveness_after
        and (live is None or (live_age or 0.0) > startup_age)
    )
    if (live_age is None or live_age > liveness_after) and not warming_up:
        seen = (
            f"the last one was {humanize_secs(live_age)} ago"
            if live_age is not None
            else "there is none in this journal at all"
        )
        problems.append(
            "no completed tick ("
            + ", ".join(LIVENESS_EVENTS)
            + f") in the last {humanize_secs(liveness_after)} "
            f"({LIVENESS_TICKS:.0f} tick intervals) — {seen}. The validator is "
            "not writing weights."
        )

    mismatches = _count_within(
        records, "PROVENANCE_VECTOR_MISMATCH", MISMATCH_WINDOW_SECS, now
    )
    if mismatches:
        problems.append(
            f"{mismatches} PROVENANCE_VECTOR_MISMATCH event(s) within "
            f"{humanize_secs(MISMATCH_WINDOW_SECS)} — the audit disagreed with "
            "an accepted vector."
        )

    audit_fails = _count_within(
        records, "PROVENANCE_AUDIT_FAIL", AUDIT_FAILURE_WINDOW_SECS, now
    )
    audit_passes = _count_within(
        records, "PROVENANCE_AUDIT_PASS", AUDIT_FAILURE_WINDOW_SECS, now
    )
    if audit_fails and not audit_passes:
        problems.append(
            f"shadow audit failing for {humanize_secs(AUDIT_FAILURE_WINDOW_SECS)} "
            f"with no PASS — {audit_fails} PROVENANCE_AUDIT_FAIL event(s) and "
            "zero PROVENANCE_AUDIT_PASS."
        )

    return Health(
        journal=label,
        ok=not problems,
        problems=tuple(problems),
        rows=_rows(
            records=records,
            now=now,
            interval=interval,
            newest_age=newest_age,
            stale_after=stale_after,
            live=live,
            live_age=live_age,
            warming_up=warming_up,
        ),
    )


def _rows(
    *,
    records: list[dict],
    now: datetime,
    interval: float,
    newest_age: float,
    stale_after: float,
    live: dict | None,
    live_age: float | None,
    warming_up: bool,
) -> tuple[tuple[str, str], ...]:
    """The one screen: what happened last, and how long ago.

    Labels stay short because ``render.banner`` pads them to a fixed column;
    a label that fills the column runs into its own value.
    """
    rows: list[tuple[str, str]] = []
    fresh = "fresh" if newest_age <= stale_after else "STALE"
    rows.append(("journal", f"{fresh} · newest record {humanize_secs(newest_age)} ago"))

    if warming_up:
        rows.append(("tick", "starting up — the first tick has not completed"))
    elif live is None or live_age is None:
        rows.append(("tick", "none completed in this journal"))
    else:
        rows.append(("tick", f"{live.get('event')} {humanize_secs(live_age)} ago"))

    write = _latest(records, WRITE_EVENTS)
    write_age = _age_secs(write, now)
    if write is None or write_age is None:
        rows.append(("write", "none in this journal"))
    else:
        name = str(write.get("event"))
        bits = [f"{name} {humanize_secs(write_age)} ago"]
        if write.get("status") and write["status"] != "PASS":
            bits.append(f"status {write['status']}")
        uids = _detail_field(write, "uid_count") or _detail_field(write, "uids")
        if uids:
            bits.append(f"{uids} uids")
        rows.append(("write", " · ".join(bits)))

    vector = _latest(records, VECTOR_EVENTS)
    vector_age = _age_secs(vector, now)
    if vector is None or vector_age is None:
        rows.append(("vector", "none in this journal"))
    else:
        bits = [f"{vector.get('event')} {humanize_secs(vector_age)} ago"]
        vector_id = str(vector.get("artifact") or _detail_field(vector, "vector_id"))
        if vector_id:
            bits.append(f"id {vector_id[:12]}")
        policy = _detail_field(vector, "policy_version")
        if policy:
            bits.append(f"policy_version {policy}")
        rows.append(("vector", " · ".join(bits)))

    audit = _latest(records, AUDIT_EVENTS)
    audit_age = _age_secs(audit, now)
    if audit is None or audit_age is None:
        rows.append(("audit", "no shadow-audit verdict in this journal"))
    else:
        rows.append(("audit", f"{audit.get('event')} {humanize_secs(audit_age)} ago"))

    if live_age is None:
        rows.append(("next tick", "unknown — no completed tick in this journal"))
    else:
        remaining = interval - live_age
        rows.append(
            (
                "next tick",
                f"~{humanize_secs(remaining)} from now"
                if remaining > 0
                else f"overdue by {humanize_secs(-remaining)}",
            )
        )
    return tuple(rows)
