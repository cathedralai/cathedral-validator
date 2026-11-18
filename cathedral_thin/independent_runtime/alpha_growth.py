"""Alpha growth guard for the open-season share (AB#351).

Outside miners paid through the open-season share (AB#320) earn SN94 alpha. If
they sell most of it, the share dilutes alpha growth. This module reports, per
miner hotkey, alpha earned against alpha sold from one dated evidence export,
and checks it against the owner's monthly decision. It reads two inputs and
changes nothing:

* a dated evidence export (``ALPHA_EVIDENCE_SCHEMA``), for example from
  Taostats, covering one window inside one calendar month;
* the owner's decision ledger, pinned in this release the same way the
  approved-miner list is: ``PINNED_DECISIONS_DOCUMENT`` below,
  ``config/open-season/alpha-growth-decisions.json`` with the same bytes, and
  ``PINNED_DECISIONS_SHA256``. An edit to one without the others fails at
  import, so every monthly decision is a reviewed change.

Definitions. ``alpha_earned`` is alpha emitted to the hotkey in the window.
``alpha_sold`` is alpha that left the miner's own stake on that hotkey in the
window by any route: unstake to TAO, transfer to another coldkey, or move to
another hotkey or subnet. Amounts are decimal strings in alpha, parsed exactly.

What the guard decides, and what it does not:

* no decision for the evidence month: ``DECISION_REQUIRED``. The ledger
  fraction is 0. Nothing live may change until the owner records one;
* a decision without ``max_sell_ratio``: ``REPORT_ONLY``;
* any hotkey, or the aggregate, selling more than ``max_sell_ratio`` of what
  it earned: ``DILUTING``. The recommendation is to lower the fraction or add
  a hold period; the owner decides, the guard never changes either;
* otherwise ``WITHIN_GUARD``.

The ceiling is ``MAX_OPEN_SEASON_FRACTION`` (1/10, the card's hard limit, not a
chosen value). A ledger entry above it is refused. ``hold_days`` is recorded
and reported but not evaluated: the evidence has no per-hotkey age.

The ledger ships empty. The cap value, hold period and sell threshold are the
owner's decision.

No network, chain, wallet or key. Usage::

    python -m cathedral_thin.independent_runtime.alpha_growth --evidence E.json

Exit 0 for ``WITHIN_GUARD`` or ``REPORT_ONLY``, 1 for ``DILUTING`` or
``DECISION_REQUIRED``, 2 for refused input.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from cathedral_thin.independent.constants import NETUID

from .approved_miners import _SS58_CHARS
from .errors import IndependentLiveError

ALPHA_EVIDENCE_SCHEMA = "cathedral_alpha_growth_evidence_v1"
DECISIONS_SCHEMA = "cathedral_alpha_growth_decisions_v1"
DECIDER = "Fred"
# Same value as open_season.MAX_OPEN_SEASON_FRACTION (AB#320, PR #342). Import
# it from there once that module is on main.
MAX_OPEN_SEASON_FRACTION = Fraction(1, 10)
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_ROWS = 4096
MAX_HOLD_DAYS = 365

STATUS_DECISION_REQUIRED = "DECISION_REQUIRED"
STATUS_REPORT_ONLY = "REPORT_ONLY"
STATUS_DILUTING = "DILUTING"
STATUS_WITHIN_GUARD = "WITHIN_GUARD"
EXIT_OK = 0
EXIT_ATTENTION = 1
EXIT_REFUSED = 2

RECOMMEND_DILUTING = (
    "miner selling exceeds the decided ratio: lower the open-season fraction "
    "or add a hold period before the share counts; the owner decides"
)
RECOMMEND_DECISION_REQUIRED = (
    "no owner decision for this month: the open-season fraction stays 0 until "
    "the owner records the cap and hold in the ledger"
)

_DECIMAL = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]+)?")
_RATIO = re.compile(r"(0|[1-9][0-9]*)/([1-9][0-9]*)")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_MONTH = re.compile(r"[0-9]{4}-[0-9]{2}")

# Canonical compact JSON of this document plus one newline is the content of
# config/open-season/alpha-growth-decisions.json. One entry per month, sorted
# by month. Shipped empty: no cap, hold or sell threshold is chosen here.
PINNED_DECISIONS_DOCUMENT: dict[str, object] = {
    "decisions": [],
    "netuid": NETUID,
    "schema": DECISIONS_SCHEMA,
}
PINNED_DECISIONS_SHA256 = (
    "dd84a3b4985c3de51d83c1f5ac0b40860c922b88cf9da98abcc647adde9397b3"
)


class AlphaGuardError(IndependentLiveError):
    """Alpha evidence or the decision ledger is malformed."""


@dataclass(frozen=True)
class AlphaRow:
    hotkey: str
    earned: Fraction
    sold: Fraction

    @property
    def retained(self) -> Fraction:
        return self.earned - self.sold

    @property
    def sell_ratio(self) -> Fraction | None:
        return None if self.earned == 0 else self.sold / self.earned

    def over(self, limit: Fraction) -> bool:
        # Selling with nothing earned in the window is over any limit.
        if self.earned == 0:
            return self.sold > 0
        return self.sold / self.earned > limit

    def evidence(self) -> dict[str, Any]:
        ratio = self.sell_ratio
        return {
            "hotkey": self.hotkey,
            "alpha_earned": _decimal_text(self.earned),
            "alpha_sold": _decimal_text(self.sold),
            "alpha_retained": _decimal_text(self.retained),
            "sell_ratio": None if ratio is None else _ratio_text(ratio),
        }


@dataclass(frozen=True)
class AlphaEvidence:
    source: str
    source_endpoint: str
    window_start: dt.date
    window_end: dt.date
    observed_at: dt.date
    rows: tuple[AlphaRow, ...]
    sha256: str

    @property
    def month(self) -> str:
        return self.window_start.strftime("%Y-%m")


@dataclass(frozen=True)
class CapDecision:
    month: str
    decided_by: str
    decided_on: dt.date
    open_season_fraction: Fraction
    hold_days: int
    max_sell_ratio: Fraction | None
    note: str

    def evidence(self) -> dict[str, Any]:
        return {
            "month": self.month,
            "decided_by": self.decided_by,
            "decided_on": self.decided_on.isoformat(),
            "open_season_fraction": _ratio_text(self.open_season_fraction),
            "hold_days": self.hold_days,
            "max_sell_ratio": (
                None
                if self.max_sell_ratio is None
                else _ratio_text(self.max_sell_ratio)
            ),
            "note": self.note,
        }


@dataclass(frozen=True)
class GuardReport:
    status: str
    evidence: AlphaEvidence
    decision: CapDecision | None
    over_hotkeys: tuple[str, ...]
    aggregate_over: bool
    recommendation: str

    @property
    def ledger_fraction(self) -> Fraction:
        return (
            Fraction(0) if self.decision is None else self.decision.open_season_fraction
        )

    @property
    def total_earned(self) -> Fraction:
        return sum((row.earned for row in self.evidence.rows), Fraction(0))

    @property
    def total_sold(self) -> Fraction:
        return sum((row.sold for row in self.evidence.rows), Fraction(0))

    @property
    def exit_code(self) -> int:
        if self.status in (STATUS_WITHIN_GUARD, STATUS_REPORT_ONLY):
            return EXIT_OK
        return EXIT_ATTENTION

    def as_dict(self) -> dict[str, Any]:
        earned, sold = self.total_earned, self.total_sold
        return {
            "status": self.status,
            "month": self.evidence.month,
            "evidence": {
                "source": self.evidence.source,
                "source_endpoint": self.evidence.source_endpoint,
                "window_start": self.evidence.window_start.isoformat(),
                "window_end": self.evidence.window_end.isoformat(),
                "observed_at": self.evidence.observed_at.isoformat(),
                "sha256": self.evidence.sha256,
            },
            "decision": None if self.decision is None else self.decision.evidence(),
            "ledger_fraction": _ratio_text(self.ledger_fraction),
            "max_open_season_fraction": _ratio_text(MAX_OPEN_SEASON_FRACTION),
            "totals": {
                "alpha_earned": _decimal_text(earned),
                "alpha_sold": _decimal_text(sold),
                "alpha_retained": _decimal_text(earned - sold),
                "sell_ratio": None if earned == 0 else _ratio_text(sold / earned),
            },
            "rows": [row.evidence() for row in self.evidence.rows],
            "over_hotkeys": list(self.over_hotkeys),
            "aggregate_over": self.aggregate_over,
            "recommendation": self.recommendation,
        }


def _decimal_text(value: Fraction) -> str:
    """Exact text: a decimal when it terminates, else ``n/d``."""

    sign = "-" if value < 0 else ""
    value = abs(value)
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        return f"{sign}{value.numerator}/{value.denominator}"
    places = max(twos, fives)
    scaled = value.numerator * (10**places) // value.denominator
    whole, frac = divmod(scaled, 10**places) if places else (scaled, 0)
    if not places:
        return f"{sign}{whole}"
    return f"{sign}{whole}.{frac:0{places}d}"


def _ratio_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _refuse_constant(name: str) -> object:
    raise AlphaGuardError(f"JSON constant {name} is not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise AlphaGuardError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


def _load_json(raw: bytes, what: str) -> dict[str, Any]:
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise AlphaGuardError(f"{what} is larger than {MAX_EVIDENCE_BYTES} bytes")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_refuse_constant,
        )
    except AlphaGuardError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise AlphaGuardError(f"{what} is not UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise AlphaGuardError(f"{what} is not a JSON object")
    return document


def _amount(value: object, field: str) -> Fraction:
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        raise AlphaGuardError(f"{field} must be a non-negative decimal string")
    return Fraction(value)


def _ratio(value: object, field: str, ceiling: Fraction) -> Fraction:
    if not isinstance(value, str) or not _RATIO.fullmatch(value):
        raise AlphaGuardError(f"{field} must be a 'n/d' string")
    ratio = Fraction(value)
    if ratio > ceiling:
        raise AlphaGuardError(f"{field} is above {_ratio_text(ceiling)}")
    return ratio


def _date(value: object, field: str) -> dt.date:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise AlphaGuardError(f"{field} must be a YYYY-MM-DD date (UTC)")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise AlphaGuardError(f"{field} is not a real date") from exc


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AlphaGuardError(f"{field} must be a non-empty string")
    return value


def _hotkey(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 47 <= len(value) <= 48
        or not set(value) <= _SS58_CHARS
    ):
        raise AlphaGuardError("row hotkey is not SS58")
    return value


def _netuid(document: dict[str, Any], what: str) -> None:
    netuid = document["netuid"]
    if isinstance(netuid, bool) or netuid != NETUID:
        raise AlphaGuardError(f"{what} is not for netuid {NETUID}")


def load_evidence(raw: bytes) -> AlphaEvidence:
    """Parse one dated evidence export, or raise ``AlphaGuardError``."""

    document = _load_json(raw, "alpha evidence")
    fields = {
        "schema",
        "source",
        "source_endpoint",
        "netuid",
        "window_start",
        "window_end",
        "observed_at",
        "rows",
    }
    if set(document) != fields:
        raise AlphaGuardError("alpha evidence fields are invalid")
    if document["schema"] != ALPHA_EVIDENCE_SCHEMA:
        raise AlphaGuardError("alpha evidence schema is not supported")
    _netuid(document, "alpha evidence")
    start = _date(document["window_start"], "window_start")
    end = _date(document["window_end"], "window_end")
    observed = _date(document["observed_at"], "observed_at")
    if not start <= end <= observed:
        raise AlphaGuardError(
            "evidence dates must be window_start <= window_end <= observed_at"
        )
    if (start.year, start.month) != (end.year, end.month):
        # One month, one decision: a window across two months has no single cap.
        raise AlphaGuardError("evidence window spans two calendar months")
    rows_in = document["rows"]
    if not isinstance(rows_in, list) or len(rows_in) > MAX_ROWS:
        raise AlphaGuardError("alpha evidence rows are invalid")
    rows: list[AlphaRow] = []
    for row in rows_in:
        if not isinstance(row, dict) or set(row) != {
            "hotkey",
            "alpha_earned",
            "alpha_sold",
        }:
            raise AlphaGuardError("alpha evidence row is malformed")
        rows.append(
            AlphaRow(
                hotkey=_hotkey(row["hotkey"]),
                earned=_amount(row["alpha_earned"], "alpha_earned"),
                sold=_amount(row["alpha_sold"], "alpha_sold"),
            )
        )
    hotkeys = [row.hotkey for row in rows]
    if len(set(hotkeys)) != len(hotkeys):
        raise AlphaGuardError("alpha evidence lists a hotkey twice")
    return AlphaEvidence(
        source=_text(document["source"], "source"),
        source_endpoint=_text(document["source_endpoint"], "source_endpoint"),
        window_start=start,
        window_end=end,
        observed_at=observed,
        rows=tuple(sorted(rows, key=lambda row: row.hotkey)),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def load_decisions(raw: bytes, *, expected_sha256: str) -> tuple[CapDecision, ...]:
    """Parse the owner's decision ledger and refuse it if it is not the pin."""

    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise AlphaGuardError("decision ledger does not match its sha256 pin")
    document = _load_json(raw, "decision ledger")
    if set(document) != {"decisions", "netuid", "schema"}:
        raise AlphaGuardError("decision ledger fields are invalid")
    if document["schema"] != DECISIONS_SCHEMA:
        raise AlphaGuardError("decision ledger schema is not supported")
    _netuid(document, "decision ledger")
    entries = document["decisions"]
    if not isinstance(entries, list):
        raise AlphaGuardError("decision ledger entries are invalid")
    decisions: list[CapDecision] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "month",
            "decided_by",
            "decided_on",
            "open_season_fraction",
            "hold_days",
            "max_sell_ratio",
            "note",
        }:
            raise AlphaGuardError("decision entry is malformed")
        month = entry["month"]
        if not isinstance(month, str) or not _MONTH.fullmatch(month):
            raise AlphaGuardError("decision month must be YYYY-MM")
        first_day = _date(f"{month}-01", "decision month")
        if entry["decided_by"] != DECIDER:
            raise AlphaGuardError(f"decisions are recorded by {DECIDER}")
        decided_on = _date(entry["decided_on"], "decided_on")
        if decided_on > first_day:
            # A decision governs the month after it is made, never evidence
            # that was already accruing when it was written.
            raise AlphaGuardError("decided_on is after the first day of its month")
        hold_days = entry["hold_days"]
        if (
            isinstance(hold_days, bool)
            or not isinstance(hold_days, int)
            or not 0 <= hold_days <= MAX_HOLD_DAYS
        ):
            raise AlphaGuardError(
                f"hold_days must be an integer in [0, {MAX_HOLD_DAYS}]"
            )
        max_sell = entry["max_sell_ratio"]
        decisions.append(
            CapDecision(
                month=month,
                decided_by=DECIDER,
                decided_on=decided_on,
                open_season_fraction=_ratio(
                    entry["open_season_fraction"],
                    "open_season_fraction",
                    MAX_OPEN_SEASON_FRACTION,
                ),
                hold_days=hold_days,
                max_sell_ratio=(
                    None
                    if max_sell is None
                    else _ratio(max_sell, "max_sell_ratio", Fraction(1))
                ),
                note=_text(entry["note"], "note"),
            )
        )
    months = [decision.month for decision in decisions]
    if months != sorted(set(months)):
        raise AlphaGuardError("decision months are not sorted and unique")
    return tuple(decisions)


def evaluate(
    evidence: AlphaEvidence, decisions: tuple[CapDecision, ...]
) -> GuardReport:
    """Report earned versus sold for the evidence month against its decision."""

    decision = next((d for d in decisions if d.month == evidence.month), None)
    if decision is None:
        return GuardReport(
            status=STATUS_DECISION_REQUIRED,
            evidence=evidence,
            decision=None,
            over_hotkeys=(),
            aggregate_over=False,
            recommendation=RECOMMEND_DECISION_REQUIRED,
        )
    limit = decision.max_sell_ratio
    if limit is None:
        return GuardReport(
            status=STATUS_REPORT_ONLY,
            evidence=evidence,
            decision=decision,
            over_hotkeys=(),
            aggregate_over=False,
            recommendation="",
        )
    over = tuple(row.hotkey for row in evidence.rows if row.over(limit))
    aggregate = AlphaRow(
        hotkey="",
        earned=sum((row.earned for row in evidence.rows), Fraction(0)),
        sold=sum((row.sold for row in evidence.rows), Fraction(0)),
    )
    aggregate_over = aggregate.over(limit)
    diluting = bool(over) or aggregate_over
    return GuardReport(
        status=STATUS_DILUTING if diluting else STATUS_WITHIN_GUARD,
        evidence=evidence,
        decision=decision,
        over_hotkeys=over,
        aggregate_over=aggregate_over,
        recommendation=RECOMMEND_DILUTING if diluting else "",
    )


def _canonical(document: dict[str, object]) -> bytes:
    return (
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        + b"\n"
    )


def _pinned_decisions() -> tuple[CapDecision, ...]:
    return load_decisions(
        _canonical(PINNED_DECISIONS_DOCUMENT), expected_sha256=PINNED_DECISIONS_SHA256
    )


OWNER_DECISIONS = _pinned_decisions()


def _render(report: GuardReport) -> str:
    data = report.as_dict()
    lines = [
        f"status: {data['status']}",
        f"month: {data['month']}  window: {data['evidence']['window_start']}"
        f" .. {data['evidence']['window_end']}  observed: {data['evidence']['observed_at']}",
        f"source: {data['evidence']['source']} {data['evidence']['source_endpoint']}",
        f"evidence sha256: {data['evidence']['sha256']}",
        f"ledger fraction: {data['ledger_fraction']} (ceiling {data['max_open_season_fraction']})",
    ]
    if report.decision is not None:
        d = data["decision"]
        lines.append(
            f"decision: {d['decided_by']} on {d['decided_on']}, hold {d['hold_days']} days,"
            f" max sell ratio {d['max_sell_ratio']}"
        )
    lines.append("hotkey  earned  sold  retained  sell_ratio")
    for row in data["rows"]:
        flag = "  OVER" if row["hotkey"] in report.over_hotkeys else ""
        lines.append(
            f"{row['hotkey']}  {row['alpha_earned']}  {row['alpha_sold']}"
            f"  {row['alpha_retained']}  {row['sell_ratio']}{flag}"
        )
    totals = data["totals"]
    lines.append(
        f"total  {totals['alpha_earned']}  {totals['alpha_sold']}"
        f"  {totals['alpha_retained']}  {totals['sell_ratio']}"
        + ("  OVER" if report.aggregate_over else "")
    )
    if report.recommendation:
        lines.append(f"recommendation: {report.recommendation}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cathedral_thin.independent_runtime.alpha_growth",
        description="Report alpha earned versus sold per hotkey against the owner's monthly decision.",
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        raw = args.evidence.read_bytes()
        report = evaluate(load_evidence(raw), OWNER_DECISIONS)
    except (OSError, AlphaGuardError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    else:
        print(_render(report))
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ALPHA_EVIDENCE_SCHEMA",
    "AlphaEvidence",
    "AlphaGuardError",
    "AlphaRow",
    "CapDecision",
    "DECISIONS_SCHEMA",
    "GuardReport",
    "MAX_OPEN_SEASON_FRACTION",
    "OWNER_DECISIONS",
    "PINNED_DECISIONS_DOCUMENT",
    "PINNED_DECISIONS_SHA256",
    "evaluate",
    "load_decisions",
    "load_evidence",
    "main",
]
