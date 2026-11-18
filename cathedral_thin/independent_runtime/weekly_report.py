"""Weekly per-hotkey readback of what this validator applied (AB#322).

``cathedral-validator weekly-report`` reads the validator's own signed
telemetry spool and, on request, the chain. It loads no key, signs nothing and
never writes to the chain.

For each hotkey over a seven day window it reports:

- applied weight: the ``weight_u16`` of every finalized write this validator
  published, its mean over the window and the last value;
- verification pass rate: the share of this validator's published cycles in
  which the hotkey had at least one verified machine. This is what this
  validator saw; it is not wall-clock uptime;
- delivered room-hours and uptime: only from the injected feeds (AB#319 and
  AB#326). Without a feed the value is null and says ``NO_FEED``; this module
  never estimates either;
- chain readback: the stored ``Weights`` row at the block the last published
  write applied, compared with that event, and the row at the finalized head.

The open-season fraction is reported as it is in code: 0 and not wired. The
owner sets it (AB#322); the share rule is AB#320.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence

from cathedral_thin.independent.constants import MECID, W

from .direct_contract import SUBNET_OWNER_BURN_HOTKEYS
from .telemetry import (
    MAX_TELEMETRY_HISTORY_BYTES,
    TelemetryError,
    validate_public_telemetry_event,
)

WEEKLY_REPORT_SCHEMA = "cathedral_validator_weekly_report_v1"
WINDOW = timedelta(days=7)
# Nothing in this release pays an open-season share. Report the code's fact,
# not a configured wish; change this only when the share is wired (AB#320).
OPEN_SEASON = {"fraction": "0", "status": "NOT_WIRED"}

NO_FEED = "NO_FEED"
FEED = "FEED"

CHAIN_MATCHES = "MATCHES_LAST_APPLIED"
CHAIN_DIFFERS = "DIFFERS"
CHAIN_UNPROVEN = "UNPROVEN"
CHAIN_UNAVAILABLE = "UNAVAILABLE"
CHAIN_NOT_READ = "NOT_READ"
HEAD_SAME = "SAME_AS_APPLIED"
HEAD_CHANGED = "CHANGED_SINCE_APPLIED"


class WeeklyReportError(RuntimeError):
    """The report cannot be built from these inputs."""


@dataclass(frozen=True)
class TelemetryHistory:
    events: tuple[Mapping[str, Any], ...]
    rejected: Mapping[str, int]


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WeeklyReportError("time must be ISO 8601 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WeeklyReportError("time must be ISO 8601 UTC ending in Z") from exc
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_telemetry_history(
    path: Path, *, netuid: int, expected_hotkey: str
) -> TelemetryHistory:
    """Read every spool line, keeping only signed events from this validator.

    Each kept line passed ``validate_public_telemetry_event``: schema, the
    signature by the hotkey the event names, and a finalized receipt. That
    signature is self-referential, so events whose validator is not
    ``expected_hotkey`` are rejected too.
    """

    if path.is_symlink():
        raise WeeklyReportError("telemetry spool is a symlink")
    try:
        if not path.is_file():
            raise WeeklyReportError("telemetry spool is not a regular file")
        if path.stat().st_size > MAX_TELEMETRY_HISTORY_BYTES:
            raise WeeklyReportError("telemetry spool is larger than its bound")
        raw = path.read_bytes()
    except OSError as exc:
        raise WeeklyReportError("telemetry spool cannot be read") from exc
    events: list[Mapping[str, Any]] = []
    rejected: dict[str, int] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            document = json.loads(line.decode("ascii"))
            if not isinstance(document, dict):
                raise TelemetryError("not an object")
            event = validate_public_telemetry_event(document, netuid=netuid)
        except (UnicodeDecodeError, json.JSONDecodeError, TelemetryError):
            rejected["invalid"] = rejected.get("invalid", 0) + 1
            continue
        if event["validator"]["hotkey"] != expected_hotkey:
            rejected["other_validator"] = rejected.get("other_validator", 0) + 1
            continue
        events.append(event)
    return TelemetryHistory(
        events=tuple(events), rejected=dict(sorted(rejected.items()))
    )


def parse_feed(
    document: object, *, label: str, upper: Fraction | None
) -> dict[str, Fraction]:
    """``{hotkey: "decimal"}`` into exact values; any bad row refuses the feed."""

    if not isinstance(document, dict):
        raise WeeklyReportError(f"{label} feed must be a JSON object")
    values: dict[str, Fraction] = {}
    for hotkey, text in document.items():
        if (
            not isinstance(hotkey, str)
            or not 1 <= len(hotkey) <= 64
            or not hotkey.isascii()
            or not hotkey.isalnum()
            or not isinstance(text, str)
        ):
            raise WeeklyReportError(f"{label} feed row is malformed")
        try:
            decimal = Decimal(text)
        except InvalidOperation as exc:
            raise WeeklyReportError(f"{label} feed value is not a decimal") from exc
        if not decimal.is_finite():
            raise WeeklyReportError(f"{label} feed value is not finite")
        value = Fraction(decimal)
        if value < 0 or (upper is not None and value > upper):
            raise WeeklyReportError(f"{label} feed value is out of range")
        values[hotkey] = value
    return values


def _ratio_text(value: Fraction) -> str:
    return f"{float(value):.4f}"


def _upscale(weights: Sequence[int]) -> tuple[int, ...]:
    # The pallet stores the max-upscaled vector; reuse the writer's exact copy.
    from .direct_writer import _subtensor_max_upscale_to_u16

    return _subtensor_max_upscale_to_u16(tuple(weights))


def compare_event_to_row(
    event: Mapping[str, Any],
    rows: Sequence[tuple[int, str | None, int]],
    *,
    burn_hotkey: str | None,
) -> dict[str, Any]:
    """Compare one published event with the stored row its write produced.

    ``rows`` is ``(uid, hotkey at that block, stored weight)``. Listed miners
    and the burn are compared exactly: the pallet upscales each value against
    the vector maximum, and the burn (at least 8/10 since #338) is that
    maximum. Escape breakers that serve no axon are on the wire but not in the
    event; their stored total is checked against what the event leaves over,
    within one unit per row of rounding.
    """

    listed = {
        int(miner["uid"]): (str(miner["hotkey"]), int(miner["weight_u16"]))
        for miner in event["miners"]
        if int(miner["weight_u16"]) > 0
    }
    burn = int(event["burn_weight"])
    leftover = W - burn - sum(weight for _hotkey, weight in listed.values())
    if burn == 0 and leftover > 0:
        # A legacy event with unlisted weight: the maximum may be unlisted.
        return {
            "status": CHAIN_UNPROVEN,
            "reason": "legacy event omits part of its vector",
        }
    values = [weight for _hotkey, weight in listed.values()]
    if burn:
        values.append(burn)
    maximum = max(values) if values else 0
    if maximum == 0:
        return {"status": CHAIN_UNPROVEN, "reason": "event carries no weight"}
    expected_listed = dict(zip(listed, _upscale(values)[: len(listed)], strict=True))
    expected_burn = _upscale(values)[-1] if burn else 0

    entries: list[dict[str, Any]] = []
    differs = False
    seen: set[int] = set()
    unlisted_total = 0
    unlisted_count = 0
    burn_seen = False
    for uid, hotkey, stored in rows:
        if uid in listed:
            seen.add(uid)
            event_hotkey, _weight = listed[uid]
            ok = hotkey == event_hotkey and stored == expected_listed[uid]
            entries.append(
                {
                    "uid": uid,
                    "hotkey": hotkey,
                    "kind": "listed",
                    "stored": stored,
                    "expected": expected_listed[uid],
                    "status": "MATCH" if ok else CHAIN_DIFFERS,
                }
            )
            differs = differs or not ok
        elif burn and burn_hotkey is not None and hotkey == burn_hotkey:
            burn_seen = True
            ok = stored == expected_burn
            entries.append(
                {
                    "uid": uid,
                    "hotkey": hotkey,
                    "kind": "burn",
                    "stored": stored,
                    "expected": expected_burn,
                    "status": "MATCH" if ok else CHAIN_DIFFERS,
                }
            )
            differs = differs or not ok
        else:
            unlisted_total += stored
            unlisted_count += 1
            entries.append(
                {
                    "uid": uid,
                    "hotkey": hotkey,
                    "kind": "not_in_event",
                    "stored": stored,
                    "expected": None,
                    "status": "NOT_IN_EVENT",
                }
            )
    for uid in sorted(set(listed) - seen):
        differs = True
        entries.append(
            {
                "uid": uid,
                "hotkey": listed[uid][0],
                "kind": "listed",
                "stored": 0,
                "expected": expected_listed[uid],
                "status": CHAIN_DIFFERS,
            }
        )
    if burn and not burn_seen:
        differs = True
    expected_unlisted = Fraction(leftover * W, maximum)
    if abs(unlisted_total - expected_unlisted) > max(unlisted_count, 1):
        differs = True
    return {
        "status": CHAIN_DIFFERS if differs else CHAIN_MATCHES,
        "unlisted": {
            "rows": unlisted_count,
            "stored_total": unlisted_total,
            "expected_total": _ratio_text(expected_unlisted),
        },
        "entries": entries,
    }


def read_chain_row(
    subtensor: Any, *, netuid: int, validator_uid: int, block_hash: str
) -> tuple[str | None, tuple[tuple[int, str | None, int], ...]]:
    """Read-only: the validator's hotkey and stored row at one block."""

    from bittensor.utils import get_mechid_storage_index

    from .direct_writer import _raw_value, _stored_weight_rows

    substrate = subtensor.substrate

    def key(uid: int) -> str | None:
        owner = _raw_value(
            substrate.query(
                module="SubtensorModule",
                storage_function="Keys",
                params=[netuid, uid],
                block_hash=block_hash,
            )
        )
        return owner if isinstance(owner, str) else None

    stored = substrate.query(
        module="SubtensorModule",
        storage_function="Weights",
        params=[get_mechid_storage_index(netuid, MECID), validator_uid],
        block_hash=block_hash,
    )
    return key(validator_uid), tuple(
        (uid, key(uid), weight) for uid, weight in _stored_weight_rows(stored)
    )


def chain_readback(subtensor: Any, event: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the last published write against storage. Never raises."""

    from .axon import finalized_head

    netuid = int(event["netuid"])
    validator_uid = int(event["validator"]["uid"])
    validator_hotkey = str(event["validator"]["hotkey"])
    applied_hash = str(event["submission"]["block_hash"])
    try:
        applied_key, applied_rows = read_chain_row(
            subtensor,
            netuid=netuid,
            validator_uid=validator_uid,
            block_hash=applied_hash,
        )
        head_number, head_hash = finalized_head(subtensor)
        head_key, head_rows = read_chain_row(
            subtensor, netuid=netuid, validator_uid=validator_uid, block_hash=head_hash
        )
    except Exception as exc:  # noqa: BLE001 - a report states the failure
        return {"status": CHAIN_UNAVAILABLE, "reason": type(exc).__name__}
    if applied_key != validator_hotkey:
        return {
            "status": CHAIN_DIFFERS,
            "reason": "validator UID was not this hotkey at the applied block",
        }
    comparison = compare_event_to_row(
        event, applied_rows, burn_hotkey=SUBNET_OWNER_BURN_HOTKEYS.get(netuid)
    )
    head_by_uid = {uid: (hotkey, weight) for uid, hotkey, weight in head_rows}
    return {
        **comparison,
        "applied_block": {
            "number": int(event["submission"]["block_number"]),
            "hash": applied_hash,
        },
        "head_block": {"number": head_number, "hash": head_hash},
        "head": HEAD_SAME
        if head_key == validator_hotkey and head_rows == applied_rows
        else HEAD_CHANGED,
        "head_rows": [
            {"uid": uid, "hotkey": hotkey, "stored": weight}
            for uid, (hotkey, weight) in sorted(head_by_uid.items())
        ],
    }


def build_weekly_report(
    history: TelemetryHistory,
    *,
    window_end: datetime,
    delivered_hours: Mapping[str, Fraction] | None = None,
    uptime: Mapping[str, Fraction] | None = None,
    chain: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Pure: aggregate one seven day window per hotkey."""

    if window_end.tzinfo is None:
        raise WeeklyReportError("window end must be UTC")
    window_start = window_end - WINDOW
    timed = sorted(
        ((_parse_time(event["observed_at"]), event) for event in history.events),
        key=lambda item: (item[0], item[1]["submission"]["block_number"]),
    )
    in_window = [event for when, event in timed if window_start <= when < window_end]
    if not timed:
        coverage = "NO_EVENTS"
    elif timed[0][0] > window_start:
        # The spool is bounded (720 events, 16 MiB) or started mid-window.
        coverage = "PARTIAL_WINDOW"
    else:
        coverage = "FULL_WINDOW"

    cycles = len(in_window)
    rows: dict[str, dict[str, Any]] = {}

    def row_for(hotkey: str) -> dict[str, Any]:
        return rows.setdefault(
            hotkey,
            {
                "hotkey": hotkey,
                "uids": set(),
                "cycles_present": 0,
                "cycles_verified": 0,
                "cycles_weighted": 0,
                "weight_total": 0,
                "last_weight_u16": 0,
            },
        )

    for event in in_window:
        for miner in event["miners"]:
            row = row_for(str(miner["hotkey"]))
            row["uids"].add(int(miner["uid"]))
            row["cycles_present"] += 1
            if int(miner["distinct_verified_compute"]) > 0:
                row["cycles_verified"] += 1
            weight = int(miner["weight_u16"])
            if weight > 0:
                row["cycles_weighted"] += 1
            row["weight_total"] += weight
    last_weights: dict[str, int] = {}
    if in_window:
        for miner in in_window[-1]["miners"]:
            last_weights[str(miner["hotkey"])] = int(miner["weight_u16"])
    for hotkey in delivered_hours or {}:
        row_for(hotkey)
    # Escape breakers that serve no axon are paid but absent from events;
    # list them from the chain row. The burn is reported once, in the header.
    for entry in (chain or {}).get("entries", ()):
        if entry.get("kind") == "not_in_event" and entry.get("hotkey"):
            row_for(str(entry["hotkey"]))
    for hotkey in uptime or {}:
        row_for(hotkey)

    chain_by_hotkey: dict[str, list[Mapping[str, Any]]] = {}
    for entry in (chain or {}).get("entries", ()):
        if entry.get("hotkey"):
            chain_by_hotkey.setdefault(str(entry["hotkey"]), []).append(entry)

    hotkeys: list[dict[str, Any]] = []
    for hotkey in sorted(rows):
        row = rows[hotkey]
        mean = Fraction(row["weight_total"], cycles) if cycles else Fraction(0)
        chain_entries = chain_by_hotkey.get(hotkey, [])
        hotkeys.append(
            {
                "hotkey": hotkey,
                "uids": sorted(row["uids"]),
                "cycles_present": row["cycles_present"],
                "cycles_verified": row["cycles_verified"],
                "cycles_weighted": row["cycles_weighted"],
                "verification_pass_rate": _ratio_text(
                    Fraction(row["cycles_verified"], cycles)
                )
                if cycles
                else None,
                "mean_weight_u16": _ratio_text(mean),
                "mean_weight_share": _ratio_text(mean / W),
                "last_weight_u16": last_weights.get(hotkey, 0),
                "delivered_hours": f"{float(delivered_hours[hotkey]):.2f}"
                if delivered_hours is not None and hotkey in delivered_hours
                else None,
                "delivered_hours_source": FEED
                if delivered_hours is not None
                else NO_FEED,
                "uptime": _ratio_text(uptime[hotkey])
                if uptime is not None and hotkey in uptime
                else None,
                "uptime_source": FEED if uptime is not None else NO_FEED,
                # Stored values are max-upscaled by the pallet, not wire units.
                "chain_stored_u16": sum(int(entry["stored"]) for entry in chain_entries)
                if chain_entries
                else (0 if chain is not None and "entries" in chain else None),
                "chain_status": ",".join(
                    sorted({str(entry["status"]) for entry in chain_entries})
                )
                or (CHAIN_NOT_READ if chain is None else "NOT_ON_CHAIN"),
            }
        )

    latest = in_window[-1] if in_window else None
    return {
        "schema": WEEKLY_REPORT_SCHEMA,
        "window": {
            "start": _iso(window_start),
            "end": _iso(window_end),
            "coverage": coverage,
            "first_retained_event": _iso(timed[0][0]) if timed else None,
        },
        "validator": dict(latest["validator"]) if latest else None,
        "netuid": int(latest["netuid"]) if latest else None,
        "applied_cycles": cycles,
        "first_applied_block": int(in_window[0]["submission"]["block_number"])
        if in_window
        else None,
        "last_applied_block": int(latest["submission"]["block_number"])
        if latest
        else None,
        "mean_burn_weight_u16": _ratio_text(
            Fraction(sum(int(event["burn_weight"]) for event in in_window), cycles)
        )
        if cycles
        else None,
        "rejected_events": dict(history.rejected),
        "open_season": dict(OPEN_SEASON),
        "chain_readback": dict(chain)
        if chain is not None
        else {"status": CHAIN_NOT_READ},
        "hotkeys": hotkeys,
    }


def render_text(report: Mapping[str, Any]) -> str:
    window = report["window"]
    chain = report["chain_readback"]
    lines = [
        f"Weekly validator report {window['start']} to {window['end']} "
        f"({window['coverage']})",
        f"validator {report['validator']['hotkey'] if report['validator'] else '-'} "
        f"netuid {report['netuid']} applied cycles {report['applied_cycles']} "
        f"blocks {report['first_applied_block']}..{report['last_applied_block']}",
        f"open-season fraction {report['open_season']['fraction']} "
        f"({report['open_season']['status']}); mean burn "
        f"{report['mean_burn_weight_u16']}",
        f"chain readback {chain['status']}"
        + (f", head {chain['head']}" if "head" in chain else "")
        + (f", reason {chain['reason']}" if "reason" in chain else ""),
        f"rejected events {report['rejected_events'] or 0}",
        "",
        "hotkey | uids | delivered_hours | uptime | pass_rate | mean_weight | "
        "last_weight | chain_stored | chain",
    ]
    for row in report["hotkeys"]:
        lines.append(
            " | ".join(
                str(value)
                for value in (
                    row["hotkey"],
                    ",".join(str(uid) for uid in row["uids"]) or "-",
                    row["delivered_hours"] or row["delivered_hours_source"],
                    row["uptime"] or row["uptime_source"],
                    row["verification_pass_rate"],
                    row["mean_weight_u16"],
                    row["last_weight_u16"],
                    row["chain_stored_u16"],
                    row["chain_status"],
                )
            )
        )
    return "\n".join(lines)


def _read_feed(
    path: Path | None, *, label: str, upper: Fraction | None
) -> dict[str, Fraction] | None:
    if path is None:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WeeklyReportError(f"{label} feed cannot be read") from exc
    return parse_feed(document, label=label, upper=upper)


def _parser(command: str) -> argparse.ArgumentParser:
    from .direct_validator import _add_netuid_argument, _add_network_argument

    parser = argparse.ArgumentParser(
        prog=f"cathedral-validator {command}",
        description=(
            "Seven day per-hotkey readback of applied weight from this "
            "validator's signed telemetry, with optional chain readback. "
            "Loads no key and never signs."
        ),
    )
    _add_network_argument(parser)
    _add_netuid_argument(parser)
    parser.add_argument("--expected-hotkey", required=True)
    parser.add_argument("--telemetry", required=True, type=Path)
    parser.add_argument("--end", help="window end, ISO 8601 UTC ending in Z")
    parser.add_argument("--chain-readback", action="store_true")
    parser.add_argument("--delivered-hours-json", type=Path)
    parser.add_argument("--uptime-json", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str], *, subtensor_factory: Any = None) -> int:
    """Return 0 with a report, 1 when the inputs refuse."""

    from .direct_validator import (
        WEEKLY_REPORT_COMMAND,
        _configured_netuid,
        _expected_hotkey,
        _pinned_network,
    )

    options = _parser(WEEKLY_REPORT_COMMAND).parse_args(list(argv))
    network = _pinned_network(options.network)
    netuid = _configured_netuid(options.netuid)
    hotkey = _expected_hotkey(options.expected_hotkey)
    try:
        end = _parse_time(options.end) if options.end else datetime.now(UTC)
        history = load_telemetry_history(
            options.telemetry, netuid=netuid, expected_hotkey=hotkey
        )
        delivered = _read_feed(
            options.delivered_hours_json, label="delivered hours", upper=None
        )
        uptime = _read_feed(options.uptime_json, label="uptime", upper=Fraction(1))
    except WeeklyReportError as exc:
        print(f"WEEKLY_REPORT_REFUSED: {exc}", flush=True)
        return 1
    chain: dict[str, Any] | None = None
    if options.chain_readback:
        in_window = [
            event
            for event in history.events
            if end - WINDOW <= _parse_time(event["observed_at"]) < end
        ]
        if not in_window:
            chain = {"status": CHAIN_UNPROVEN, "reason": "no applied write in window"}
        else:
            latest = max(
                in_window,
                key=lambda event: (
                    _parse_time(event["observed_at"]),
                    event["submission"]["block_number"],
                ),
            )
            if subtensor_factory is None:
                import bittensor as bt

                from cathedral_thin.bt_compat import make_subtensor

                def subtensor_factory() -> Any:
                    return make_subtensor(bt, network=network)

            try:
                subtensor = subtensor_factory()
            except Exception as exc:  # noqa: BLE001 - a report states the failure
                chain = {"status": CHAIN_UNAVAILABLE, "reason": type(exc).__name__}
            else:
                chain = chain_readback(subtensor, latest)
    report = build_weekly_report(
        history,
        window_end=end,
        delivered_hours=delivered,
        uptime=uptime,
        chain=chain,
    )
    if options.format == "json":
        print(json.dumps(report, sort_keys=True), flush=True)
    else:
        print(render_text(report), flush=True)
    return 0


__all__ = [
    "OPEN_SEASON",
    "WEEKLY_REPORT_SCHEMA",
    "TelemetryHistory",
    "WeeklyReportError",
    "build_weekly_report",
    "chain_readback",
    "compare_event_to_row",
    "load_telemetry_history",
    "main",
    "parse_feed",
    "read_chain_row",
    "render_text",
]
