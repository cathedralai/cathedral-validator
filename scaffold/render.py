"""Human-facing terminal rendering for the validator's lifecycle stream.

The validator emits two streams that must not be confused. The JSONL journal is
the durable machine record and its shape is a contract with the status
publisher, so it is never touched here. Standard output is for a person
watching a long-running service, and this module owns it entirely.

The design goal is that an operator can answer four questions at a glance
without parsing anything: is it alive and in which mode, did the signed vector
verify, what did it decide to pay, and did the chain accept it. Every value is
passed through the same neutralizer the journal uses, so nothing renders
control characters or leaks a secret into a terminal.

Emission is streaming rather than buffered-per-tick, because a tick can take
forty seconds and a silent terminal reads as a hang. The one exception is the
feed row: signature, freshness and rollback each arrive as a separate event and
collapse into a single line, so those fragments accumulate and flush when the
vector is accepted, rejected, or the tick moves on to another row.
"""

from __future__ import annotations

import datetime
import os
import re
import sys
import time
from typing import Any

from .events import _neutralize

# Finney block time. Only used to render block deltas as human durations; no
# decision anywhere depends on it, so an occasional drifting block is harmless.
_SECS_PER_BLOCK = 12

_LABEL_WIDTH = 10
_INDENT = "   "
_RULE_WIDTH = 68


def _color_enabled() -> bool:
    """Colour only a real terminal, and honour NO_COLOR."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CATHEDRAL_VALIDATOR_NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001 - a closed or exotic stream is not a tty
        return False


_COLOR = _color_enabled()


def _sgr(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def dim(t: str) -> str:
    return _sgr("2", t)


def bold(t: str) -> str:
    return _sgr("1", t)


def green(t: str) -> str:
    return _sgr("32", t)


def red(t: str) -> str:
    return _sgr("31", t)


def yellow(t: str) -> str:
    return _sgr("33", t)


def cyan(t: str) -> str:
    return _sgr("36", t)


def _n(value: Any) -> str:
    """Neutralize any interpolated value, exactly as the journal does."""
    return _neutralize(str(value))


def _sep(parts: list[str]) -> str:
    return dim(" · ").join(p for p in parts if p)


def _short(value: str, head: int = 10, tail: int = 5) -> str:
    """Middle-elide a long opaque identifier so the columns stay aligned."""
    text = _n(value)
    if len(text) <= head + tail + 1:
        return text
    return f"{text[:head]}…{text[-tail:]}"


def _duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f}m"
    return f"{minutes / 60:.1f}h"


def _blocks_as_time(blocks: Any) -> str:
    try:
        n = int(blocks)
    except (TypeError, ValueError):
        return ""
    return _duration(n * _SECS_PER_BLOCK)


_KV = re.compile(r"(\w+)=(\S+)")


def parse_detail(detail: str) -> tuple[dict[str, str], str]:
    """Split ``k=v k=v free text`` into a mapping plus whatever was not a pair.

    The lifecycle call sites were written for a flat key=value line, so this
    keeps them working untouched while the renderer gets structured input.
    """
    kv = {m.group(1): m.group(2) for m in _KV.finditer(detail or "")}
    leftover = _KV.sub("", detail or "").strip()
    return kv, leftover


class _Stream:
    """Rendering state for one process: tick framing and the pending feed row."""

    def __init__(self) -> None:
        self.feed_bits: list[str] = []
        self.feed_open = False
        self.in_tick = False
        self.rows_since_rule = 0
        self.tick_started: float | None = None

    def elapsed(self) -> str:
        if self.tick_started is None:
            return ""
        return _duration(time.monotonic() - self.tick_started)

    # -- primitives ---------------------------------------------------------

    def write(self, text: str = "") -> None:
        print(text)

    def row(self, label: str, text: str) -> None:
        # Anything emitted outside a tick (startup preflight, receipt recovery)
        # opens its own block, so a row is never orphaned above the first rule.
        if not self.in_tick:
            self.rule("")
        self.flush_feed(unless=label)
        self.write(f"{_INDENT}{dim(label.ljust(_LABEL_WIDTH))}{text}")
        self.rows_since_rule += 1

    def note(self, symbol: str, text: str) -> None:
        if not self.in_tick:
            self.rule("")
        self.flush_feed()
        self.write(f"{_INDENT}{symbol} {text}")
        self.rows_since_rule += 1

    def rule(self, stamp: str = "") -> None:
        # Rows emitted outside a tick carry no event timestamp of their own, so
        # the block is stamped with the wall clock instead of rendering blank.
        stamp = stamp or datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S")
        # An empty block helps nobody: a rule drawn with nothing under it yet
        # is reused rather than stacked.
        if self.in_tick and self.rows_since_rule == 0:
            return
        self.flush_feed()
        if self.in_tick:
            self.write()
        head = f"── {stamp} "
        self.write(dim(_INDENT + head + "─" * max(0, _RULE_WIDTH - len(head))))
        self.in_tick = True
        self.rows_since_rule = 0
        self.tick_started = time.monotonic()

    # -- the one accumulated row -------------------------------------------

    def feed(self, fragment: str) -> None:
        self.feed_bits.append(fragment)
        self.feed_open = True

    def flush_feed(self, unless: str | None = None) -> None:
        if not self.feed_open or unless == "feed":
            return
        bits, self.feed_bits, self.feed_open = self.feed_bits, [], False
        self.write(f"{_INDENT}{dim('feed'.ljust(_LABEL_WIDTH))}{_sep(bits)}")


_STREAM = _Stream()


def _hhmmss(iso_ts: str) -> str:
    """`2026-07-27T22:04:17.239Z` -> `22:04:17`, falling back to the input."""
    match = re.search(r"T(\d{2}:\d{2}:\d{2})", iso_ts or "")
    return match.group(1) if match else _n(iso_ts)


# -- per-event renderers ---------------------------------------------------
#
# Each returns None after emitting. Events deliberately absent from this table
# fall through to a readable default rather than being dropped, so a new call
# site can never silently vanish from the operator's view.


def _r_feed_fetch(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.rule(_hhmmss(ts))


def _r_feed_fetched(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    version = _n(kv.get("policy_version", ""))
    # The version is a millisecond epoch: the low digits are what changes
    # between ticks, so they are the only part worth a person's attention.
    s.feed(f"v…{version[-6:]}" if version else "fetched")


def _r_signature(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.feed(green("signed"))


def _r_freshness(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.feed(green("fresh"))


def _r_rollback(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.feed(green("fence ok"))


def _r_vector_accepted(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.flush_feed()
    miners = kv.get("miners")
    burn = kv.get("burn")
    parts = []
    if miners is not None:
        n = _n(miners)
        parts.append(f"{bold(n)} miner{'' if n == '1' else 's'} scored")
    if burn:
        parts.append(f"burn {_n(burn)}")
    s.row("vector", _sep(parts) or "accepted")


def _r_vector_rejected(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    stage = kv.get("stage", "")
    reason = kv.get("reason", "") or rest
    s.note(red("✗"), _sep([red("vector rejected"), _n(stage), _n(reason)]))


def _r_vector_idle(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("vector", dim(_n(rest) or "nothing to act on"))


def _r_verify_failed(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.note(red("✗"), _sep([red("verification failed"), _n(kv.get("reason", ""))]))


def _r_feed_unavailable(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.flush_feed()
    s.row(
        "feed",
        _sep(
            [
                yellow("unavailable"),
                _n(kv.get("reason", "")),
                dim("continuing on independent evidence"),
            ]
        ),
    )


def _r_feed_invalid(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.flush_feed()
    s.row("feed", _sep([red("invalid"), _n(kv.get("reason", ""))]))


def _r_preflight(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    block = kv.get("block", "")
    until_epoch = kv.get("blocks_until_epoch")
    since = kv.get("blocks_since_update")
    safe = kv.get("replacement_safe_uids")
    parts = [f"block {bold(_n(block))}" if block else ""]
    if until_epoch is not None:
        parts.append(f"epoch in {_blocks_as_time(until_epoch)}")
    if since is not None:
        parts.append(f"last write {_blocks_as_time(since)} ago")
    if safe is not None:
        parts.append(dim(f"{_n(safe)} uids replacement-safe"))
    s.row("chain", _sep(parts))


def _r_map_complete(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    burn_uid = kv.get("burn_uid")
    vector = kv.get("vector", "")
    entries = []
    for pair in vector.split(","):
        if ":" not in pair:
            continue
        uid, _, weight = pair.partition(":")
        try:
            pct = f"{float(weight) * 100:.1f}%"
        except ValueError:
            pct = _n(weight)
        tag = dim("burn") if uid == burn_uid else ""
        entries.append(f"{cyan(_n(uid))} {bold(pct)}{(' ' + tag) if tag else ''}")
    s.row("weights", _sep(entries) if entries else dim("none"))


def _r_map_offline(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("weights", dim("offline · synthetic uid map, no chain access"))


def _r_dry_run(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.note(dim("·"), dim(f"dry run, nothing written {_n(rest)}".strip()))


def _r_chain_submitted(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    final = str(kv.get("finalized", "")).lower() == "true"
    s.row(
        "submit",
        _sep(
            [
                _short(kv.get("extrinsic_hash", "")),
                f"block {bold(_n(kv.get('block_number', '')))}",
                green("finalized") if final else yellow("included"),
            ]
        ),
    )
    took = s.elapsed()
    s.note(green("✓"), _sep([green("weights written"), dim(f"in {took}" if took else "")]))


def _r_chain_problem(label: str):
    def render(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
        parts = [
            _n(kv.get("reason", "")),
            _short(kv.get("attempt_id", "")) if kv.get("attempt_id") else "",
        ]
        s.note(yellow("⚠"), _sep([yellow(label)] + parts))

    return render


def _r_provenance(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("evidence", _sep([_n(rest), _n(kv.get("reason", ""))]) or dim("audited"))


def _r_suppress(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    """Startup facts already shown in the banner; not repeated per tick."""
    return None


_RENDERERS = {
    "FEED fetch": _r_feed_fetch,
    "FEED fetched": _r_feed_fetched,
    "FEED unavailable": _r_feed_unavailable,
    "FEED invalid": _r_feed_invalid,
    "SIGNATURE valid": _r_signature,
    "FRESHNESS valid": _r_freshness,
    "ROLLBACK valid": _r_rollback,
    "VECTOR accepted": _r_vector_accepted,
    "VECTOR rejected": _r_vector_rejected,
    "VECTOR idle": _r_vector_idle,
    "VERIFY failed": _r_verify_failed,
    "PREFLIGHT complete": _r_preflight,
    "MAP complete": _r_map_complete,
    "MAP offline": _r_map_offline,
    "WEIGHTS dry-run": _r_dry_run,
    "CHAIN submitted": _r_chain_submitted,
    "CHAIN failed": _r_chain_problem("chain call failed"),
    "CHAIN ambiguous": _r_chain_problem("outcome unproven"),
    "CHAIN expired": _r_chain_problem("attempt expired"),
    "CHAIN recovered": _r_chain_problem("recovered a pending attempt"),
    "CHAIN reservation released": _r_chain_problem("reservation released"),
    "PROVENANCE": _r_provenance,
    "PROVENANCE mismatch": _r_provenance,
    "AUTHORITY provenance": _r_provenance,
    "LAUNCH rewarded-set gate": _r_provenance,
    "PIN active": _r_suppress,
    "MODE active": _r_suppress,
}


def lifecycle(event: str, detail: str, timestamp: str) -> None:
    """Render one lifecycle event. Never raises; falls back to a plain row."""
    try:
        kv, rest = parse_detail(detail)
        renderer = _RENDERERS.get(event.strip())
        if renderer is not None:
            renderer(_STREAM, kv, rest, timestamp)
            return
        _STREAM.row(event.split()[0].lower()[:_LABEL_WIDTH], _n(detail) or _n(event))
    except Exception:  # noqa: BLE001 - presentation must never break the tick
        print(f"{_n(event)} {_n(detail)}")


# Plain-English readings of the refusals an operator actually meets. The
# original sanitized text is always appended in dim, so nothing is hidden and a
# message that stops matching degrades to today's behaviour rather than lying.
_PLAIN = (
    (
        r"inside the live validator weight-update cooldown",
        "waiting out the chain's write cooldown",
    ),
    (
        r"authority requires FULL assurance",
        "independent recomputation could not reach full assurance",
    ),
    (
        r"cannot prove the exact next epoch",
        "too close to the epoch boundary to land safely",
    ),
    (
        r"finalized head advanced after preflight",
        "the chain moved while preparing; rebuilding from a fresh head",
    ),
    (
        r"policy rollback .* <=",
        "this policy version was already used; waiting for a fresher one",
    ),
    (
        r"UID mappings stable|not chain-immune",
        "a target UID could be reassigned mid-flight; refusing to pay the wrong hotkey",
    ),
    (
        r"burn destination is not the pinned burn hotkey",
        "the signed vector named an unexpected burn destination",
    ),
    (r"validated_supply .* mismatch", "the signed vector does not match the contract"),
    (r"single writer|already active", "another writer holds the submission lock"),
)


def humanize(text: str) -> tuple[str, str]:
    """Return (plain reading, original detail). Original is never discarded."""
    raw = _n(text)
    for pattern, plain in _PLAIN:
        if re.search(pattern, raw):
            return plain, raw
    return raw, ""


def outcome(ok: bool, text: str) -> None:
    """Terminal line for a tick, whether or not anything was written."""
    plain, original = humanize(text)
    tint = green if ok else red
    took = _STREAM.elapsed()
    _STREAM.note(
        tint("✓") if ok else tint("✗"),
        _sep([tint(plain), dim(original), dim(f"after {took}" if took else "")]),
    )


def banner(rows: list[tuple[str, str]], title: str, subtitle: str) -> None:
    """Startup identity block. One per process, before the first tick."""
    _STREAM.write()
    _STREAM.write(f"{_INDENT}{bold(_n(title))}{dim('  ' + _n(subtitle))}")
    _STREAM.write(dim(_INDENT + "─" * _RULE_WIDTH))
    for label, value in rows:
        _STREAM.write(f"{_INDENT}{dim(label.ljust(_LABEL_WIDTH))}{value}")
    _STREAM.write()
