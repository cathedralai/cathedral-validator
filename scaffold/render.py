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
import shutil
import sys
import time
from typing import Any

from .events import _neutralize

# Finney block time. Only used to render block deltas as human durations; no
# decision anywhere depends on it, so an occasional drifting block is harmless.
_SECS_PER_BLOCK = 12

_LABEL_WIDTH = 11  # one wider than the longest label ("provenance")
_INDENT = "   "


def _rule_width() -> int:
    """Pane width to lay out against; a garbage COLUMNS must not be fatal."""
    try:
        columns = int(os.environ.get("COLUMNS") or 0)
    except ValueError:
        columns = 0
    if not columns:
        columns = shutil.get_terminal_size(fallback=(100, 24)).columns
    return max(60, min(120, columns) - len(_INDENT))


_RULE_WIDTH = _rule_width()


def _color_enabled() -> bool:
    """Colour a real terminal, or anything that asks for it.

    A systemd service writes to the journal, not a tty, so isatty() alone
    leaves production output permanently monochrome even though journalctl
    renders ANSI perfectly well. FORCE_COLOR exists for exactly that case.
    NO_COLOR still wins over everything, per the convention.
    """
    if os.environ.get("NO_COLOR") or os.environ.get("CATHEDRAL_VALIDATOR_NO_COLOR"):
        return False
    if os.environ.get("CATHEDRAL_VALIDATOR_FORCE_COLOR"):
        return True
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


def _percent(share: Any) -> str:
    """A 0..1 share as a percentage; anything unparseable renders as itself."""
    try:
        return f"{float(share) * 100:.1f}%"
    except (TypeError, ValueError):
        return _n(share)


# A value is everything up to the next space, EXCEPT when it opens a delimiter
# the writer clearly meant to hold spaces. Call sites interpolate Python
# containers and reprs (``wire_uids=[0, 1]``, ``error='not pinned; refusing'``),
# and a tokenizer that stops at the first interior space splits those in half:
# the head becomes a truncated value and the tail becomes leftover.
# The bracket alternative excludes ``=`` so an UNBALANCED opener cannot swallow
# the keys that follow it. ``burn_uid=[204 vector=163:0.9,204:0.1]`` must still
# yield two keys, not one giant value: a malformed detail should lose its own
# field, never the well-formed fields after it. A list that genuinely contains
# ``=`` falls through to ``\S+`` and truncates at the first space, which is the
# pre-existing behaviour and is strictly better than losing a neighbour.
_KV = re.compile(r"""(\w+)=("[^"]*"|'[^']*'|\[[^\]=]*\]|\S+)""")


def _unquote(value: str) -> str:
    """Drop one matched pair of surrounding quotes, and only a matched pair."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_detail(detail: str) -> tuple[dict[str, str], str]:
    """Split ``k=v k=v free text`` into a mapping plus whatever was not a pair.

    The lifecycle call sites were written for a flat key=value line, so this
    keeps them working untouched while the renderer gets structured input.

    Leftover is prose the writer meant to be read, never the debris of a value
    this parser failed to tokenize. Widening ``_KV`` above keeps that promise
    for the shapes call sites actually emit, but a renderer must not assume it:
    the only safe thing to print is a field it can name.
    """
    kv = {m.group(1): _unquote(m.group(2)) for m in _KV.finditer(detail or "")}
    leftover = _KV.sub("", detail or "").strip()
    return kv, leftover


_ANSI = re.compile(r"\033\[[0-9;]*m")


def _visible(text: str) -> int:
    """Width as a person sees it. Colour codes occupy no columns."""
    return len(_ANSI.sub("", text))


def _atomic(part: str) -> bool:
    """True for a part that must never be split across lines.

    A hash, hotkey, digest or URL is only useful if it can be copied whole, so
    those overflow rather than break. Anything with spaces is prose and wraps.
    """
    return " " not in _ANSI.sub("", part).strip()


def _wrap(parts: list[str], first: str, cont: str, width: int) -> list[str]:
    """Lay parts out across as many lines as they need.

    Breaking prefers separator boundaries so related fields stay together. A
    single part too wide for the budget is word-wrapped unless it is atomic, in
    which case it overflows: splitting an identifier to make a column line up
    would be the wrong trade.
    """
    sep = " · "
    lines: list[str] = []
    prefix, budget = first, width - _visible(first)
    current: list[str] = []
    used = 0
    expanded: list[str] = []
    for part in [p for p in parts if p and p.strip()]:
        if _visible(part) <= width - _visible(cont) or _atomic(part):
            expanded.append(part)
            continue
        # Too wide and not atomic: split it into word-sized pieces that the
        # packing loop below can lay out normally.
        import textwrap

        expanded.extend(textwrap.wrap(part, width=max(20, width - _visible(cont))))
    for part in expanded:
        need = _visible(part) + (len(sep) if current else 0)
        if current and used + need > budget:
            lines.append(prefix + dim(sep).join(current))
            prefix, budget = cont, width - _visible(cont)
            current, used = [part], _visible(part)
            continue
        current.append(part)
        used += need
    if current:
        lines.append(prefix + dim(sep).join(current))
    return lines or [first]


class _Stream:
    """Rendering state for one process: tick framing and the pending feed row."""

    def __init__(self) -> None:
        self.feed_bits: list[str] = []
        self.feed_open = False
        self.in_tick = False
        self.rows_since_rule = 0
        self.last_stamp = ""
        self.seen_rows: dict[str, str] = {}
        self.tick_started: float | None = None

    def elapsed(self) -> str:
        if self.tick_started is None:
            return ""
        return _duration(time.monotonic() - self.tick_started)

    # -- primitives ---------------------------------------------------------

    def write(self, text: str = "") -> None:
        print(text)

    def row(self, label: str, text: str, *, once: bool = False) -> None:
        # Anything emitted outside a tick (startup preflight, receipt recovery)
        # opens its own block, so a row is never orphaned above the first rule.
        if not self.in_tick:
            self.rule("")
        parts = text if isinstance(text, list) else [text]
        if not [p for p in parts if p and p.strip()]:
            return
        # Chain preflight runs more than once per tick. An IDENTICAL second
        # reading is a refresh, not news -- but a reading that changed (a
        # different block, a different safety count) is exactly news, so
        # dedupe on content, not on the label alone.
        rendered = "\x00".join(parts)
        if once and self.seen_rows.get(label) == rendered:
            return
        self.seen_rows[label] = rendered
        self.flush_feed(unless=label)
        first = f"{_INDENT}{dim(label.ljust(_LABEL_WIDTH))}"
        cont = f"{_INDENT}{' ' * _LABEL_WIDTH}"
        for line in _wrap(
            text if isinstance(text, list) else [text],
            first,
            cont,
            _RULE_WIDTH + len(_INDENT),
        ):
            self.write(line)
        self.rows_since_rule += 1

    def note(self, symbol: str, text: str) -> None:
        if not self.in_tick:
            self.rule("")
        self.flush_feed()
        first = f"{_INDENT}{symbol} "
        cont = f"{_INDENT}  "
        for line in _wrap(
            text if isinstance(text, list) else [text],
            first,
            cont,
            _RULE_WIDTH + len(_INDENT),
        ):
            self.write(line)
        self.rows_since_rule += 1

    def rule(self, stamp: str = "") -> None:
        # Rows emitted outside a tick carry no event timestamp of their own, so
        # the block is stamped with the wall clock instead of rendering blank.
        stamp = stamp or datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S")
        # An empty block helps nobody. A tick that failed before emitting
        # anything leaves its rule open, and the next tick reuses it rather
        # than drawing a second identical divider under the first.
        if self.in_tick and self.rows_since_rule == 0:
            self.tick_started = time.monotonic()
            self.seen_rows = {}
            self.last_stamp = stamp
            return
        # A head-drift retry rebuilds the whole tick, so it re-enters here
        # within the same second. Those are attempts at one submission, not
        # separate ticks, and drawing a fresh identical divider for each made
        # the stream look like it was repeating itself.
        if self.in_tick and stamp == self.last_stamp:
            # seen_rows deliberately NOT reset: a retry is the same tick, and
            # content-aware dedupe already lets a changed reading through.
            return
        self.flush_feed()
        if self.in_tick:
            self.write()
        head = f"── {stamp} "
        self.write(dim(_INDENT + head + "─" * max(0, _RULE_WIDTH - len(head))))
        self.in_tick = True
        self.rows_since_rule = 0
        self.seen_rows = {}
        self.last_stamp = stamp
        self.tick_started = time.monotonic()

    # -- the one accumulated row -------------------------------------------

    def feed(self, fragment: str) -> None:
        self.feed_bits.append(fragment)
        self.feed_open = True

    def flush_feed(self, unless: str | None = None) -> None:
        if not self.feed_open or unless == "feed":
            return
        bits, self.feed_bits, self.feed_open = self.feed_bits, [], False
        first = f"{_INDENT}{dim('feed'.ljust(_LABEL_WIDTH))}"
        cont = f"{_INDENT}{' ' * _LABEL_WIDTH}"
        for line in _wrap(bits, first, cont, _RULE_WIDTH + len(_INDENT)):
            self.write(line)


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
    s.row("vector", parts or ["accepted"])


def _r_vector_rejected(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    stage = kv.get("stage", "")
    reason = kv.get("reason", "") or rest
    s.note(red("✗"), [red("vector rejected"), _n(stage), _n(reason)])


def _r_vector_idle(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("vector", dim(_n(rest) or "nothing to act on"))


def _r_verify_failed(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.note(red("✗"), [red("verification failed"), _n(kv.get("reason", ""))])


def _r_feed_unavailable(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.flush_feed()
    switching = kv.get("switching_to")
    s.row(
        "feed",
        [
            yellow("unavailable"),
            _n(kv.get("reason", "")),
            yellow("switching to full permanently")
            if switching
            else dim("continuing on independent evidence"),
        ],
    )


def _r_feed_invalid(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.flush_feed()
    s.row("feed", [red("invalid"), _n(kv.get("reason", ""))])


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
    s.row("chain", parts, once=True)


def _r_map_complete(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    burn_uid = kv.get("burn_uid")
    vector = kv.get("vector", "")
    entries = []
    for pair in vector.split(","):
        if ":" not in pair:
            continue
        uid, _, weight = pair.partition(":")
        pct = _percent(weight)
        tag = dim("burn") if uid == burn_uid else ""
        entries.append(f"{cyan(_n(uid))} {bold(pct)}{(' ' + tag) if tag else ''}")
    s.row("weights", entries or [dim("none")])


def _r_map_offline(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("weights", dim("offline · synthetic uid map, no chain access"))


def _r_dry_run(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    """The last line of the first command a new operator ever runs.

    It is assembled from named fields only. The detail carries Python list
    reprs (``wire_uids=[0, 1] wire_weights=[58982, 7282]``), and echoing the
    unparsed remainder printed their tails -- ``1]  7282]`` -- as the closing
    words of the quickstart. ``leftover`` is deliberately unused here: any
    detail whose fields this row cannot name is debris, and the wire encoding
    it came from is in the journal for anyone who needs it.

    The only field it names is the uid count. The two "WEIGHTS dry-run" emit
    sites in ``validator_thin`` write ``uids= wire_uids= wire_weights= vector=``
    -- no ``burn_uid``, ``burn_share`` or ``vector_id``, so branches keyed on
    those would be unreachable code that reads as coverage. ``vector`` is not
    rendered either: the ``weights`` row immediately above already prints the
    same allocation as percentages, and running the preview through ``_short``
    truncates it mid-number (``0=0.9000,1....1000``), which is less legible
    than the line it duplicates.
    """
    parts = []
    count = kv.get("uids")
    if count:
        parts.append(f"{_n(count)} uid{'' if count == '1' else 's'}")
    s.note(dim("·"), [dim(p) for p in ["dry run, nothing written", *parts]])


def _r_chain_submitted(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    final = str(kv.get("finalized", "")).lower() == "true"
    s.row(
        "submit",
        [
            _short(kv.get("extrinsic_hash", "")),
            f"block {bold(_n(kv.get('block_number', '')))}",
            green("finalized") if final else yellow("included"),
        ],
    )
    took = s.elapsed()
    s.note(green("✓"), [green("weights written"), dim(f"in {took}" if took else "")])


def _r_chain_problem(label: str):
    def render(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
        parts = [
            _n(kv.get("reason", "")),
            _short(kv.get("attempt_id", "")) if kv.get("attempt_id") else "",
            # The exact transaction being recovered or expired is the fact an
            # operator has to correlate against the chain; never drop it.
            _short(kv.get("extrinsic_hash", "")) if kv.get("extrinsic_hash") else "",
            f"block {_n(kv['block_number'])}" if kv.get("block_number") else "",
            _n(kv.get("included", "")) and f"included={_n(kv['included'])}",
        ]
        s.note(yellow("⚠"), [yellow(label)] + parts)

    return render


def _r_provenance(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    s.row("evidence", [_n(rest), _n(kv.get("reason", ""))])


def _r_provenance_mismatch(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    # A recomputation that disagrees with the signed vector is the single most
    # important thing this stream can ever say. It was landing in the generic
    # renderer with every field consumed as key=value, leaving an empty row
    # that the empty-parts guard then suppressed entirely.
    s.note(
        red("✗"),
        [red("independent recomputation DISAGREES with the signed vector")]
        + [f"{key}={value}" for key, value in kv.items()],
    )


def _r_provenance_not_proven(
    s: _Stream, kv: dict[str, str], rest: str, ts: str
) -> None:
    # Named explicitly rather than left to the fallback: the fallback derives a
    # label from the first word, which for "PROVENANCE not proven" collided
    # with the label column and dumped the whole detail as one unbreakable run.
    message = kv.get("error") or kv.get("reason") or kv.get("detail") or rest
    s.row("evidence", [yellow("not proven"), _n(message)])


def _r_startup_fact(s: _Stream, kv: dict[str, str], rest: str, ts: str) -> None:
    """Duplicates the banner when there is one, but a caller that skips the
    banner (direct run(), tests, embedding) still gets the facts."""
    s.row("startup", [dim(_n(rest))] + [dim(f"{k}={_n(v)}") for k, v in kv.items()])


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
    "PROVENANCE not proven": _r_provenance_not_proven,
    "PROVENANCE mismatch": _r_provenance_mismatch,
    "AUTHORITY provenance": _r_provenance,
    "LAUNCH rewarded-set gate": _r_provenance,
    "PIN active": _r_startup_fact,
    "MODE active": _r_startup_fact,
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
        # Two spellings of one refusal. The second is the wording since the
        # epoch-room gate was split into its six distinct causes; the first is
        # the collapsed sentence it replaced, kept so older journals still read
        # in plain English. Only the "too few blocks left" cause matches: the
        # sibling refusals ("cannot prove the blocks remaining in this epoch",
        # "composed against a different epoch") are not boundary timing and
        # must not borrow a reading that says they clear themselves.
        r"remain in this epoch|cannot prove the exact next epoch",
        "too close to the epoch boundary to land safely",
    ),
    (
        r"continuous broadcast is locked until",
        "not writing at all until `cathedral-validator reconcile-launch` is run",
    ),
    (
        r"attempt fence refused before chain write",
        "the local attempt journal would not reserve; nothing was sent",
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
        [tint(plain), dim(f"in {took}") if took else ""],
    )
    # The exact message stays available, but one indent down and dimmed, so the
    # headline is what the eye lands on.
    if original:
        import textwrap

        body = _INDENT + "  "
        for line in textwrap.wrap(
            original,
            width=max(40, _RULE_WIDTH - 2),
            initial_indent="",
            subsequent_indent="",
        ):
            _STREAM.write(body + dim(line))


def banner(rows: list[tuple[str, list[str] | str]], title: str, subtitle: str) -> None:
    """Startup identity block. One per process, before the first tick."""
    _STREAM.write()
    _STREAM.write(f"{_INDENT}{bold(_n(title))}{dim('  ' + _n(subtitle))}")
    _STREAM.write(dim(_INDENT + "─" * _RULE_WIDTH))
    for label, value in rows:
        first = f"{_INDENT}{dim(label.ljust(_LABEL_WIDTH))}"
        cont = f"{_INDENT}{' ' * _LABEL_WIDTH}"
        parts = value if isinstance(value, list) else [value]
        for line in _wrap(parts, first, cont, _RULE_WIDTH + len(_INDENT)):
            _STREAM.write(line)
    _STREAM.write()
