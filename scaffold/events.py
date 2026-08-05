"""Validator event streams: stable JSONL plus an ergonomic TTY line.

Field-compatible with ``cathedral.events`` in the cathedralconfidential repo
(one emitter, two views), but dependency-light: a thin-only validator install
must not need the provenance extra to produce structured logs.

Every event carries a UTC timestamp, a stable UPPER_SNAKE event code, a
stage, the emitting validator mode, a PASS/FAIL/NOT_PROVEN/INFO status, and
optionally: miner hotkey, duration, an evidence/artifact reference, and
remediation guidance. Credential-shaped values are redacted defensively.

Watch commands (documented in VALIDATOR.md):

    journalctl -fu cathedral-validator -o cat        # TTY view
    tail -f ~/.cathedral/validator-events.jsonl | jq  # JSONL view
"""

from __future__ import annotations

import grp
import json
import math
import os
import re
import sys
from datetime import UTC, datetime
from collections.abc import Mapping
from typing import IO, Any

PASS = "PASS"
FAIL = "FAIL"
NOT_PROVEN = "NOT_PROVEN"
INFO = "INFO"
_STATUSES = (PASS, FAIL, NOT_PROVEN, INFO)

_EVENT_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
# Full credential grammar: key=value / key: value forms AND scheme-prefixed
# header values ("Authorization: Bearer <secret>", "Basic <secret>").
# Full credential grammar: bare and QUOTED values (single/double quotes,
# JSON-serialized and Python-repr forms, values containing spaces),
# scheme-prefixed opaque header values, and URL-safe tokens.
_SECRET_RE = re.compile(
    r"(?i)([\"']?)(bearer|basic|token|secret|hmac|api_key|authorization|"
    r"password|private_key)\1((\s*[=:]\s*)|\s+)"
    r"(?:(?:bearer|basic)\s+)?"
    r"(\"[^\"]*\"|'[^']*'|\S+)"
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)^(authorization|.*(token|secret|password|credential|api_key|"
    r"private_key|hmac).*)$"
)

_COLORS = {
    PASS: "\x1b[32m",
    FAIL: "\x1b[31;1m",
    NOT_PROVEN: "\x1b[33m",
    INFO: "\x1b[2m",
}
_RESET = "\x1b[0m"


def _now_iso() -> str:
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


_PATH_RE = re.compile(
    r"(?:file |path )?"
    r"(?:(?<![A-Za-z0-9:/])/(?!/)|~[A-Za-z0-9_-]*(?:/|\\)|"
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/])"
    r"[^\s'\"]*"
)
# Greedy through the FINAL `@` in the authority. A malformed raw password may
# itself contain `@`; stopping at the first one would leak the credential
# suffix as a fake hostname in the public event stream.
_URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s]+@")
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s]+")
# If a malformed URL contains authority credentials, query, or fragment and
# then whitespace, token boundaries are no longer trustworthy. Redact the
# remainder of that line rather than leaking a whitespace-separated suffix.
_SENSITIVE_URL_LINE_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\r\n'\"]*[@?#][^\r\n'\"]*"
)


def _scrub_url(match: re.Match[str]) -> str:
    """Keep a URL useful for diagnosis without retaining credentials.

    Query strings and fragments are removed wholesale rather than trying to
    enumerate every signed-URL vocabulary (``apikey``, ``sig``, ``X-Amz-*``,
    and vendor-specific variants). Userinfo is greedy through the final ``@``
    so malformed passwords cannot leak a suffix as a fake hostname.
    """
    raw = match.group(0)
    base = raw.split("#", 1)[0].split("?", 1)[0]
    return _URL_USERINFO_RE.sub(r"\1[REDACTED]@", base)


def _neutralize(value: str) -> str:
    """Strip ANSI/control characters, redact secrets and absolute
    filesystem paths/usernames, bound the length."""
    cleaned = _CONTROL_RE.sub(" ", value)
    cleaned = _SENSITIVE_URL_LINE_RE.sub("<redacted-url>", cleaned)
    cleaned = _URL_RE.sub(_scrub_url, cleaned)
    cleaned = _SECRET_RE.sub(
        lambda match: (match.group(2) or "credential") + "=[REDACTED]", cleaned
    )
    cleaned = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", cleaned)
    cleaned = _PATH_RE.sub("<path>", cleaned)
    return cleaned[:2048]


def stable_error(exc: BaseException) -> str:
    """A stable, redacted error code for output surfaces: OS errors become
    errno codes (no paths, no usernames), everything else keeps its type
    name with a neutralized message."""
    if isinstance(exc, OSError) and exc.errno is not None:
        import errno as errno_module

        code = errno_module.errorcode.get(exc.errno, str(exc.errno))
        return f"OSError[{code}]"
    return f"{type(exc).__name__}: {_neutralize(str(exc))}"[:200]


def _scrub(value):
    """Recursive scrub of every string in nested dict/list payloads."""
    if isinstance(value, str):
        return _neutralize(value)
    if isinstance(value, dict):
        # Sensitive FIELD NAMES redact the entire value regardless of shape.
        return {
            _neutralize(str(key)): (
                "[REDACTED]" if _SENSITIVE_FIELD_RE.match(str(key)) else _scrub(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return "[NON_FINITE]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _neutralize(str(value))


def _redact(value: str) -> str:
    return _neutralize(value)


# The sanitized status stream carries operational shape only. It is a strict
# allowlist rather than a denylist because the raw record accepts arbitrary
# **fields from callers: a denylist would leak every field nobody thought to
# name. `hotkey` is deliberately absent, as are all caller-supplied extras,
# so receipts, evidence payloads, credentials and private provenance cannot
# reach a group-readable file no matter what an emitter passes.
STATUS_FIELDS = (
    "ts",
    "event",
    "stage",
    "mode",
    "status",
    "duration_ms",
    "artifact",
    "detail",
    "remediation",
)


# One `statvfs` at startup. Large enough that the warning lands while an
# operator can still act on it, small enough that a normally provisioned host
# never sees it.
JOURNAL_LOW_SPACE_BYTES = 8 * 1024 * 1024


def _stderr_line(message: str) -> None:
    """Report on stderr, which under systemd IS journald.

    Once the journal file cannot be written, this is the operator's only
    remaining signal, so it must never raise: a failure here would reintroduce
    exactly the crash the caller is degrading away from.
    """
    stream = sys.stderr
    if stream is None:  # pragma: no cover - stderr detached
        return
    try:
        stream.write(message + "\n")
        stream.flush()
    except OSError:
        # The last resort failed too. There is nowhere left to say so, and
        # raising would kill the loop over a logging failure.
        pass


def _warn_if_low_on_space(path: str, label: str) -> None:
    """Advisory startup warning; it may never fail the start.

    A validator that degrades to stderr at 03:00 crossed 90% full hours
    earlier with nobody watching. This costs one syscall on the startup path
    and prints at most one line.

    It is advisory ONLY. It gates nothing, and every error is swallowed:
    `statvfs` is missing on some platforms and fails on some mounts, and a
    warning that can refuse to start a validator is worse than no warning.
    Deciding whether a write may happen is the durable fences' job, never
    this function's.
    """
    try:
        free = os.statvfs(os.path.dirname(os.path.abspath(path)) or ".")
        available = free.f_bavail * free.f_frsize
    except (OSError, ValueError, AttributeError):
        return
    if available < JOURNAL_LOW_SPACE_BYTES:
        _stderr_line(
            f"warning: {label} {path} has {available // 1024} KiB free. "
            f"Journal writes degrade to stderr when the disk fills; clear "
            f"space before that is the only place events can go."
        )


class EventLogPathError(RuntimeError):
    """The journal path is unusable, and the message says how to fix it.

    Raised instead of letting a bare ``OSError`` escape. The journal is opened
    from the STARTUP event, before the first tick, so a bad path is the very
    first thing a new operator hits — and a raw ``FileNotFoundError`` deep in
    ``os.open`` names neither the setting that chose the path nor the command
    that repairs it. The CLI entry points turn this into a one-line
    ``error: …`` and exit 2, which systemd still sees as a failed start.
    """


def _prepare_journal_directory(path: str, label: str) -> None:
    """Create the journal's parent directory, or explain why we could not.

    Creating it is the right default: the directory holds nothing but the
    journal, the file's own owner/mode/symlink gates below are unchanged, and
    0700 keeps the parent at least as private as the 0600 file it will hold.
    A missing ``$HOME/.cathedral`` is an operator typo away from working and
    is not worth an error.

    Creating it is not sufficient, which is why the error path exists too: the
    shipped SN39 profiles log to ``/var/log/cathedral-validator``, which the
    service install owns and no ordinary user can create. There the honest
    answer is a message naming the directory and both fixes, not a traceback.
    """
    directory = os.path.dirname(os.path.abspath(path))
    if not directory:  # pragma: no cover - abspath always yields a parent
        return
    try:
        # Not os.makedirs(mode=...): that applies the mode to the LEAF only and
        # leaves every intermediate directory it invented at 0777 & ~umask.
        # Directories we create for a private journal are all created private.
        missing: list[str] = []
        walk = directory
        while not os.path.isdir(walk):
            missing.append(walk)
            parent = os.path.dirname(walk)
            if parent == walk:  # pragma: no cover - reached the filesystem root
                break
            walk = parent
        for component in reversed(missing):
            try:
                os.mkdir(component, 0o700)
            except FileExistsError:
                # Another process got there first; an existing directory is
                # exactly what we wanted and its mode is not ours to restat.
                if not os.path.isdir(component):
                    raise
    except OSError as exc:
        raise EventLogPathError(
            f"{label} directory {directory} does not exist and could not be "
            f"created ({exc.strerror}). Either create it for this user "
            f'(`sudo install -d -o "$USER" -m 0700 {directory}`), or point the '
            f"journal at a directory you already own, e.g. "
            f'`--jsonl "$HOME/.cathedral/validator-events.jsonl"`.'
        ) from exc


def _open_secure_append(path: str, group: str | None, label: str) -> IO[str]:
    """Append-only open that refuses symlinks and non-owner files.

    Creates 0600. A reader group is permitted only when the service pins one
    explicitly, and then the mode is forced to exactly 0640. Callers that pass
    no group get a strictly private file.
    """
    import stat as _stat

    group_gid = grp.getgrnam(group).gr_gid if group is not None else None
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    _prepare_journal_directory(path, label)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise EventLogPathError(
            f"{label} {path} could not be opened ({exc.strerror}). Check that "
            f"this user owns the path and that it is a regular file, not a "
            f"symlink; or point the journal at a directory you own, e.g. "
            f'`--jsonl "$HOME/.cathedral/validator-events.jsonl"`.'
        ) from exc
    try:
        opened = os.fstat(descriptor)
        opened_mode = _stat.S_IMODE(opened.st_mode)
        if (
            not _stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened_mode & 0o007
            or opened_mode not in (0o600, 0o640)
        ):
            raise ValueError(f"{label} must be an owner-controlled regular file")
        if group_gid is None:
            if opened_mode & 0o070:
                raise ValueError(
                    f"{label} must be private (0600) without a reader group"
                )
        else:
            os.fchown(descriptor, -1, group_gid)
            os.fchmod(descriptor, 0o640)
            secured = os.fstat(descriptor)
            if secured.st_gid != group_gid or _stat.S_IMODE(secured.st_mode) != 0o640:
                raise ValueError(f"{label} reader-group setup failed")
    except BaseException:
        os.close(descriptor)
        raise
    return os.fdopen(descriptor, "a", encoding="utf-8")


def sanitized_status_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Project one raw event onto the operational allowlist.

    The raw journal stays private (0600, no reader group). This projection is
    what a separate status publisher is permitted to read, so it must never
    widen with the raw schema.
    """
    return {key: record[key] for key in STATUS_FIELDS if key in record}


class EventLogger:
    def __init__(
        self,
        *,
        mode: str,
        jsonl: IO[str] | None = None,
        jsonl_path: str | None = None,
        jsonl_group: str | None = None,
        status_path: str | None = None,
        status_group: str | None = None,
        tty: IO[str] | None = None,
        color: bool | None = None,
    ) -> None:
        self.mode = _neutralize(mode)[:32]
        self._jsonl = jsonl
        self._jsonl_file: IO[str] | None = None
        self._status_file: IO[str] | None = None
        if jsonl_path:
            self._jsonl_file = _open_secure_append(jsonl_path, jsonl_group, "event log")
        if status_path:
            # The sanitized stream is the ONLY surface a reader group may see.
            # It is projected through STATUS_FIELDS, so granting it a group is
            # safe in a way granting one to the raw journal is not.
            self._status_file = _open_secure_append(
                status_path, status_group, "status log"
            )
        # After the opens, so a genuinely broken path still reports its own
        # error first. Deduplicated by directory: both streams normally share
        # one filesystem and one warning is the useful number.
        warned: set[str] = set()
        for candidate, candidate_label in (
            (jsonl_path, "event log"),
            (status_path, "status log"),
        ):
            if not candidate:
                continue
            directory = os.path.dirname(os.path.abspath(candidate))
            if directory in warned:
                continue
            warned.add(directory)
            _warn_if_low_on_space(candidate, candidate_label)
        self._tty = tty if tty is not None else sys.stdout
        if color is None:
            color = (
                hasattr(self._tty, "isatty")
                and self._tty.isatty()
                and not os.environ.get("NO_COLOR")
            )
        self._color = bool(color)
        self._is_tty = bool(hasattr(self._tty, "isatty") and self._tty.isatty())

    def close(self) -> None:
        if self._jsonl_file is not None:
            self._jsonl_file.close()
            self._jsonl_file = None
        if self._status_file is not None:
            self._status_file.close()
            self._status_file = None

    def event(
        self,
        code: str,
        *,
        stage: str,
        status: str = INFO,
        hotkey: str | None = None,
        duration_ms: float | None = None,
        artifact: str | None = None,
        remediation: str | None = None,
        detail: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        if _EVENT_CODE_RE.fullmatch(code) is None:
            raise ValueError(f"unstable event code {code!r}")
        if status not in _STATUSES:
            raise ValueError(f"unknown status {status!r}")
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "event": code,
            "stage": _neutralize(stage)[:32],
            "mode": self.mode,
            "status": status,
        }
        if hotkey is not None:
            record["hotkey"] = _neutralize(hotkey)
        if duration_ms is not None:
            parsed_duration = float(duration_ms)
            if math.isfinite(parsed_duration):
                record["duration_ms"] = round(parsed_duration, 3)
        if artifact is not None:
            record["artifact"] = _redact(str(artifact))
        if detail is not None:
            record["detail"] = _redact(str(detail))
        if remediation is not None:
            record["remediation"] = _redact(str(remediation))
        for key, value in fields.items():
            if key not in record:
                record[key] = _scrub(value)
        # Serialization stays OUTSIDE the guard below: a record that cannot be
        # encoded is a defect in what we are asking the journal to record, and
        # it must still raise.
        line = json.dumps(record, separators=(",", ":"), allow_nan=False)
        for target in (self._jsonl, self._jsonl_file):
            if target is not None:
                self._append(target, line, "journal")
        if self._status_file is not None:
            status_line = json.dumps(
                sanitized_status_record(record), separators=(",", ":"), allow_nan=False
            )
            self._append(self._status_file, status_line, "status log")
        self._write_tty(record)
        return record

    def _append(self, target: IO[str], line: str, label: str) -> bool:
        """Append one line, degrading to stderr instead of killing the caller.

        A full disk used to take the validator down rather than degrade it.
        `TICK_FAILED` is emitted from the tick loop's own generic handler, so
        an `OSError` raised while writing it unwinds past BOTH `while True`
        loops in `run()` and the process dies on a raw traceback — losing the
        operator the one event that explains the outage. Degrading here means
        the NEXT tick's `TICK_FAILED` still reaches journald.

        Only `OSError` is caught, and only around the write. A full disk, a
        read-only remount, a revoked descriptor: none of them say anything
        about whether the tick's own work was sound. Everything else still
        propagates, because a broad `except Exception` around a durable write
        is how the head-drift bug hid for weeks — a `TypeError` from an
        unserializable field or a `ValueError` from a malformed record is a
        defect in this code, and swallowing it would leave the journal quietly
        dropping events with a healthy-looking process on top.

        Degrading the journal changes NOTHING about whether a tick's work was
        SOUND. No status is rewritten, no caller is told the write landed, and
        the return value below is advisory: `event()` is telemetry, and no
        decision about writing weights reads it. The fences that decide that
        are in the state file, which stays fatal on the same ENOSPC — see
        `_replace_private_state` in `validator_thin`.

        It does change what a full disk DOES, and the shipped configs make that
        reachable. `state_file` is under `/var/lib/cathedral-validator` and
        `jsonl` under `/var/log/cathedral-validator` — separate ReadWritePaths,
        commonly separate filesystems. Same filesystem: the state write hits
        ENOSPC too, and the tick still refuses. **Only `/var/log` full: the
        tick that previously died at its first `event()` now runs to
        completion and can broadcast, with no journal record of having done
        so.**

        That is the deliberate trade and it is not free. Replay protection is
        unaffected (the fences are durable, on the other filesystem), so this
        costs observability, not safety — and losing a whole emission cycle to
        a full LOG disk is the worse outcome. The exposure is bounded by the
        liveness alert: a frozen journal trips `cathedral-mismatch-check`'s
        staleness rule at three tick intervals, so a blind validator is
        reported rather than silently tolerated. `cathedral-mismatch-alert`
        becomes load-bearing here in a way it was not before.
        """
        try:
            target.write(line + "\n")
            target.flush()
        except OSError as exc:
            _stderr_line(f"{label} write failed: {stable_error(exc)}")
            return False
        return True

    def _write_tty(self, record: dict[str, Any]) -> None:
        if self._tty is None or not self._is_tty:
            return
        status = record["status"]
        badge = f"{status:<10}"
        if self._color:
            badge = _COLORS[status] + badge + _RESET
        clock = record["ts"][11:23]
        parts = [f"{clock} {badge} {record['event']:<28} [{record['mode']}]"]
        if "hotkey" in record:
            hotkey = record["hotkey"]
            parts.append(
                hotkey if len(hotkey) <= 12 else f"{hotkey[:6]}..{hotkey[-4:]}"
            )
        if "duration_ms" in record:
            parts.append(f"{record['duration_ms']:.0f}ms")
        if "detail" in record:
            parts.append(str(record["detail"]))
        if "artifact" in record:
            parts.append(f"ref={record['artifact']}")
        line = "  ".join(parts)
        if record.get("remediation"):
            line += f"\n{'':>13}↳ {record['remediation']}"
        self._tty.write(line + "\n")
        self._tty.flush()
