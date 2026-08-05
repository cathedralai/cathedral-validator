"""A full disk must degrade the validator, not kill it.

Reproduced on a real 96K tmpfs before any of this was written: the journal was
opened while there was still room, the filesystem then filled, and the ninth
tick crossed the journal's last allocated page. The failure shape was exactly
this, and it is the reason these tests exist:

    ✗ tick failed: OSError[ENOSPC]          <- the handler classified it right
    Traceback (most recent call last):
      File ".../validator_thin.py", line 10516, in run
        _get_events(args).event(
      File ".../scaffold/events.py", line 382, in event
        target.flush()
    OSError: [Errno 28] No space left on device

`TICK_FAILED` is emitted from the tick loop's own generic handler, so the
`OSError` raised while writing it unwound past BOTH `while True` loops in
`run()` and the process died on a raw traceback, exit 1. The operator loses the
one event that explains the outage at the exact moment they need it.

What must NOT change while fixing that:

* A refusal stays a refusal. Degrading the JOURNAL may never turn a tick that
  refused to write weights into one that submitted, so the tick outcome and
  exit code are asserted alongside every degradation below.
* The STATE file stays fatal. It carries the monotonic fences and the
  anti-rollback watermark; swallowing a failed state write would leave the
  fence pointing at an older attempt while the process believed it advanced.
  A crash is strictly better, and the last two tests pin that asymmetry.
* Only `OSError` is swallowed. A broad `except Exception` around a durable
  write is how the head-drift bug hid for weeks.
"""

from __future__ import annotations

import errno
import io
import os
from types import SimpleNamespace

import pytest

from scaffold import events as events_module
from scaffold import validator_thin as vt
from scaffold.events import EventLogger


class _FullDisk(io.StringIO):
    """A journal on a filesystem with no space left.

    Raises the genuine kernel errno the tmpfs reproduction produced, from both
    `write` and `flush` — the real crash came out of `flush()`, because the
    buffered writer only reaches the disk when a page boundary is crossed.
    """

    def __init__(self) -> None:
        super().__init__()
        self.space_returned = False
        self.landed: list[str] = []

    def _refuse(self) -> None:
        if not self.space_returned:
            raise OSError(errno.ENOSPC, "No space left on device")

    def write(self, text: str) -> int:  # type: ignore[override]
        self._refuse()
        self.landed.append(text)
        return len(text)

    def flush(self) -> None:  # type: ignore[override]
        self._refuse()


def _logger(journal) -> EventLogger:
    return EventLogger(mode="thin", jsonl=journal, tty=io.StringIO(), color=False)


def _run_args(tmp_path, journal, **overrides) -> SimpleNamespace:
    args = SimpleNamespace(
        broadcast=True,
        offline=False,
        once=True,
        interval_secs=0,
        network="finney",
        netuid=39,
        wallet_name="validator",
        wallet_hotkey="default",
        publisher_url="https://api.cathedral.computer",
        public_key_hex="ab" * 32,
        key_id="k1",
        require_policy="validated_supply_v3",
        provenance="shadow",
        max_submissions=1,
        state_file=str(tmp_path / "state.json"),
        runtime_root=str(tmp_path),
        _events=_logger(journal),
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def _quiet_loop(monkeypatch) -> None:
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _args: None)
    monkeypatch.setattr(vt, "_recover_pending_launch_receipt", lambda _args: None)
    monkeypatch.setattr(vt, "_drain_shadow_audit_once", lambda _args: True)


# ---------------------------------------------------------------------------
# The crash itself
# ---------------------------------------------------------------------------


def test_a_journal_write_that_hits_enospc_does_not_escape_the_event_call():
    """The narrowest statement of the bug: `event()` used to raise."""
    logger = _logger(_FullDisk())

    record = logger.event("TICK_FAILED", stage="result", status=events_module.FAIL)

    assert record["event"] == "TICK_FAILED"
    assert record["status"] == events_module.FAIL, (
        "the record itself is unchanged; only its delivery degraded"
    )


def test_a_full_disk_no_longer_kills_the_tick_loop(monkeypatch, tmp_path, capsys):
    """The reported crash, at the loop level: it escaped both `while True`s."""
    _quiet_loop(monkeypatch)
    journal = _FullDisk()
    args = _run_args(tmp_path, journal)
    monkeypatch.setattr(
        vt,
        "tick",
        lambda _args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "No space left")),
    )

    exit_code = vt.run(args)

    assert exit_code == 1, "a tick that failed still fails; only the journal degraded"
    assert "journal write failed: OSError[ENOSPC]" in capsys.readouterr().err


def test_the_loop_keeps_ticking_so_the_next_tick_failed_can_still_land(
    monkeypatch, tmp_path
):
    """The whole point of degrading: the NEXT tick still reaches journald.

    A single surviving tick would be worth little. What the operator needs is
    for the loop to still be running when the disk is cleared, so the next
    `TICK_FAILED` is delivered normally.
    """
    _quiet_loop(monkeypatch)
    journal = _FullDisk()
    args = _run_args(tmp_path, journal, once=False)
    ticks = {"n": 0}

    class _Stop(BaseException):
        """Ends the loop from outside the generic handler's reach."""

    def _tick(_args):
        ticks["n"] += 1
        if ticks["n"] == 3:
            journal.space_returned = True  # the operator cleared the disk
        if ticks["n"] > 3:
            raise _Stop()
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(vt, "tick", _tick)

    with pytest.raises(_Stop):
        vt.run(args)

    assert ticks["n"] == 4, "the loop survived two unwritable ticks and kept going"
    delivered = [line for line in journal.landed if "TICK_FAILED" in line]
    assert len(delivered) == 1, (
        "exactly the tick that ran after space returned reached the journal"
    )


def test_the_status_stream_degrades_without_taking_the_raw_journal_with_it(tmp_path):
    """Two streams, one disk. Neither may kill the caller."""
    raw = _FullDisk()
    status = _FullDisk()
    logger = EventLogger(mode="thin", jsonl=raw, tty=io.StringIO(), color=False)
    logger._status_file = status

    logger.event("TICK_FAILED", stage="result", status=events_module.FAIL)

    raw.space_returned = True
    logger.event("TICK_FAILED", stage="result", status=events_module.FAIL)
    assert len(raw.landed) == 1, "the raw journal recovered on its own"
    assert status.landed == [], "the status stream is still full, and still silent"


# ---------------------------------------------------------------------------
# What must still propagate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("writer is misconfigured, not full"),
        RuntimeError("the journal object is in a broken state"),
        AttributeError("the target is not a writer at all"),
    ],
)
def test_a_non_oserror_from_the_journal_still_kills_the_call(failure):
    """`except OSError`, never `except Exception`.

    A broken writer is a defect in this code, not a property of the disk.
    Swallowing it would leave the journal quietly dropping every event with a
    healthy-looking validator on top — the head-drift failure mode, which hid
    behind a broad `except Exception` around a durable write for weeks.
    """

    class _BrokenWriter(io.StringIO):
        def write(self, text: str) -> int:  # type: ignore[override]
            raise failure

    with pytest.raises(type(failure)):
        _logger(_BrokenWriter()).event("TICK_FAILED", stage="result")


def test_an_invalid_event_code_is_still_rejected_on_a_full_disk():
    """The record contract is validated before any write is attempted, so a
    full disk cannot become a way to smuggle an unstable code past it."""
    logger = _logger(_FullDisk())

    with pytest.raises(ValueError, match="unstable event code"):
        logger.event("tick_failed", stage="result")
    with pytest.raises(ValueError, match="unknown status"):
        logger.event("TICK_FAILED", stage="result", status="BROKEN")


# ---------------------------------------------------------------------------
# Degrading the journal must never turn a refusal into a submission
# ---------------------------------------------------------------------------


def test_a_dead_journal_does_not_turn_a_refused_tick_into_a_successful_one(
    monkeypatch, tmp_path
):
    """Every refusal the loop knows about, with the journal unwritable."""
    _quiet_loop(monkeypatch)
    refusals = (
        vt._ContinuousLaunchLocked("continuous writes are locked"),
        vt._SubmissionFenceRefused("attempt fence refused"),
        vt._EpochRoomUnavailable("too few blocks left in the epoch"),
        vt.wire.VectorError("thin dry run refused: policy pin is not satisfied"),
    )
    for refusal in refusals:
        args = _run_args(tmp_path, _FullDisk())
        monkeypatch.setattr(
            vt, "tick", lambda _args, exc=refusal: (_ for _ in ()).throw(exc)
        )

        assert vt.run(args) == 1, (
            f"{type(refusal).__name__} must still exit non-zero with a dead journal"
        )


def test_a_dead_journal_never_reaches_the_chain_write(monkeypatch, tmp_path):
    """The submission path is not entered at all when the tick refuses."""
    _quiet_loop(monkeypatch)
    calls: list[str] = []
    monkeypatch.setattr(
        vt,
        "set_weights_on_chain",
        lambda *a, **k: calls.append("submitted"),
    )
    monkeypatch.setattr(
        vt,
        "tick",
        lambda _args: (_ for _ in ()).throw(
            vt._SubmissionFenceRefused("attempt fence refused")
        ),
    )

    assert vt.run(_run_args(tmp_path, _FullDisk())) == 1
    assert calls == [], "a degraded journal did not unlock a chain write"


# ---------------------------------------------------------------------------
# The state file is the asymmetry: it stays fatal
# ---------------------------------------------------------------------------


def test_a_state_write_that_hits_enospc_is_still_fatal(monkeypatch, tmp_path):
    """The fence must never advance in memory while failing on disk.

    Swallowing this the way the journal now does would leave the durable
    anti-rollback watermark pointing at an older attempt while the process
    carried on believing it had advanced — the double-submit/replay path.
    """
    state_file = tmp_path / "state.json"
    vt.save_fence(state_file, 5, "vector-5")
    assert vt.load_fence(state_file) == 5

    real_fsync = os.fsync

    def _full_disk_fsync(fd):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", _full_disk_fsync)
    with pytest.raises(OSError) as raised:
        vt.save_fence(state_file, 9, "vector-9")
    assert raised.value.errno == errno.ENOSPC

    monkeypatch.setattr(os, "fsync", real_fsync)
    assert vt.load_fence(state_file) == 5, (
        "the fence stayed exactly where it was; nothing claimed version 9"
    )


def test_a_failed_state_write_fails_the_tick_closed(monkeypatch, tmp_path):
    """The fatal state write reaches the loop as a refusal, not a submission."""
    _quiet_loop(monkeypatch)
    calls: list[str] = []
    monkeypatch.setattr(
        vt, "set_weights_on_chain", lambda *a, **k: calls.append("submitted")
    )

    def _tick_that_cannot_persist(_args):
        vt.save_fence(vt.Path(_args.state_file), 9, "vector-9")
        return True  # never reached

    monkeypatch.setattr(vt, "tick", _tick_that_cannot_persist)
    monkeypatch.setattr(
        os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
    )

    assert vt.run(_run_args(tmp_path, _FullDisk())) == 1
    assert calls == []


# ---------------------------------------------------------------------------
# The cheap startup warning
# ---------------------------------------------------------------------------


def test_a_nearly_full_filesystem_warns_at_startup(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        events_module.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_bavail=16, f_frsize=4096),
    )

    EventLogger(
        mode="thin", jsonl_path=str(tmp_path / "events.jsonl"), tty=io.StringIO()
    )

    assert "64 KiB free" in capsys.readouterr().err


def test_a_healthy_filesystem_says_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        events_module.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_bavail=1_000_000, f_frsize=4096),
    )

    EventLogger(
        mode="thin", jsonl_path=str(tmp_path / "events.jsonl"), tty=io.StringIO()
    )

    assert capsys.readouterr().err == ""


def test_the_startup_check_can_never_fail_the_start(monkeypatch, tmp_path):
    """Advisory only. A warning that can refuse a start is worse than none."""

    def _broken_statvfs(_path):
        raise OSError(errno.EACCES, "permission denied")

    monkeypatch.setattr(events_module.os, "statvfs", _broken_statvfs)

    logger = EventLogger(
        mode="thin", jsonl_path=str(tmp_path / "events.jsonl"), tty=io.StringIO()
    )
    logger.event("STARTUP", stage="startup")
    logger.close()

    assert (tmp_path / "events.jsonl").read_text().count("STARTUP") == 1
