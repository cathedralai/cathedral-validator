"""The alert must be red when the validator is dead, not green when it is blind.

The failure that costs an SN39 operator money is the quiet one: the validator
stops writing weights. A crashed process, a wedged RPC, a full disk, a
deregistered hotkey or a mistyped ``--jsonl`` path all look the same from
outside — the journal stops growing — and for a while none of them had a
detector. ``cathedral-mismatch-check`` alerted on exactly two shadow-audit
conditions, both computed by grepping a file inside ``$(...)``, so a journal
that was missing, unreadable, or simply no longer growing produced zero
matches, and zero matches read as "nothing is wrong".

These tests pin the opposite: every way of seeing nothing is an alert, the
absence of a completed tick is an alert, and the two original shadow-audit
rules still behave exactly as they did. The shell alert and
``cathedral-validator status`` are checked against the same journals, because
two monitors that disagree about "healthy" are worse than one.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scaffold import health
from scaffold.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_SCRIPT = REPO_ROOT / "deploy" / "sn39" / "cathedral-mismatch-check"
TICK = 1500.0


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _record(event: str, *, ago_secs: float, status: str = "PASS", **fields) -> dict:
    return {
        "ts": _stamp(datetime.now(UTC) - timedelta(seconds=ago_secs)),
        "event": event,
        "stage": "result",
        "mode": "shadow",
        "status": status,
        **fields,
    }


def _journal(
    tmp_path: Path, records, *, name: str = "events.jsonl", pretty=False
) -> Path:
    path = tmp_path / name
    separators = None if pretty else (",", ":")
    path.write_text(
        "".join(json.dumps(r, separators=separators) + "\n" for r in records),
        encoding="utf-8",
    )
    return path


def _run_alert(journal, *, tick_secs: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if tick_secs is not None:
        env["CATHEDRAL_TICK_SECS"] = tick_secs
    return subprocess.run(
        ["bash", str(ALERT_SCRIPT), str(journal)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def _alive(ago_secs: float = 60.0) -> list[dict]:
    """A journal that proves the loop is running, with nothing else wrong."""
    return [
        _record("STARTUP", ago_secs=ago_secs + 4 * TICK, status="INFO"),
        _record("VECTOR_ACCEPTED", ago_secs=ago_secs + 5),
        _record("WEIGHTS_SUBMITTED", ago_secs=ago_secs, uid_count=42),
        _record("PROVENANCE_AUDIT_PASS", ago_secs=ago_secs),
    ]


# -- fail closed: every way of seeing nothing is an alert --------------------


def test_a_missing_journal_is_an_alert_not_a_pass(tmp_path):
    """The regression that motivated all of this.

    Before the fix, `cathedral-mismatch-check /nonexistent/path` printed "no
    recent mismatch" and exited 0 — a green light on a sensor pointed at
    nothing.
    """
    result = _run_alert(tmp_path / "never-written.jsonl")
    assert result.returncode == 1
    assert "does not exist" in result.stdout
    assert "blind" in result.stdout


def test_an_empty_journal_is_an_alert(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("", encoding="utf-8")
    result = _run_alert(path)
    assert result.returncode == 1
    assert "is empty" in result.stdout


def test_a_journal_of_unparseable_lines_is_an_alert(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("not json\n{broken\n", encoding="utf-8")
    result = _run_alert(path)
    assert result.returncode == 1
    assert "no parseable event record" in result.stdout


def test_a_directory_where_the_journal_should_be_is_an_alert(tmp_path):
    directory = tmp_path / "events.jsonl"
    directory.mkdir()
    result = _run_alert(directory)
    assert result.returncode == 1
    assert "not a regular file" in result.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_an_unreadable_journal_is_an_alert(tmp_path):
    path = _journal(tmp_path, _alive())
    path.chmod(0o000)
    try:
        result = _run_alert(path)
    finally:
        path.chmod(0o600)
    assert result.returncode == 1
    assert "not readable" in result.stdout


# -- the journal must still be growing, and ticks must still complete --------


def test_a_journal_that_stopped_growing_is_an_alert(tmp_path):
    """Everything was fine four hours ago. That is exactly the problem."""
    path = _journal(tmp_path, _alive(ago_secs=4 * TICK))
    result = _run_alert(path)
    assert result.returncode == 1
    assert "has not grown" in result.stdout


def test_a_fresh_journal_with_no_completed_tick_is_an_alert(tmp_path):
    """The loop is writing, but nothing is finishing: still not writing weights."""
    records = [
        _record("STARTUP", ago_secs=10 * TICK, status="INFO"),
        _record("WEIGHTS_SUBMITTED", ago_secs=5 * TICK),
        _record("TICK_FAILED", ago_secs=30, status="FAIL"),
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 1
    assert "no completed tick" in result.stdout
    assert "not writing weights" in result.stdout


@pytest.mark.parametrize(
    "event",
    [
        "WEIGHTS_SUBMITTED",
        "WEIGHTS_DRY_RUN",
        "WEIGHT_COOLDOWN_SKIPPED",
        "WAITING_FOR_JOB",
    ],
)
def test_every_tick_completing_event_counts_as_alive(tmp_path, event):
    """A rate-limited tick and a nothing-to-score tick are both healthy.

    Treating either as dead would page an operator every night on a subnet
    whose `weights_rate_limit` is independent of the tick interval.
    """
    records = [
        _record("STARTUP", ago_secs=10 * TICK, status="INFO"),
        _record(event, ago_secs=120, status="INFO"),
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 0, result.stdout
    assert "validator alive" in result.stdout


def test_a_validator_that_just_started_is_not_yet_late(tmp_path):
    """A restart must not alert before its first tick could possibly finish."""
    records = [_record("STARTUP", ago_secs=60, status="INFO")]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 0, result.stdout
    assert "starting up" in result.stdout


def test_a_validator_that_started_and_then_hung_still_alerts(tmp_path):
    """Warm-up grace is bounded: staleness catches the hang a tick sooner."""
    records = [_record("STARTUP", ago_secs=3.5 * TICK, status="INFO")]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 1
    assert "has not grown" in result.stdout


def _restart_loop(hours: float = 6.0, every_secs: float = 600.0) -> list[dict]:
    """A process that starts, fails its tick, dies, and is restarted. Forever."""
    records: list[dict] = []
    ago = hours * 3600.0
    while ago > 0:
        records.append(_record("STARTUP", ago_secs=ago, status="INFO"))
        records.append(_record("TICK_FAILED", ago_secs=ago - 5, status="FAIL"))
        ago -= every_secs
    return records


def test_a_restart_loop_cannot_renew_its_own_warm_up_grace(tmp_path):
    """The expensive failure, and it used to read as healthy in both monitors.

    Every restart writes a STARTUP, so grace dated from the NEWEST one was
    renewed by the crashes themselves — and the same crashes kept the journal
    growing, so the staleness rule stayed green too. Six hours of writing no
    weights, exit 0, "starting up". Grace is dated from the FIRST restart since
    the last completed tick, so it is granted once and then expires.
    """
    path = _journal(tmp_path, _restart_loop())
    result = _run_alert(path)
    assert result.returncode == 1
    assert "no completed tick" in result.stdout
    assert "not writing weights" in result.stdout

    report = health.evaluate(path, interval_secs=TICK)
    assert report.ok is False
    assert any("not writing weights" in problem for problem in report.problems)
    assert report.warming_up is False


def test_a_single_restart_still_gets_its_whole_grace_window(tmp_path):
    """The fix must not page an operator for one ordinary restart."""
    records = [
        _record("WEIGHTS_SUBMITTED", ago_secs=5 * TICK),
        _record("STARTUP", ago_secs=3.5 * TICK, status="INFO"),
        _record("VECTOR_ACCEPTED", ago_secs=60),
    ]
    path = _journal(tmp_path, records)
    result = _run_alert(path)
    assert result.returncode == 0, result.stdout
    assert "starting up" in result.stdout
    report = health.evaluate(path, interval_secs=TICK)
    assert report.ok is True
    assert report.warming_up is True


def test_the_windows_are_tick_multiples_not_fixed_minutes(tmp_path):
    """A validator configured to tick fast is declared dead fast."""
    records = _alive(ago_secs=600)
    path = _journal(tmp_path, records)
    assert _run_alert(path).returncode == 0
    fast = _run_alert(path, tick_secs="60")
    assert fast.returncode == 1
    assert "has not grown" in fast.stdout


def test_a_nonsense_tick_interval_is_an_alert(tmp_path):
    result = _run_alert(_journal(tmp_path, _alive()), tick_secs="twenty-five minutes")
    assert result.returncode == 1
    assert "CATHEDRAL_TICK_SECS" in result.stdout


def test_a_healthy_journal_still_passes(tmp_path):
    result = _run_alert(_journal(tmp_path, _alive()))
    assert result.returncode == 0, result.stdout
    assert "no recent mismatch" in result.stdout
    assert "shadow audit not persistently failing" in result.stdout


def test_whitespace_in_the_journal_encoding_does_not_blind_the_check(tmp_path):
    """The emitter writes compact JSON; a re-serialized copy must still parse."""
    path = _journal(tmp_path, _alive(), pretty=True)
    assert '"ts": "' in path.read_text(encoding="utf-8")
    result = _run_alert(path)
    assert result.returncode == 0, result.stdout


# -- the two original shadow-audit rules are unchanged ----------------------


def test_a_recent_vector_mismatch_still_alerts(tmp_path):
    records = _alive() + [
        _record("PROVENANCE_VECTOR_MISMATCH", ago_secs=300, status="FAIL")
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 1
    assert "PROVENANCE_VECTOR_MISMATCH" in result.stdout


def test_a_stale_epoch_classification_still_does_not_alert(tmp_path):
    """The serving race is a classification, not the tamper alarm."""
    records = _alive() + [
        _record("PROVENANCE_VECTOR_STALE_EPOCH", ago_secs=300, status="NOT_PROVEN")
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 0, result.stdout


def test_persistent_audit_failure_still_alerts(tmp_path):
    records = [
        _record("STARTUP", ago_secs=10 * TICK, status="INFO"),
        _record("WEIGHTS_SUBMITTED", ago_secs=60),
        _record("PROVENANCE_AUDIT_FAIL", ago_secs=1200, status="FAIL"),
        _record("PROVENANCE_AUDIT_FAIL", ago_secs=60, status="FAIL"),
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 1
    # Rule 5 counts a run of consecutive FAILs; it no longer keys recovery on a
    # PASS, which a receipts-only relay never emits. See the denoise suite.
    assert "2 consecutive" in result.stdout


def test_a_transient_audit_failure_followed_by_a_pass_does_not_alert(tmp_path):
    records = [
        _record("STARTUP", ago_secs=10 * TICK, status="INFO"),
        _record("PROVENANCE_AUDIT_FAIL", ago_secs=1200, status="FAIL"),
        _record("WEIGHTS_SUBMITTED", ago_secs=60),
        _record("PROVENANCE_AUDIT_PASS", ago_secs=60),
    ]
    result = _run_alert(_journal(tmp_path, records))
    assert result.returncode == 0, result.stdout


# -- rule 5 is ONE rule, not two implementations of it ----------------------


def _audit_run(outcomes: list[str]) -> list[dict]:
    """A live relay whose audit produced ``outcomes``, oldest first."""
    records = [_record("STARTUP", ago_secs=10 * TICK, status="INFO")]
    for index, outcome in enumerate(reversed(outcomes)):
        ago = 300 + index * 1500
        records.insert(1, _record(f"PROVENANCE_AUDIT_{outcome}", ago_secs=ago))
    records.append(_record("WEIGHTS_SUBMITTED", ago_secs=60))
    return records


@pytest.mark.parametrize(
    "outcomes,healthy",
    [
        # The relay steady state: receipts_only, so NOT_PROVEN forever and a
        # PASS that never comes. One transient publisher-side FAIL between two
        # of them must not page anyone.
        (["NOT_PROVEN", "FAIL", "NOT_PROVEN"], True),
        (["NOT_PROVEN", "NOT_PROVEN", "NOT_PROVEN"], True),
        (["FAIL"], True),
        (["FAIL", "FAIL"], False),
        (["FAIL", "FAIL", "NOT_PROVEN"], True),
        (["FAIL", "FAIL", "PASS"], True),
        (["NOT_PROVEN", "FAIL", "FAIL"], False),
    ],
)
def test_rule_five_agrees_between_status_and_the_alert(tmp_path, outcomes, healthy):
    """#64 rewrote rule 5 in the shell script only, and the two diverged.

    ``health.py`` still read "one FAIL and no PASS in 90 minutes", so on the
    receipts-only relay this repository ships — where a PASS is impossible by
    design — a single transient FAIL left `cathedral-validator status` red for
    a full 90 minutes while the systemd alert stayed green. The interactive
    tool false-alarmed on the documented steady state.
    """
    path = _journal(tmp_path, _audit_run(outcomes))
    assert health.evaluate(path, interval_secs=TICK).ok is healthy
    assert (_run_alert(path).returncode == 0) is healthy


# -- scaffold.health applies the same five rules ----------------------------


@pytest.mark.parametrize(
    "records,healthy",
    [
        (_alive(), True),
        (_alive(ago_secs=4 * TICK), False),
        ([_record("STARTUP", ago_secs=60, status="INFO")], True),
        ([_record("TICK_FAILED", ago_secs=30, status="FAIL")], False),
    ],
)
def test_health_and_the_shell_alert_agree(tmp_path, records, healthy):
    path = _journal(tmp_path, records)
    report = health.evaluate(path, interval_secs=TICK)
    assert report.ok is healthy
    assert (_run_alert(path).returncode == 0) is healthy


def test_health_names_the_reason_it_cannot_see(tmp_path):
    report = health.evaluate(tmp_path / "absent.jsonl", interval_secs=TICK)
    assert report.ok is False
    assert any("cannot be read" in problem for problem in report.problems)
    assert report.rows[0] == ("journal", "UNREADABLE — this check is blind")


def test_health_reads_only_the_tail_of_a_large_journal(tmp_path):
    """The journal is append-only and unbounded; the rules only need its end."""
    padding = [_record("VECTOR_ACCEPTED", ago_secs=50 * TICK) for _ in range(6000)]
    path = _journal(tmp_path, padding + _alive())
    assert path.stat().st_size > health.TAIL_BYTES
    assert health.evaluate(path, interval_secs=TICK).ok is True


def test_a_clock_ahead_of_this_host_is_not_read_as_stale(tmp_path):
    records = [
        _record("STARTUP", ago_secs=10 * TICK, status="INFO"),
        _record("WEIGHTS_SUBMITTED", ago_secs=-90),
    ]
    assert health.evaluate(_journal(tmp_path, records), interval_secs=TICK).ok is True


def test_an_absent_interval_falls_back_to_the_shipped_default(tmp_path):
    path = _journal(tmp_path, _alive(ago_secs=4 * 1500.0))
    assert health.evaluate(path, interval_secs=None).ok is False
    assert health.DEFAULT_INTERVAL_SECS == 1500.0


# -- `cathedral-validator status` ------------------------------------------


def test_status_exits_zero_and_shows_the_last_write(tmp_path, capsys):
    path = _journal(tmp_path, _alive())
    assert cli_main(["status", "--jsonl", str(path)]) == 0
    out = capsys.readouterr().out
    assert "WEIGHTS_SUBMITTED" in out
    assert "healthy" in out
    # The path is printed verbatim: a status check pointed at the wrong file is
    # one of the failures this command exists to catch.
    assert str(path) in out


def test_status_exits_nonzero_when_the_validator_is_not_writing(tmp_path, capsys):
    path = _journal(tmp_path, _alive(ago_secs=4 * TICK))
    assert cli_main(["status", "--jsonl", str(path)]) == 1
    out = capsys.readouterr().out
    assert "UNHEALTHY" in out
    assert "not writing weights" in out


def test_status_does_not_claim_ticks_are_completing_before_the_first_one(
    tmp_path, capsys
):
    """The footer is the line an operator reads; it may not out-claim the body.

    A fresh start printed `tick starting up — the first tick has not completed`
    and, four lines later, `healthy ticks are completing`.
    """
    path = _journal(tmp_path, [_record("STARTUP", ago_secs=60, status="INFO")])
    assert cli_main(["status", "--jsonl", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ticks are completing" not in out
    assert "starting up" in out


def test_status_on_a_journal_that_does_not_exist_is_not_healthy(tmp_path, capsys):
    assert cli_main(["status", "--jsonl", str(tmp_path / "absent.jsonl")]) == 1
    assert "UNHEALTHY" in capsys.readouterr().out


def test_status_without_a_journal_says_which_setting_to_fill_in(capsys):
    assert cli_main(["status"]) == 2
    err = capsys.readouterr().err
    assert "[logs].jsonl" in err
    assert "--jsonl" in err


def test_status_honours_the_configured_interval(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CATHEDRAL_VALIDATOR_JSONL", raising=False)
    path = _journal(tmp_path, _alive(ago_secs=600))
    config = tmp_path / "validator.toml"
    config.write_text(
        f'[weights]\ninterval_secs = 60\n\n[logs]\njsonl = "{path}"\n',
        encoding="utf-8",
    )
    assert cli_main(["status", "--config", str(config)]) == 1
    assert "has not grown" in capsys.readouterr().out


def test_status_never_touches_the_chain_or_the_wallet(tmp_path, monkeypatch):
    """Read-only by construction: it must be safe beside a live validator."""
    import scaffold.validator_thin as validator_thin

    def _forbidden(*args, **kwargs):  # pragma: no cover - only fails on regression
        raise AssertionError("status must not reach the chain")

    monkeypatch.setattr(validator_thin, "chain_preflight", _forbidden, raising=False)
    monkeypatch.setattr(validator_thin, "run", _forbidden, raising=False)
    assert cli_main(["status", "--jsonl", str(_journal(tmp_path, _alive()))]) == 0


def test_status_is_listed_in_the_command_surface(capsys):
    """README names one command for "is it working?"; it has to be findable."""
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["--help"])
    assert excinfo.value.code == 0
    assert "status" in capsys.readouterr().out
