"""The operator stream must surface while the validator is still running.

`journalctl -fu cathedral-validator-sn39-relay` is the first thing any operator
runs, and until this was fixed it showed them nothing for hours.

Every supported way of running this validator puts a PIPE on stdout: systemd's
journal, `nohup`, `tmux | tee`, `docker logs`. Python's default for a non-tty
stdout is an 8192-byte BLOCK buffer, and a tick emits a few hundred bytes, so a
live validator filled roughly one buffer every few hours. Measured on a running
SN39 relay, same PID throughout: the flush at 15:11:21 carried content stamped
12:10:35, and the window 11:44:48 -> 15:11:21 (3h26m) produced zero journal
lines while the JSONL recorded seven successful WEIGHTS_SUBMITTED events.

What the operator sees is worse than mere lateness: the tail ends on a tick
divider with no outcome line under it, which is the exact signature of a hang
mid-submission. The rational response is `systemctl restart`, and that is the
harm -- SIGTERM does not flush, so the restart DISCARDS the buffered evidence
that everything was fine, costs a write cycle, and drops them into receipt
recovery.

The fix has to live in the process. The SN39 release launcher `execve`s a
curated environment, so an operator's own `PYTHONUNBUFFERED` -- from a systemd
drop-in, a shell, a compose file -- never reaches the child; and the unit's
digest is bound in the release manifest's `external_files`, so they cannot edit
the unit either. Nothing here changes a verdict, a gate or an ordering: only
when bytes leave the process.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import select
import subprocess
import sys
import textwrap

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[2]
_LAUNCHER_PATH = _REPO / "deploy" / "sn39" / "cathedral-sn39-release-launcher.py"

# Deliberately far apart: a loaded CI box may take many seconds to start an
# interpreter, and the child must be nowhere near exiting when we give up.
_READ_TIMEOUT = 60.0
_CHILD_LIFETIME = 3600


def _run_child(body: str, *, text: bool = True) -> subprocess.Popen:
    """Start a child whose stdout is a PIPE -- the production shape."""
    return subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(body)],
        cwd=_REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def test_cli_main_line_buffers_a_piped_stdout():
    """`scaffold.cli.main` must leave stdout line-buffered, not block-buffered.

    Asserted on the interpreter's own view of the stream rather than on
    timings, so the check is deterministic on a loaded machine.
    """
    child = _run_child(
        """
        import sys
        from scaffold import cli

        assert not sys.stdout.isatty(), "this child must be piped to be meaningful"
        assert sys.stdout.line_buffering is False, (
            "precondition: a piped stdout starts block-buffered"
        )
        cli.main(["version"])
        print(f"line_buffering={sys.stdout.line_buffering}", file=sys.stderr)
        """
    )
    _, err = child.communicate(timeout=60)
    assert child.returncode == 0, err
    assert "line_buffering=True" in err, (
        "an 8192-byte block buffer on a journald pipe hides hours of ticks; "
        f"stderr was: {err}"
    )


def test_output_reaches_the_reader_before_the_process_exits():
    """The end-to-end property: a reader sees a line from a LIVE validator.

    A block-buffered child only flushes when the buffer fills or the process
    exits, which is precisely why the journal looked hung. This child prints
    and then blocks for an hour, so the two outcomes are hours apart and the
    `_READ_TIMEOUT` window cannot straddle them: bytes inside the window mean
    they were flushed by a running process, not by its teardown.
    """
    child = _run_child(
        f"""
        import time
        from scaffold import cli

        cli.main(["version"])
        time.sleep({_CHILD_LIFETIME})
        """,
        text=False,
    )
    try:
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], _READ_TIMEOUT)
        assert ready, (
            f"nothing readable after {_READ_TIMEOUT}s from a child that will "
            f"not exit for {_CHILD_LIFETIME}s -- the operator stream is still "
            "held in a block buffer"
        )
        assert os.read(child.stdout.fileno(), 4096).strip(), (
            "a live validator produced no readable output"
        )
        assert child.poll() is None, "the child was supposed to still be running"
    finally:
        child.kill()
        child.communicate()


@pytest.mark.parametrize(
    ("argv", "expected_target"),
    [
        (["continuous"], "scaffold.cli"),
        (["status"], "scripts/publish_sn39_validator_status.py"),
        (
            ["finalize", f"/var/lib/cathedral-validator/journal-{'a' * 64}.json"],
            "scripts/finalize_sn39_public_release.py",
        ),
    ],
)
def test_the_release_launcher_passes_dash_u_for_every_mode(
    argv, expected_target, monkeypatch, tmp_path
):
    """Belt to `cli.main`'s braces, and the only cover for the script modes.

    `scripts/publish_sn39_validator_status.py` and
    `scripts/finalize_sn39_public_release.py` never call `cli.main`, so `-u` is
    the whole fix for them.
    """
    spec = importlib.util.spec_from_file_location(
        "_sn39_release_launcher_buffering", _LAUNCHER_PATH
    )
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)

    release = tmp_path / "release"
    release.mkdir()
    python = tmp_path / "python"
    python.write_text("")

    captured: dict[str, list[str]] = {}

    monkeypatch.setattr(
        launcher, "_verify", lambda mode: (release, python, "sha256:" + "0" * 64)
    )
    monkeypatch.setattr(launcher, "_digest", lambda path: "sha256:" + "1" * 64)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: launcher.ROOT_UID)
    monkeypatch.setattr(launcher.os, "chdir", lambda path: None)
    monkeypatch.setattr(
        launcher,
        "_finalizer_context_digest",
        lambda **kwargs: "sha256:" + "2" * 64,
    )
    monkeypatch.setattr(
        launcher.os,
        "execve",
        lambda program, command, environment: captured.update(command=command),
    )

    launcher.main(argv)

    command = captured["command"]
    assert "-u" in command, (
        f"{argv[0]} would block-buffer its operator stream: {command}"
    )
    target = next(i for i, arg in enumerate(command[1:], 1) if not arg.startswith("-"))
    assert command[target].endswith(expected_target), (
        f"the command itself must be unchanged: {command}"
    )
    # -u is an interpreter flag: it only counts ahead of the script (or of the
    # -m that names the module), never after it.
    assert command.index("-u") < target


def test_verify_checks_the_install_without_execing_the_validator(monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location(
        "_sn39_release_launcher_verify", _LAUNCHER_PATH
    )
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)

    verified_modes: list[str] = []
    monkeypatch.setattr(
        launcher,
        "_verify",
        lambda mode: (
            verified_modes.append(mode)
            or (pathlib.Path("a" * 40), pathlib.Path("/unused"), "sha256:" + "0" * 64)
        ),
    )
    monkeypatch.setattr(
        launcher.os,
        "execve",
        lambda *_args: pytest.fail("verify mode must not exec the validator"),
    )

    assert launcher.main(["verify"]) == 0
    assert verified_modes == ["continuous"]
    assert "immutable-install verification PASS" in capsys.readouterr().out
