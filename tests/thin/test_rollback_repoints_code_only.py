"""Rolling back must move the CODE and refuse to move anything else.

``deploy/sn39/cathedral-sn39-rollback`` exists because going back a version was a
hand-run sequence — sed the drop-in, daemon-reload, restart — performed under the
time pressure that makes hand-run sequences go wrong. Three properties are what
make the scripted form safer than the hand-run one, and they are what these tests
pin:

1. **It only ever repoints.** The staged trees, the validator's state file and
   its journal are untouched. That is not a stylistic preference: ``thin-state``
   carries the submission fences and the anti-rollback high-water marks, so
   winding state back would hand the validator a fence it has already spent. Code
   goes backwards, state does not.

2. **It refuses rather than guesses.** A version that is not staged, is staged but
   has no usable venv, is the one already running, or is not a plain directory
   name is a refusal — because each of those, applied, replaces a working
   validator with a unit that cannot start, and it does so at the moment the
   operator is least able to debug it.

3. **The drop-in survives.** Only the version token is rewritten; every other
   line the installer or the operator put in that file is still there afterwards,
   and a failed edit restores the backup rather than leaving a half-written file
   the service manager will read.

The service manager is stubbed here, so these run anywhere: what is asserted is
which commands the script *would* issue, and against which unit.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "sn39" / "cathedral-sn39-rollback"

PREFIX = "cathedral-validator-staging-"
OLD = "a026a68"
NEW = "750d766"

DROPIN_BODY = """\
[Service]
Environment=CATHEDRAL_VALIDATOR_PROFILE=relay
WorkingDirectory=/opt/{prefix}{version}
ExecStart=
ExecStart=/opt/{prefix}{version}/.venv/bin/python -m scaffold.cli serve
"""


# ---------------------------------------------------------------- harness ----


def _stage(root: Path, version: str, *, usable: bool = True) -> Path:
    tree = root / f"{PREFIX}{version}"
    (tree / ".venv" / "bin").mkdir(parents=True)
    if usable:
        interpreter = tree / ".venv" / "bin" / "python"
        interpreter.write_text("#!/bin/sh\nexit 0\n")
        interpreter.chmod(0o755)
    return tree


def _dropin(
    etc: Path, version: str, unit: str = "cathedral-validator-passive.service"
) -> Path:
    path = etc / f"{unit}.d" / "20-quickstart.conf"
    path.parent.mkdir(parents=True)
    path.write_text(DROPIN_BODY.format(prefix=PREFIX, version=version))
    return path


def _systemctl(tmp_path: Path, *, exit_code: int = 0) -> tuple[Path, Path]:
    log = tmp_path / "systemctl.log"
    stub = tmp_path / "systemctl"
    stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\nexit {exit_code}\n')
    stub.chmod(0o755)
    return stub, log


@pytest.fixture
def host(tmp_path: Path):
    """A host with two staged versions, running OLD."""

    root = tmp_path / "opt"
    root.mkdir()
    _stage(root, OLD)
    _stage(root, NEW)
    dropin = _dropin(tmp_path / "etc", OLD)
    stub, log = _systemctl(tmp_path)

    def run(*args: str, systemctl: Path = stub) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "CATHEDRAL_RELEASE_ROOT": str(root),
            "CATHEDRAL_STAGING_PREFIX": PREFIX,
            "CATHEDRAL_DROPIN": str(dropin),
            "CATHEDRAL_SYSTEMCTL": str(systemctl),
        }
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    return {"run": run, "root": root, "dropin": dropin, "log": log, "tmp": tmp_path}


# ------------------------------------------------------------- reads back ----


def test_current_reads_the_version_the_dropin_names(host):
    result = host["run"]("current")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == OLD


def test_list_marks_the_running_version(host):
    result = host["run"]("list")
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert f"* {OLD} (running)" in lines
    assert f"  {NEW}" in lines


# ---------------------------------------------------------------- repoint ----


def test_a_repointed_dropin_names_the_target_and_nothing_else(host):
    host["run"]("to", NEW)
    body = host["dropin"].read_text()
    # Both the WorkingDirectory and the ExecStart moved together. A file naming
    # the target *somewhere* is not the property; naming it everywhere is.
    assert f"{PREFIX}{OLD}" not in body
    assert body.count(f"{PREFIX}{NEW}") == 2


def test_repointing_rewrites_only_the_version_token(host):
    before = host["dropin"].read_text()
    result = host["run"]("to", NEW)
    assert result.returncode == 0, result.stderr

    after = host["dropin"].read_text()
    assert NEW in after and f"{PREFIX}{OLD}" not in after
    # Every non-version line is still present, byte for byte.
    assert "Environment=CATHEDRAL_VALIDATOR_PROFILE=relay" in after
    assert before.count("\n") == after.count("\n")
    assert after == before.replace(f"{PREFIX}{OLD}", f"{PREFIX}{NEW}")


def test_repointing_restarts_the_unit_its_dropin_belongs_to(host):
    host["run"]("to", NEW)
    issued = host["log"].read_text().splitlines()
    assert "daemon-reload" in issued
    assert "restart cathedral-validator-passive.service" in issued


def test_repointing_leaves_a_restorable_backup(host):
    original = host["dropin"].read_text()
    host["run"]("to", NEW)
    backups = list(host["dropin"].parent.glob("20-quickstart.conf.pre-*"))
    assert len(backups) == 1
    assert backups[0].read_text() == original


def test_history_records_the_move_so_previous_can_undo_it(host):
    host["run"]("to", NEW)
    assert host["run"]("current").stdout.strip() == NEW

    result = host["run"]("previous")
    assert result.returncode == 0, result.stderr
    assert host["run"]("current").stdout.strip() == OLD


# --------------------------------------------------------------- refusals ----


def test_refuses_a_version_that_is_not_staged(host):
    result = host["run"]("to", "deadbee")
    assert result.returncode != 0
    assert "not staged" in result.stderr
    assert OLD in host["dropin"].read_text()


def test_refuses_a_staged_tree_with_no_usable_venv(host):
    _stage(host["root"], "0badven", usable=False)
    result = host["run"]("to", "0badven")
    assert result.returncode != 0
    assert "no usable venv" in result.stderr
    assert OLD in host["dropin"].read_text()


def test_refuses_the_version_already_running(host):
    result = host["run"]("to", OLD)
    assert result.returncode != 0
    assert "already running" in result.stderr


@pytest.mark.parametrize("bad", ["../etc", "a b", "a;rm -rf /", "$(id)", ""])
def test_refuses_a_version_that_is_not_a_plain_directory_name(host, bad):
    result = host["run"]("to", bad)
    assert result.returncode != 0
    # It must be REJECTED AS A NAME, not merely found to be unstaged. Asserting
    # only the exit code would pass with validation deleted, because every value
    # here also fails the later "is it staged" test — and that later test is not
    # the one keeping shell metacharacters out of `sed`.
    assert (
        "empty version" in result.stderr
        or "not a plain directory name" in result.stderr
        or ("characters outside" in result.stderr)
    ), result.stderr
    assert OLD in host["dropin"].read_text()


def test_refuses_a_dropin_that_names_two_versions(host):
    # The hand-edit that has already cost this project once: ExecStart moved to a
    # new tree, WorkingDirectory left on the old one.
    mixed = (
        host["dropin"]
        .read_text()
        .replace(
            f"WorkingDirectory=/opt/{PREFIX}{OLD}",
            f"WorkingDirectory=/opt/{PREFIX}{NEW}",
        )
    )
    host["dropin"].write_text(mixed)

    result = host["run"]("to", NEW)
    assert result.returncode != 0
    assert "names more than one version" in result.stderr
    assert host["dropin"].read_text() == mixed


def test_dry_run_changes_nothing(host):
    before = host["dropin"].read_text()
    result = host["run"]("to", NEW, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "would repoint" in result.stdout
    assert host["dropin"].read_text() == before
    assert not host["log"].exists()


def test_previous_refuses_when_there_is_no_history(host):
    result = host["run"]("previous")
    assert result.returncode != 0
    assert "no rollback history" in result.stderr


def test_a_failed_restart_is_not_reported_as_success(host):
    fail_dir = host["tmp"] / "fail"
    fail_dir.mkdir()
    failing, _ = _systemctl(fail_dir, exit_code=1)
    result = host["run"]("to", NEW, systemctl=failing)
    assert result.returncode != 0
    # The drop-in still names the target: the edit succeeded, the restart did
    # not, and the operator is told exactly that rather than "done".
    assert NEW in host["dropin"].read_text()


# -------------------------------------------------------- state is sacred ----


def test_state_and_journal_are_never_touched(host):
    state = host["tmp"] / "thin-state.json"
    journal = host["tmp"] / "validator-events.jsonl"
    state.write_text('{"fence": 42}')
    journal.write_text('{"event": "WEIGHTS_SUBMITTED"}\n')

    host["run"]("to", NEW)

    assert state.read_text() == '{"fence": 42}'
    assert journal.read_text() == '{"event": "WEIGHTS_SUBMITTED"}\n'


def test_staged_trees_are_left_alone(host):
    old_tree = host["root"] / f"{PREFIX}{OLD}"
    host["run"]("to", NEW)
    # Rolling forward does not delete what you might roll back to.
    assert (old_tree / ".venv" / "bin" / "python").exists()
