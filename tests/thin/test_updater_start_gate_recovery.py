"""Adversarial process-boundary coverage for the validator updater start gate."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cathedral_thin.independent_runtime.updater as updater_module
from cathedral_thin.independent_runtime.updater import (
    UPDATER_STATE_SCHEMA,
    SignedReleaseUpdater,
    UpdateRefused,
)
from tests.thin import test_updater as fixture


def _spawn_transition_gate(
    updater: SignedReleaseUpdater,
    *,
    observed_cycle_check: Path,
) -> subprocess.Popen[str]:
    """Run a process gate that reports its first observed free cycle lock."""

    root = Path(__file__).resolve().parents[2]
    program = """\\
import os
import sys
from pathlib import Path

from cathedral_thin.independent_runtime.updater import SignedReleaseUpdater, UpdateRefused

class MarkingGate(SignedReleaseUpdater):
    def _cycle_lock_is_held_elsewhere(self):
        held = super()._cycle_lock_is_held_elsewhere()
        if not held:
            Path(sys.argv[5]).touch(exist_ok=True)
        return held

updater = MarkingGate(
    install_root=Path(sys.argv[1]),
    state_root=Path(sys.argv[2]),
    expected_hotkey=sys.argv[3],
    journal_scope_root=Path(sys.argv[4]),
    expected_uid=os.geteuid(),
)
try:
    print(updater.reconcile_boot(cycle_wait_seconds=0.05, operation_timeout_seconds=2.0))
except UpdateRefused as exc:
    print(f\"REFUSED: {exc}\", file=sys.stderr)
    raise SystemExit(23)
"""
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(root)
        if not existing_pythonpath
        else f"{root}{os.pathsep}{existing_pythonpath}"
    )
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            program,
            str(updater.install_root),
            str(updater.state_root),
            updater.journal.parent.name,
            str(updater.journal.parent.parent),
            str(observed_cycle_check),
        ],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _active_updater(
    tmp_path: Path,
) -> tuple[SignedReleaseUpdater, Ed25519PrivateKey, Path, bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    archive = fixture._archive()
    metadata = fixture._canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=fixture._tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    fixture._journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = fixture._updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )
    assert fixture._update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    return updater, private, journal, archive, metadata


def test_start_gate_waits_for_precycle_updater_then_reconciles_without_mutation(
    tmp_path: Path,
) -> None:
    updater, _private, _journal, _archive, _metadata = _active_updater(tmp_path)
    state_path = tmp_path / "state" / "state.json"
    before_state = state_path.read_bytes()
    before_target = os.readlink(tmp_path / "install" / "current")
    lock = fixture._lock_for_other_process(tmp_path / "state" / "updater.lock")

    def release() -> None:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)

    timer = threading.Timer(0.01, release)
    timer.start()
    try:
        result = fixture._run_reconcile_in_separate_process(updater)
    finally:
        timer.join(timeout=1.0)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "RECONCILED"
    assert state_path.read_bytes() == before_state
    assert os.readlink(tmp_path / "install" / "current") == before_target


def test_start_gate_refuses_when_precycle_updater_lock_does_not_clear(
    tmp_path: Path,
) -> None:
    updater, _private, _journal, _archive, _metadata = _active_updater(tmp_path)
    state_path = tmp_path / "state" / "state.json"
    before_state = state_path.read_bytes()
    before_target = os.readlink(tmp_path / "install" / "current")
    lock = fixture._lock_for_other_process(tmp_path / "state" / "updater.lock")
    try:
        result = fixture._run_reconcile_in_separate_process(updater)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)

    assert result.returncode == 23
    assert "did not finish before timeout" in result.stderr
    assert state_path.read_bytes() == before_state
    assert os.readlink(tmp_path / "install" / "current") == before_target


def test_start_gate_switches_to_nested_authorization_when_cycle_lock_appears(
    tmp_path: Path,
) -> None:
    updater, private, journal, _archive, _metadata = _active_updater(tmp_path)
    archive_two = fixture._archive(marker_path=tmp_path / "transition-two")
    metadata_two = fixture._canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=fixture._tree_digest(tmp_path, archive_two, name="transition-tree"),
    )
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    def interrupt_after_authorization(_command: object) -> None:
        raise KeyboardInterrupt("leave an authorized target for the gate")

    updater.service_restarter = interrupt_after_authorization
    with pytest.raises(KeyboardInterrupt, match="authorized target"):
        fixture._update(updater, private, channel="canary", sequence=2)

    observed = tmp_path / "observed-free-cycle-lock"
    updater_lock = fixture._lock_for_other_process(tmp_path / "state" / "updater.lock")
    gate = _spawn_transition_gate(updater, observed_cycle_check=observed)
    cycle_lock = -1
    try:
        deadline = time.monotonic() + 1.0
        while not observed.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert observed.exists(), "start gate did not observe the pre-cycle window"
        cycle_lock = fixture._lock_for_other_process(journal.with_name("cycle.lock"))
        stdout, stderr = gate.communicate(timeout=3.0)
    finally:
        if cycle_lock >= 0:
            fcntl.flock(cycle_lock, fcntl.LOCK_UN)
            os.close(cycle_lock)
        fcntl.flock(updater_lock, fcntl.LOCK_UN)
        os.close(updater_lock)
        if gate.poll() is None:
            gate.kill()
            gate.communicate(timeout=1.0)

    assert gate.returncode == 0, stderr
    assert stdout.strip() == "START_AUTHORIZED"


@pytest.mark.parametrize("roll_back", (False, True), ids=("target", "rollback"))
def test_nested_start_gate_authorizes_only_the_exact_locked_target(
    tmp_path: Path,
    roll_back: bool,
) -> None:
    updater, private, journal, _archive_one, _metadata_one = _active_updater(tmp_path)
    archive_two = fixture._archive(marker_path=tmp_path / "nested-two")
    metadata_two = fixture._canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=fixture._tree_digest(tmp_path, archive_two, name="second-tree"),
    )
    original = os.readlink(tmp_path / "install" / "current")
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    def interrupt_after_authorization(_command: object) -> None:
        raise KeyboardInterrupt("simulated updater interruption")

    updater.service_restarter = interrupt_after_authorization
    with pytest.raises(KeyboardInterrupt, match="updater interruption"):
        fixture._update(updater, private, channel="canary", sequence=2)

    if roll_back:
        current = tmp_path / "install" / "current"
        current.unlink()
        current.symlink_to(original)
    state_path = tmp_path / "state" / "state.json"
    before_state = state_path.read_bytes()
    updater_lock = fixture._lock_for_other_process(tmp_path / "state" / "updater.lock")
    cycle_lock = fixture._lock_for_other_process(journal.with_name("cycle.lock"))
    try:
        result = fixture._run_reconcile_in_separate_process(updater)
    finally:
        fcntl.flock(cycle_lock, fcntl.LOCK_UN)
        os.close(cycle_lock)
        fcntl.flock(updater_lock, fcntl.LOCK_UN)
        os.close(updater_lock)

    expected = original if roll_back else (
        f"releases/{hashlib.sha256(archive_two).hexdigest()}"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "START_AUTHORIZED"
    assert os.readlink(tmp_path / "install" / "current") == expected
    assert state_path.read_bytes() == before_state


def test_pause_cannot_hide_an_unresolved_recovery_outage(tmp_path: Path) -> None:
    updater, private, journal, _archive, _metadata = _active_updater(tmp_path)
    archive_two = fixture._archive(marker_path=tmp_path / "pending-two")
    metadata_two = fixture._canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=fixture._tree_digest(tmp_path, archive_two, name="pending-tree"),
    )
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )
    def interrupt_after_authorization(_command: object) -> None:
        raise KeyboardInterrupt("leave a crash-uncertain activation")

    updater.service_restarter = interrupt_after_authorization
    with pytest.raises(KeyboardInterrupt, match="crash-uncertain"):
        fixture._update(updater, private, channel="canary", sequence=2)

    state_path = tmp_path / "state" / "state.json"
    before_state = state_path.read_bytes()
    before_target = os.readlink(tmp_path / "install" / "current")
    pause = tmp_path / "pause"
    pause.write_text("operator pause\n")
    restart_attempts: list[tuple[str, ...]] = []

    def refuse_recovery(command: object) -> None:
        restart_attempts.append(tuple(command))
        raise OSError("target readiness is still unconfirmed")

    recovered = fixture._updater(
        tmp_path,
        journal=journal,
        metadata=metadata_two,
        archive=archive_two,
        service_restarter=refuse_recovery,
    )
    with pytest.raises(UpdateRefused, match="pending activation remains unresolved"):
        fixture._update(recovered, private, channel="canary", sequence=3)

    assert restart_attempts == [
        (updater_module.SYSTEMCTL, "restart", updater_module.VALIDATOR_SERVICE)
    ]
    assert state_path.read_bytes() == before_state
    assert os.readlink(tmp_path / "install" / "current") == before_target


def test_first_install_timeout_preserves_recovery_record_and_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = fixture._archive()
    metadata = fixture._canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=fixture._tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    calls: list[tuple[str, ...]] = []

    def readiness_times_out(command: object) -> None:
        calls.append(tuple(command))
        raise OSError("service readiness timeout")

    updater = fixture._updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        service_restarter=readiness_times_out,
        seed_current=False,
    )
    original_remaining = updater_module._remaining_seconds
    control_checks = 0

    def expire_before_stop(deadline: float, *, label: str) -> float:
        nonlocal control_checks
        if label == "validator service control":
            control_checks += 1
            if control_checks == 2:
                raise updater_module._OperationDeadlineExpired(
                    "update operation deadline expired during validator service control"
                )
        return original_remaining(deadline, label=label)

    monkeypatch.setattr(updater_module, "_remaining_seconds", expire_before_stop)
    with pytest.raises(UpdateRefused, match="could not be stopped; pending activation remains"):
        updater.bootstrap(
            metadata_url="https://releases.example/canary.json",
            channel="canary",
            public_key=private.public_key(),
            pause_file=tmp_path / "pause",
            minimum_sequence=1,
            validator_uid=os.geteuid(),
            validator_gid=os.getegid(),
            cycle_wait_seconds=0.1,
            operation_timeout_seconds=1.0,
        )

    state = json.loads((tmp_path / "state" / "state.json").read_text())
    target = f"releases/{hashlib.sha256(archive).hexdigest()}"
    assert calls == [(updater_module.SYSTEMCTL, "restart", updater_module.VALIDATOR_SERVICE)]
    assert state["schema"] == UPDATER_STATE_SCHEMA
    assert state["channels"] == {}
    assert state["pending"]["stage"] == "may_have_run"
    assert os.readlink(tmp_path / "install" / "current") == target
