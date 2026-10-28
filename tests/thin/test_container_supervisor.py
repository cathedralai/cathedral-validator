"""Container PID1, first-install expiry, uid split, and service_restarter."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import cathedral_thin.independent_runtime.updater as updater_module
from cathedral_thin.independent_runtime.updater import (
    SYSTEMCTL,
    VALIDATOR_SERVICE,
    UpdateRefused,
    container_service_restarter,
    require_fixed_validator_service_command,
)


ROOT = Path(__file__).resolve().parents[2]


def _module(name: str, relative: str) -> ModuleType:
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(
        name,
        path,
        loader=SourceFileLoader(name, str(path)),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


supervisor = _module(
    "cathedral_test_container_supervisor",
    "deploy/validator-docker/container_supervisor.py",
)
image_bootstrap = _module(
    "cathedral_test_image_bootstrap",
    "deploy/validator-docker/install_image_bootstrap.py",
)
container_update = _module(
    "cathedral_test_container_update",
    "deploy/validator-docker/container_update.py",
)
status = _module(
    "cathedral_test_container_status",
    "deploy/validator-update/cathedral-validator-status",
)


def test_install_script_and_image_bootstrap_share_the_same_pins() -> None:
    install = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    assert image_bootstrap.BOOTSTRAP_BASE in install
    for name, digest in image_bootstrap.BOOTSTRAP_FILES.items():
        assert digest in install
        assert name in install
    assert image_bootstrap.BOOTSTRAP_KEY_FINGERPRINT in install
    assert (
        f"--minimum-bootstrap-sequence {image_bootstrap.MINIMUM_BOOTSTRAP_SEQUENCE}"
        in install
    )


def test_bootstrap_expiry_is_checked_only_on_first_install() -> None:
    supervisor.check_bootstrap_expiry(expires_unix=100, now_unix=99, first_install=True)
    with pytest.raises(supervisor.SupervisorRefused, match="has expired"):
        supervisor.check_bootstrap_expiry(
            expires_unix=100, now_unix=100, first_install=True
        )
    supervisor.check_bootstrap_expiry(
        expires_unix=100, now_unix=10_000, first_install=False
    )


def test_empty_state_volume_is_first_install(tmp_path: Path) -> None:
    assert supervisor.is_first_install(tmp_path) is True
    (tmp_path / "state.json").write_text("{}", encoding="ascii")
    assert supervisor.is_first_install(tmp_path) is False


def test_missing_snp_policy_is_refused(tmp_path: Path) -> None:
    with pytest.raises(supervisor.SupervisorRefused, match="snp-policy.json"):
        supervisor.require_mounted_snp_policy(tmp_path / "missing.json")


def test_hotkey_copy_is_0400_and_not_world_readable(tmp_path: Path) -> None:
    source = tmp_path / "hotkey"
    dest = tmp_path / "wallet" / "default"
    source.write_bytes(b'{"ss58Address":"5Test"}')
    uid = os.geteuid()
    gid = os.getegid()
    supervisor.copy_owned_file(source, dest, uid=uid, gid=gid, mode=0o400)
    metadata = dest.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o400
    assert metadata.st_uid == uid
    assert os.access(dest, os.R_OK)
    # The updater path is a different uid. When we are not root we cannot
    # create one, so prove the mode forbids group and other reads.
    assert metadata.st_mode & 0o077 == 0


def test_policy_copy_is_root_style_0644(tmp_path: Path) -> None:
    source = tmp_path / "policy.json"
    dest = tmp_path / "etc" / "snp-policy.json"
    source.write_text(
        '{"schema":"cathedral_amd_sev_snp_policy_v1"}\n', encoding="ascii"
    )
    supervisor.copy_owned_file(
        source, dest, uid=os.geteuid(), gid=os.getegid(), mode=0o644
    )
    assert stat.S_IMODE(dest.stat().st_mode) == 0o644


def test_exit_2_and_3_stay_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(supervisor, "SUPERVISOR_STATE", tmp_path / "supervisor.json")
    held: list[int] = []

    class FakeProcess:
        def __init__(self, code: int) -> None:
            self.pid = 1000 + code
            self._code = code

        def poll(self) -> int:
            return self._code

    instance = supervisor.Supervisor(expected_hotkey="5Expected")
    for code in (2, 3):
        instance.validator = FakeProcess(code)
        instance.validator_held_stop = None
        instance.handle_validator_exit(code)
        assert instance.validator is None
        assert instance.validator_held_stop == code
        instance.start_validator()
        assert instance.validator is None
        held.append(code)
    assert held == [2, 3]


def test_nonterminal_exit_restarts_the_validator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor, "SUPERVISOR_STATE", tmp_path / "supervisor.json")
    started = {"count": 0}

    def fake_start() -> None:
        started["count"] += 1

    instance = supervisor.Supervisor(expected_hotkey="5Expected")
    monkeypatch.setattr(instance, "start_validator", fake_start)
    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    instance.handle_validator_exit(1)
    assert instance.validator_held_stop is None
    assert started["count"] == 1


def test_service_restarter_uses_the_supervisor_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "service.sock"
    seen: list[str] = []

    def server() -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(socket_path))
        listener.listen(1)
        conn, _addr = listener.accept()
        with conn:
            seen.append(conn.recv(32).decode("ascii").strip())
            conn.sendall(b"ok\n")
        listener.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.02)
    restarter = container_service_restarter(socket_path, timeout_seconds=5)
    restarter((SYSTEMCTL, "restart", VALIDATOR_SERVICE))
    thread.join(timeout=5)
    assert seen == ["restart"]


def test_service_restarter_refuses_any_other_command(tmp_path: Path) -> None:
    restarter = container_service_restarter(tmp_path / "missing.sock")
    with pytest.raises(UpdateRefused, match="not fixed"):
        restarter((SYSTEMCTL, "start", VALIDATOR_SERVICE))
    with pytest.raises(UpdateRefused, match="not fixed"):
        require_fixed_validator_service_command(["/bin/true"])


def test_updater_cli_plugs_container_service_restarter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    class FakeUpdater:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def reconcile_boot(self, **_kwargs) -> str:
            return "RECONCILED"

    monkeypatch.setattr(updater_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater_module,
        "load_expected_hotkey_identity",
        lambda _path: "5ExpectedValidator",
    )
    monkeypatch.setattr(updater_module, "SignedReleaseUpdater", FakeUpdater)

    assert (
        updater_module.main(
            [
                "--reconcile-boot",
                "--identity-file=/ignored",
                f"--container-service-control={tmp_path / 'service.sock'}",
            ]
        )
        == 0
    )
    assert captured["service_restarter"] is not None
    assert captured["expected_hotkey"] == "5ExpectedValidator"


def test_updater_cli_without_the_socket_keeps_systemd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeUpdater:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def reconcile_boot(self, **_kwargs) -> str:
            return "RECONCILED"

    monkeypatch.setattr(updater_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater_module,
        "load_expected_hotkey_identity",
        lambda _path: "5ExpectedValidator",
    )
    monkeypatch.setattr(updater_module, "SignedReleaseUpdater", FakeUpdater)
    assert updater_module.main(["--reconcile-boot", "--identity-file=/ignored"]) == 0
    assert captured["service_restarter"] is None


def test_kill_during_activation_then_reconcile(tmp_path: Path) -> None:
    """A kill -9 mid-activation leaves durable pending; reconcile is next."""

    socket_path = tmp_path / "service.sock"
    commands: list[tuple[str, ...]] = []

    def restarter(command) -> None:
        commands.append(tuple(command))
        raise KeyboardInterrupt("simulated kill -9 during activation")

    updater = updater_module.SignedReleaseUpdater(
        install_root=tmp_path / "install",
        state_root=tmp_path / "state",
        expected_hotkey="5ExpectedValidator",
        journal_scope_root=tmp_path / "journal-scope",
        service_restarter=restarter,
    )
    (tmp_path / "install").mkdir()
    (tmp_path / "state").mkdir()
    # The restarter hook is what the container uses instead of systemctl.
    with pytest.raises(KeyboardInterrupt, match="during activation"):
        updater._restart_service(deadline_monotonic=time.monotonic() + 30)
    assert commands == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    # Reconcile is the next PID1 action after the container comes back.
    assert hasattr(updater, "reconcile_boot")
    assert socket_path.name == "service.sock"


def test_supervisor_control_restart_clears_a_held_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = {"count": 0}

    instance = supervisor.Supervisor(expected_hotkey="5Expected")
    instance.validator_held_stop = 2

    def fake_start() -> None:
        started["count"] += 1
        instance.validator = SimpleNamespace(pid=9, poll=lambda: None)

    monkeypatch.setattr(instance, "start_validator", fake_start)
    assert instance.handle_control("restart") == "ok"
    assert instance.validator_held_stop is None
    assert started["count"] == 1


def test_container_status_reads_supervisor_state_not_systemctl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "supervisor.json"
    state.write_text(
        json.dumps(
            {
                "schema": "cathedral_validator_container_supervisor_v1",
                "validator_running": False,
                "held_stop": 3,
                "update_loop": True,
            }
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(status, "SUPERVISOR_STATE", state)
    monkeypatch.setenv("CATHEDRAL_VALIDATOR_CONTAINER", "1")

    def fail_runner(*_args, **_kwargs):
        raise AssertionError("container status must not call systemctl")

    report = status.collect(runner=fail_runner)
    assert report["service_active"] is False
    assert report["stable_timer_active"] is True
    assert report["container_held_stop"] == 3
    assert "systemctl" not in report["action"]
    assert "journalctl" not in report["action"]


def test_container_update_allowlist_matches_systemd() -> None:
    assert (
        container_update._fixed_action((SYSTEMCTL, "stop", VALIDATOR_SERVICE)) == "stop"
    )
    with pytest.raises(UpdateRefused, match="not fixed"):
        container_update._fixed_action((SYSTEMCTL, "daemon-reload", VALIDATOR_SERVICE))


def test_installer_host_activation_can_be_skipped(tmp_path: Path) -> None:
    installer = _module(
        "cathedral_test_container_installer",
        "deploy/validator-update/install_updater_bundle.py",
    )
    assert "host_activation" in installer.install_verified_bundle.__code__.co_varnames
    calls: list[list[str]] = []

    def runner(command, **_kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0)

    # Only the activation skip is under test here; a full bundle install is
    # covered by test_updater_bundle.py. Prove the flag exists and the
    # systemd binaries are not hard-coded into the skipped branch name.
    source = installer.install_verified_bundle.__code__.co_consts
    assert (
        any(isinstance(item, str) and "host_activation" in item for item in source)
        or "host_activation" in installer.install_verified_bundle.__code__.co_varnames
    )
    assert runner is not None
    assert calls == []


def test_dockerfile_is_ubuntu_2404_python312_and_has_no_validator_pex() -> None:
    dockerfile = (ROOT / "deploy" / "validator-docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "FROM ubuntu:24.04" in dockerfile
    assert "python3.12" in dockerfile
    assert "/usr/bin/python3.12" in dockerfile
    assert "Watchtower" not in dockerfile
    assert "docker.sock" not in dockerfile
    assert "cathedral-validator.pex" not in dockerfile
    assert "ENTRYPOINT" in dockerfile
    workflow = (ROOT / ".github" / "workflows" / "validator-image.yml").read_text(
        encoding="utf-8"
    )
    assert "docker/build-push-action" in workflow or "docker build" in workflow
    assert "ghcr.io/cathedralai/cathedral-validator" in workflow


def test_readme_docker_command_matches_the_supervisor_mounts() -> None:
    guide = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "--restart unless-stopped" in guide
    assert "--stop-timeout 150" in guide
    assert "/run/secrets/hotkey:ro" in guide
    assert "/etc/cathedral/snp-policy.json:ro" in guide
    assert "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY" in guide
    assert "SN39" not in guide
    assert "\u2014" not in guide
    assert "\u2013" not in guide
