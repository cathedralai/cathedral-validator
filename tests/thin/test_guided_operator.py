from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from importlib.machinery import SourceFileLoader

import pytest


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


setup = _module(
    "cathedral_test_guided_setup", "deploy/validator-update/cathedral-validator-setup"
)
status = _module(
    "cathedral_test_guided_status", "deploy/validator-update/cathedral-validator-status"
)


HOTKEY = "5C4iA2und8WV6mbvTBYupm2eZwtxk3wCYUM2SFHXSyQuapGp"
OTHER_HOTKEY = "5CmWHcV2bCNFVRMMEMmiECmG3ULaLoGcLYufhZyrXV3VZoJe"
MEASUREMENT = "a" * 96
TCB = "0x0101000000000101"


def _write(path: Path, body: str | bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body.encode("ascii") if isinstance(body, str) else body)
    path.chmod(mode)
    return path


def _policy() -> bytes:
    return json.dumps(
        {
            "schema": "cathedral_amd_sev_snp_policy_v1",
            "generations": {
                "genoa": {
                    "allowed_measurements": [MEASUREMENT],
                    "minimum_tcb": TCB,
                }
            },
        },
        separators=(",", ":"),
    ).encode("ascii")


def _setup_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    etc = tmp_path / "etc" / "cathedral-validator"
    examples = tmp_path / "examples"
    systemd = tmp_path / "systemd"
    updater = _write(
        tmp_path / "bin" / "cathedral-validator-update", "#!/bin/sh\n", 0o700
    )
    runtime = _write(etc / "runtime-release-public-key.pem", "PUBLIC\n", 0o644)
    _write(
        examples / "direct.env.example",
        "CATHEDRAL_SNP_POLICY=/etc/cathedral-validator/snp-policy.json\n",
        0o644,
    )
    _write(
        examples / "update.env.example",
        "CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=https://example.invalid/canary.json\n"
        "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=https://example.invalid/stable.json\n"
        "CATHEDRAL_VALIDATOR_CANARY_MINIMUM_SEQUENCE=1\n"
        "CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=7\n",
        0o644,
    )
    for unit in (setup.DIRECT_UNIT, setup.STABLE_TIMER):
        _write(systemd / unit, "[Unit]\n", 0o644)
    monkeypatch.setattr(setup, "ETC", etc)
    monkeypatch.setattr(setup, "EXAMPLES", examples)
    monkeypatch.setattr(setup, "SYSTEMD", systemd)
    monkeypatch.setattr(setup, "UPDATER", updater)
    monkeypatch.setattr(setup, "RUNTIME_KEY", runtime)
    monkeypatch.setattr(setup, "INSTALL_ROOT", tmp_path / "opt" / "cathedral-validator")
    monkeypatch.setattr(
        setup,
        "UPDATER_STATE",
        tmp_path / "var" / "lib" / "cathedral-validator-update" / "state.json",
    )
    monkeypatch.setattr(setup, "BOOTSTRAP_OWNER", os.geteuid())
    monkeypatch.setattr(setup, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(setup, "ROOT_GID", os.getgid())
    monkeypatch.setattr(setup, "_operator_uids", lambda: {os.geteuid()})
    monkeypatch.setattr(setup, "_service_gid", lambda: os.getgid())
    monkeypatch.setattr(setup.os, "fchown", lambda _fd, _uid, _gid: None)
    hotkey = _write(
        tmp_path / "operator" / "hotkeys" / "validator",
        json.dumps({"ss58Address": HOTKEY}),
    )
    policy = _write(tmp_path / "operator" / "policy.json", _policy())
    return hotkey, policy


def _runner(calls: list[list[str]]):
    def run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    return run


def _setup_runner(calls: list[list[str]], *, direct_active: bool = True):
    active = direct_active

    def run(command, **_kwargs):
        nonlocal active
        calls.append(command)
        if command == [
            "/usr/bin/systemctl",
            "enable",
            "--now",
            setup.DIRECT_UNIT,
        ]:
            active = True
        if (
            len(command) > 2
            and command[1] == "is-active"
            and command[-1] == setup.DIRECT_UNIT
        ):
            return SimpleNamespace(returncode=0 if active else 3)
        if (
            len(command) > 2
            and command[1] in {"is-active", "is-enabled"}
            and command[-1] in setup.REFUSED_UNITS
        ):
            return SimpleNamespace(returncode=3)
        return SimpleNamespace(returncode=0)

    return run


def _make_current(root: Path) -> None:
    release = root / "releases" / ("b" * 64)
    release.mkdir(parents=True)
    root.mkdir(parents=True, exist_ok=True)
    (root / "current").symlink_to(release)


def _release_record() -> dict[str, object]:
    return {
        "sequence": 7,
        "archive_sha256": "b" * 64,
        "signed_sha256": "c" * 64,
        "metadata_sha256": "d" * 64,
    }


def _write_updater_state(*, channels: dict, pending: object) -> None:
    _write(
        setup.UPDATER_STATE,
        json.dumps(
            {
                "schema": "cathedral_validator_updater_state_v3",
                "selected_channel": "stable",
                "channels": channels,
                "pending": pending,
            },
            separators=(",", ":"),
        ),
    )


def test_setup_configures_only_stable_direct_validator(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []
    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=HOTKEY,
        snp_policy=policy,
        runner=_setup_runner(calls),
    )

    assert (setup.ETC / "validator-hotkey").read_bytes() == hotkey.read_bytes()
    assert stat.S_IMODE((setup.ETC / "validator-hotkey").stat().st_mode) == 0o600
    assert (
        setup.ETC / "identity.env"
    ).read_text() == f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={HOTKEY}\n"
    update = (setup.ETC / "update.env").read_text()
    assert "STABLE_METADATA_URL=https://example.invalid/stable.json" in update
    assert "CANARY" not in update
    flattened = " ".join(" ".join(command) for command in calls)
    assert "--bootstrap-first-install" in flattened
    assert "--channel=stable" in flattened
    assert "--minimum-sequence=7" in flattened
    assert "--channel=canary" not in flattened
    assert setup.DIRECT_UNIT in flattened
    assert setup.STABLE_TIMER in flattened
    assert [command for command in calls if command[1] == "enable"] == [
        ["/usr/bin/systemctl", "enable", "--now", setup.DIRECT_UNIT],
        ["/usr/bin/systemctl", "enable", "--now", setup.STABLE_TIMER],
    ]
    assert not any(
        command[:3] == ["/usr/bin/systemctl", "enable", "--now"]
        and command[-1] == "cathedral-validator-canary-update.timer"
        for command in calls
    )
    assert hotkey.read_text() not in flattened


def test_setup_is_idempotent_and_refuses_different_existing_configuration(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []
    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=HOTKEY,
        snp_policy=policy,
        runner=_setup_runner(calls),
    )
    _make_current(setup.INSTALL_ROOT)
    _write_updater_state(channels={"stable": _release_record()}, pending=None)
    calls.clear()
    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=HOTKEY,
        snp_policy=policy,
        runner=_setup_runner(calls),
    )
    assert not any(command[0] == str(setup.UPDATER) for command in calls)

    (setup.ETC / "identity.env").write_text(
        f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={OTHER_HOTKEY}\n"
    )
    with pytest.raises(setup.SetupRefused, match="differs"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )
    assert (setup.ETC / "identity.env").read_text().endswith(f"{OTHER_HOTKEY}\n")


def test_setup_rerun_refuses_stopped_writer_without_invoking_updater(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _make_current(setup.INSTALL_ROOT)
    _write_updater_state(channels={"stable": _release_record()}, pending=None)
    _write(
        setup.ETC / "setup-complete.json",
        setup._setup_completion_body(HOTKEY),
    )
    calls: list[list[str]] = []

    with pytest.raises(setup.SetupRefused, match="stopped and needs review"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner(calls, direct_active=False),
        )

    assert not any(command[0] == str(setup.UPDATER) for command in calls)
    assert not (setup.ETC / "validator-hotkey").exists()


def test_setup_resumes_committed_first_install_before_completion_marker(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _make_current(setup.INSTALL_ROOT)
    _write_updater_state(channels={"stable": _release_record()}, pending=None)
    calls: list[list[str]] = []

    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=HOTKEY,
        snp_policy=policy,
        runner=_setup_runner(calls, direct_active=False),
    )

    assert not any(command[0] == str(setup.UPDATER) for command in calls)
    assert [
        "/usr/bin/systemctl",
        "enable",
        "--now",
        setup.DIRECT_UNIT,
    ] in calls
    assert (setup.ETC / "setup-complete.json").read_bytes() == (
        setup._setup_completion_body(HOTKEY)
    )


def test_setup_recovers_interrupted_first_install_despite_current_symlink(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _make_current(setup.INSTALL_ROOT)
    record = _release_record()
    _write_updater_state(
        channels={},
        pending={
            "channel": "stable",
            "record": record,
            "previous_current": None,
            "target_current": f"releases/{record['archive_sha256']}",
            "stage": "may_have_run",
        },
    )
    calls: list[list[str]] = []

    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=HOTKEY,
        snp_policy=policy,
        runner=_setup_runner(calls),
    )

    updater_calls = [command for command in calls if command[0] == str(setup.UPDATER)]
    assert len(updater_calls) == 1
    assert "--bootstrap-first-install" in updater_calls[0]


def test_setup_refuses_non_stable_updater_state_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write(
        setup.UPDATER_STATE,
        '{"schema":"cathedral_validator_updater_state_v3",'
        '"selected_channel":"canary","channels":{},"pending":null}',
    )

    with pytest.raises(setup.SetupRefused, match="stable-only"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )

    assert not (setup.ETC / "validator-hotkey").exists()


def test_setup_refuses_bad_hotkey_or_policy_before_config_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write(hotkey, json.dumps({"ss58Address": OTHER_HOTKEY}))
    with pytest.raises(setup.SetupRefused, match="does not match"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )
    assert not (setup.ETC / "identity.env").exists()

    _write(hotkey, json.dumps({"ss58Address": HOTKEY}))
    _write(policy, b'{"schema":"cathedral_amd_sev_snp_policy_v1","generations":{}}')
    with pytest.raises(setup.SetupRefused, match="production shape"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_runner([]),
        )
    assert not (setup.ETC / "validator-hotkey").exists()


def test_setup_refuses_symlinked_operator_input(monkeypatch, tmp_path: Path) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    link = hotkey.parent / "key-link"
    link.symlink_to(hotkey)
    with pytest.raises(setup.SetupRefused, match="non-symlink"):
        setup.configure(
            hotkey_file=link,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )


def test_setup_refuses_symlinked_hotkeys_directory_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    _hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    coldkeys = tmp_path / "operator" / "coldkeys"
    copied = _write(coldkeys / "validator", json.dumps({"ss58Address": HOTKEY}))
    wallet = tmp_path / "second-wallet"
    wallet.mkdir()
    (wallet / "hotkeys").symlink_to(coldkeys, target_is_directory=True)

    with pytest.raises(setup.SetupRefused, match="hotkey file is unavailable"):
        setup.configure(
            hotkey_file=wallet / "hotkeys" / copied.name,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )

    assert not (setup.ETC / "validator-hotkey").exists()


def test_setup_refuses_coldkey_and_conflicting_writer_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    coldkey = tmp_path / "operator" / "coldkeys" / "validator"
    _write(coldkey, hotkey.read_bytes())
    with pytest.raises(setup.SetupRefused, match="hotkeys directory"):
        setup.configure(
            hotkey_file=coldkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=_setup_runner([]),
        )

    def conflicting(command, **_kwargs):
        if command[-1] == "cathedral-validator-sn39-relay.service":
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=3)

    with pytest.raises(setup.SetupRefused, match="conflicting"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=HOTKEY,
            snp_policy=policy,
            runner=conflicting,
        )
    assert not (setup.ETC / "identity.env").exists()


@pytest.mark.parametrize(
    "invalid",
    [
        "0" + HOTKEY[1:],
        HOTKEY[:-1] + ("1" if HOTKEY[-1] != "1" else "2"),
        "5short",
    ],
)
def test_setup_refuses_invalid_ss58_before_mutation(
    monkeypatch, tmp_path: Path, invalid: str
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write(hotkey, json.dumps({"ss58Address": invalid}))
    with pytest.raises(setup.SetupRefused, match="public SS58"):
        setup.configure(
            hotkey_file=hotkey,
            expected_hotkey=invalid,
            snp_policy=policy,
            runner=_setup_runner([]),
        )
    assert not (setup.ETC / "identity.env").exists()


def test_setup_surfaces_only_sanitized_updater_refusal() -> None:
    command = [str(setup.UPDATER), "--channel=stable"]

    def refused(_command, **_kwargs):
        raise subprocess.CalledProcessError(
            2,
            command,
            output="ignored output\n",
            stderr=(
                "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: "
                "release is below the trusted bootstrap sequence\n"
            ),
        )

    with pytest.raises(
        setup.SetupRefused, match="release is below the trusted bootstrap sequence"
    ):
        setup._run_checked(refused, command, "first signed install")

    def unsafe(_command, **_kwargs):
        raise subprocess.CalledProcessError(
            2,
            command,
            stderr="CATHEDRAL_VALIDATOR_UPDATE_REFUSED: bad\nsecond line\x00secret\n",
        )

    with pytest.raises(setup.SetupRefused, match="refused: bad$"):
        setup._run_checked(unsafe, command, "first signed install")


def test_install_once_removes_hotkey_temporary_after_write_failure(
    monkeypatch, tmp_path: Path
) -> None:
    destination = tmp_path / "validator-hotkey"
    monkeypatch.setattr(setup, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(
        setup.os, "write", lambda *_args: (_ for _ in ()).throw(OSError())
    )

    with pytest.raises(setup.SetupRefused, match="cannot create"):
        setup._install_once(destination, b"secret", mode=0o600, gid=os.getgid())

    assert list(tmp_path.iterdir()) == []


def _status_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    etc = tmp_path / "etc" / "cathedral-validator"
    install = tmp_path / "opt" / "cathedral-validator"
    state = tmp_path / "var" / "lib" / "cathedral-validator-update" / "state.json"
    scope = (
        tmp_path
        / "var"
        / "lib"
        / "cathedral-validator"
        / ".local"
        / "state"
        / "cathedral-validator"
        / "direct-writer"
        / "finney-sn39-mechanism-0"
    )
    monkeypatch.setattr(status, "ETC", etc)
    monkeypatch.setattr(status, "INSTALL_ROOT", install)
    monkeypatch.setattr(status, "UPDATER_STATE", state)
    monkeypatch.setattr(status, "DIRECT_SCOPE", scope)
    monkeypatch.setattr(status, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(
        status.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=os.geteuid())
    )
    _write(etc / "identity.env", f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={HOTKEY}\n")
    _write(
        state,
        json.dumps(
            {
                "schema": "cathedral_validator_updater_state_v3",
                "selected_channel": "stable",
                "channels": {
                    "stable": {
                        "sequence": 7,
                        "archive_sha256": "b" * 64,
                        "signed_sha256": "c" * 64,
                        "metadata_sha256": "d" * 64,
                    }
                },
                "pending": None,
            }
        ),
    )
    _write(
        scope / HOTKEY / "state.json",
        json.dumps(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": None,
                "last_attempt": {
                    "status": "CONFIRMED",
                    "receipt": {"block_number": 123},
                },
            }
        ),
    )
    _make_current(install)


def test_status_reports_sanitized_local_confirmed_state(
    monkeypatch, tmp_path: Path
) -> None:
    _status_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []
    report = status.collect(runner=_runner(calls))
    assert report["result"] == "OPERATING_CONFIRMED"
    assert report["direct"]["pending"] is False
    assert report["direct"]["last_result"] == "CONFIRMED"
    assert report["direct"]["block_number"] == 123
    assert report["direct"]["recorded_age_seconds"] <= 2
    assert HOTKEY not in json.dumps(report)
    assert all("validator-hotkey" not in " ".join(command) for command in calls)


def test_status_fails_closed_for_pending_or_unreadable_state(
    monkeypatch, tmp_path: Path
) -> None:
    _status_paths(monkeypatch, tmp_path)
    journal = status.DIRECT_SCOPE / HOTKEY / "state.json"
    _write(
        journal,
        json.dumps(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": {},
                "last_attempt": None,
            }
        ),
    )
    assert status.collect(runner=_runner([]))["result"] == "NOT_PROVEN"

    journal.write_text("not-json")
    report = status.collect(runner=_runner([]))
    assert report["result"] == "NOT_PROVEN"
    assert "not-json" not in json.dumps(report)


def test_status_never_reads_hotkey_file(monkeypatch, tmp_path: Path) -> None:
    _status_paths(monkeypatch, tmp_path)
    observed: list[Path] = []
    original = status._read_controlled_file

    def recording(path: Path, **kwargs):
        observed.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(status, "_read_controlled_file", recording)
    status.collect(runner=_runner([]))
    assert all(path.name != "validator-hotkey" for path in observed)


def test_status_confirmation_freshness_boundary(monkeypatch, tmp_path: Path) -> None:
    _status_paths(monkeypatch, tmp_path)
    journal = status.DIRECT_SCOPE / HOTKEY / "state.json"
    recorded = 1_700_000_000
    os.utime(journal, (recorded, recorded))

    monkeypatch.setattr(
        status.time, "time", lambda: recorded + status.MAX_CONFIRMED_AGE_SECONDS
    )
    assert status.collect(runner=_runner([]))["result"] == "OPERATING_CONFIRMED"

    monkeypatch.setattr(
        status.time, "time", lambda: recorded + status.MAX_CONFIRMED_AGE_SECONDS + 1
    )
    assert status.collect(runner=_runner([]))["result"] == "NOT_PROVEN"
