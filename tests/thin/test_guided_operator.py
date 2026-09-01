from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from importlib.machinery import SourceFileLoader

import pytest
from bittensor_wallet import Keyfile, Keypair


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


# Disposable keypairs for this test session only. The hotkey fixture is written
# by the pinned bittensor-wallet keyfile writer so the guided setup is tested
# against the exact file shape btcli produces rather than a hand-typed guess.
_HOTKEY_PAIR = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
_OTHER_PAIR = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
HOTKEY = _HOTKEY_PAIR.ss58_address
OTHER_HOTKEY = _OTHER_PAIR.ss58_address
MEASUREMENT = "a" * 96
TCB = "0x0101000000000101"
STABLE_METADATA_SHA256 = "e" * 64
STABLE_DIGEST_LINE = (
    f"CATHEDRAL_VALIDATOR_STABLE_METADATA_SHA256={STABLE_METADATA_SHA256}\n"
)
UPDATE_EXAMPLE = (
    "CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=https://example.invalid/canary.json\n"
    "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=https://example.invalid/stable.json\n"
    "CATHEDRAL_VALIDATOR_CANARY_MINIMUM_SEQUENCE=1\n"
    "CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=7\n" + STABLE_DIGEST_LINE
)
ENABLE_DIRECT = ["/usr/bin/systemctl", "enable", setup.DIRECT_UNIT]
ENABLE_TIMER = ["/usr/bin/systemctl", "enable", "--now", setup.STABLE_TIMER]


def _write(path: Path, body: str | bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body.encode("ascii") if isinstance(body, str) else body)
    path.chmod(mode)
    return path


def _write_hotkey(
    path: Path,
    keypair: Keypair = _HOTKEY_PAIR,
    *,
    encrypt: bool = False,
    password: str | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.unlink()
    Keyfile(str(path)).set_keypair(
        keypair, encrypt=encrypt, overwrite=True, password=password
    )
    path.chmod(0o600)
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
    _write(examples / "update.env.example", UPDATE_EXAMPLE, 0o644)
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
    hotkey = _write_hotkey(tmp_path / "operator" / "hotkeys" / "validator")
    policy = _write(tmp_path / "operator" / "policy.json", _policy())
    return hotkey, policy


def _runner(calls: list[list[str]]):
    def run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    return run


def _setup_runner(
    calls: list[list[str]],
    *,
    direct_active: bool = False,
    updater_starts_writer: bool = True,
    writer_stops_after_timer_enable: bool = False,
):
    """Model systemd as the guided setup observes it.

    The direct writer becomes active only when the first-install updater
    starts it, or when a test explicitly models an already running committed
    installation. ``systemctl enable --now`` on the direct unit is modelled as
    a start too, so a regression toward that unsafe restart shows up in the
    recorded calls instead of hiding behind a passing readiness check.
    """

    active = direct_active

    def returncode_for(command: list[str]) -> int:
        if (
            len(command) > 2
            and command[1] == "is-active"
            and command[-1] == setup.DIRECT_UNIT
        ):
            return 0 if active else 3
        if (
            len(command) > 2
            and command[1] in {"is-active", "is-enabled"}
            and command[-1] in setup.REFUSED_UNITS
        ):
            return 3
        return 0

    def run(command, **kwargs):
        nonlocal active
        calls.append(command)
        if command[0] == str(setup.UPDATER) and updater_starts_writer:
            active = True
        if (
            command[:3] == ["/usr/bin/systemctl", "enable", "--now"]
            and command[-1] == setup.DIRECT_UNIT
        ):
            active = True
        if writer_stops_after_timer_enable and command == ENABLE_TIMER:
            active = False
        returncode = returncode_for(command)
        # Like subprocess.run, a checked call with a non-zero exit raises, so
        # the readiness checks in setup are really exercised.
        if kwargs.get("check") and returncode != 0:
            raise subprocess.CalledProcessError(returncode, command)
        return SimpleNamespace(returncode=returncode)

    return run


def _configure(hotkey: Path, policy: Path, runner, *, expected: str = HOTKEY) -> None:
    setup.configure(
        hotkey_file=hotkey,
        expected_hotkey=expected,
        snp_policy=policy,
        runner=runner,
    )


def _updater_calls(calls: list[list[str]]) -> list[list[str]]:
    return [command for command in calls if command[0] == str(setup.UPDATER)]


def _enable_calls(calls: list[list[str]]) -> list[list[str]]:
    return [
        command for command in calls if command[:2] == ["/usr/bin/systemctl", "enable"]
    ]


def _writer_start_calls(calls: list[list[str]]) -> list[list[str]]:
    return [
        command
        for command in calls
        if command[0] == "/usr/bin/systemctl"
        and command[-1] == setup.DIRECT_UNIT
        and (command[1] in {"start", "restart"} or "--now" in command)
    ]


def _assert_no_configuration_written() -> None:
    assert not (setup.ETC / "validator-hotkey").exists()
    assert not (setup.ETC / "identity.env").exists()
    assert not (setup.ETC / "setup-complete.json").exists()


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


def _committed_install() -> None:
    _make_current(setup.INSTALL_ROOT)
    _write_updater_state(channels={"stable": _release_record()}, pending=None)


def test_setup_configures_only_stable_direct_validator(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []
    _configure(hotkey, policy, _setup_runner(calls))

    assert (setup.ETC / "validator-hotkey").read_bytes() == hotkey.read_bytes()
    assert stat.S_IMODE((setup.ETC / "validator-hotkey").stat().st_mode) == 0o600
    assert (
        setup.ETC / "identity.env"
    ).read_text() == f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={HOTKEY}\n"
    update = (setup.ETC / "update.env").read_text()
    assert "STABLE_METADATA_URL=https://example.invalid/stable.json" in update
    assert "STABLE_MINIMUM_SEQUENCE=7" in update
    assert "CANARY" not in update
    updater_calls = _updater_calls(calls)
    assert len(updater_calls) == 1
    assert "--bootstrap-first-install" in updater_calls[0]
    assert "--channel=stable" in updater_calls[0]
    assert "--minimum-sequence=7" in updater_calls[0]
    assert (
        f"--first-install-metadata-sha256={STABLE_METADATA_SHA256}" in updater_calls[0]
    )
    flattened = " ".join(" ".join(command) for command in calls)
    assert "--channel=canary" not in flattened
    assert not any(
        command[1] == "enable" and "canary" in command[-1] for command in calls
    )
    # The updater started the writer; setup only records the boot dependency.
    assert _enable_calls(calls) == [ENABLE_DIRECT, ENABLE_TIMER]
    assert _writer_start_calls(calls) == []
    assert (setup.ETC / "setup-complete.json").read_bytes() == (
        setup._setup_completion_body(HOTKEY)
    )
    assert hotkey.read_text() not in flattened
    document = json.loads(hotkey.read_bytes())
    assert document["privateKey"] not in flattened
    assert document["secretSeed"] not in flattened


def test_setup_is_idempotent_and_refuses_different_existing_configuration(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []
    _configure(hotkey, policy, _setup_runner(calls))
    _committed_install()
    calls.clear()
    _configure(hotkey, policy, _setup_runner(calls, direct_active=True))
    assert _updater_calls(calls) == []
    assert _enable_calls(calls) == [ENABLE_DIRECT, ENABLE_TIMER]
    assert _writer_start_calls(calls) == []

    (setup.ETC / "identity.env").write_text(
        f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={OTHER_HOTKEY}\n"
    )
    with pytest.raises(setup.SetupRefused, match="differs"):
        _configure(hotkey, policy, _setup_runner([], direct_active=True))
    assert (setup.ETC / "identity.env").read_text().endswith(f"{OTHER_HOTKEY}\n")


@pytest.mark.parametrize(
    "marker_present",
    [True, False],
    ids=["completed-install-stopped", "interrupted-before-marker"],
)
def test_setup_rerun_refuses_inactive_committed_writer_before_mutation(
    monkeypatch, tmp_path: Path, marker_present: bool
) -> None:
    """A committed installation whose writer is not running fails closed.

    Setup cannot tell a reboot, an operator stop, and a contradiction stop
    that ``RestartPreventExitStatus=2`` keeps stopped apart. None of them may
    be cleared by starting the writer, and the completion marker changes
    nothing: the first-install updater starts the writer before it returns,
    so an absent marker only proves setup was interrupted afterwards.
    """

    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _committed_install()
    marker = setup.ETC / "setup-complete.json"
    if marker_present:
        _write(marker, setup._setup_completion_body(HOTKEY))
    calls: list[list[str]] = []

    with pytest.raises(setup.SetupRefused, match="stopped and needs review"):
        _configure(hotkey, policy, _setup_runner(calls, direct_active=False))

    assert _updater_calls(calls) == []
    assert _enable_calls(calls) == []
    assert _writer_start_calls(calls) == []
    assert not (setup.ETC / "validator-hotkey").exists()
    assert not (setup.ETC / "identity.env").exists()
    assert marker.exists() is marker_present


def test_setup_finishes_interrupted_enablement_only_while_writer_is_active(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _committed_install()
    calls: list[list[str]] = []

    _configure(hotkey, policy, _setup_runner(calls, direct_active=True))

    assert _updater_calls(calls) == []
    assert _enable_calls(calls) == [ENABLE_DIRECT, ENABLE_TIMER]
    assert _writer_start_calls(calls) == []
    assert (setup.ETC / "setup-complete.json").read_bytes() == (
        setup._setup_completion_body(HOTKEY)
    )


@pytest.mark.parametrize(
    "committed",
    [False, True],
    ids=["first-install", "committed-rerun"],
)
def test_setup_writes_no_completion_marker_when_writer_stops_before_readiness(
    monkeypatch, tmp_path: Path, committed: bool
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    if committed:
        _committed_install()
    calls: list[list[str]] = []

    with pytest.raises(setup.SetupRefused, match="direct service readiness failed"):
        _configure(
            hotkey,
            policy,
            _setup_runner(
                calls,
                direct_active=committed,
                writer_stops_after_timer_enable=True,
            ),
        )

    assert len(_updater_calls(calls)) == (0 if committed else 1)
    assert _writer_start_calls(calls) == []
    assert not (setup.ETC / "setup-complete.json").exists()

    # The rerun sees a committed installation with a stopped writer and
    # refuses rather than restarting it.
    if not committed:
        _committed_install()
    with pytest.raises(setup.SetupRefused, match="stopped and needs review"):
        _configure(hotkey, policy, _setup_runner([], direct_active=False))
    assert not (setup.ETC / "setup-complete.json").exists()


def test_setup_first_install_failure_leaves_no_marker_and_no_writer_start(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    calls: list[list[str]] = []

    def refuse_first_install(command, **_kwargs):
        calls.append(command)
        if command[0] == str(setup.UPDATER):
            raise subprocess.CalledProcessError(
                2,
                command,
                stderr=(
                    "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: first release failed "
                    "readiness and was deactivated\n"
                ),
            )
        return SimpleNamespace(returncode=3)

    with pytest.raises(setup.SetupRefused, match="failed readiness and was"):
        _configure(hotkey, policy, refuse_first_install)

    assert _enable_calls(calls) == []
    assert _writer_start_calls(calls) == []
    assert not (setup.ETC / "setup-complete.json").exists()


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

    _configure(hotkey, policy, _setup_runner(calls))

    updater_calls = _updater_calls(calls)
    assert len(updater_calls) == 1
    assert "--bootstrap-first-install" in updater_calls[0]
    assert (
        f"--first-install-metadata-sha256={STABLE_METADATA_SHA256}" in updater_calls[0]
    )
    assert _writer_start_calls(calls) == []


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
        _configure(hotkey, policy, _setup_runner([]))

    _assert_no_configuration_written()


def test_setup_refuses_signed_example_without_stable_metadata_digest(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write(
        setup.EXAMPLES / "update.env.example",
        UPDATE_EXAMPLE.replace(STABLE_DIGEST_LINE, ""),
        0o644,
    )
    calls: list[list[str]] = []

    with pytest.raises(setup.SetupRefused, match="stable metadata digest is invalid"):
        _configure(hotkey, policy, _setup_runner(calls))

    assert _updater_calls(calls) == []
    _assert_no_configuration_written()


def test_setup_refuses_bad_hotkey_or_policy_before_config_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write_hotkey(hotkey, _OTHER_PAIR)
    with pytest.raises(setup.SetupRefused, match="does not match"):
        _configure(hotkey, policy, _setup_runner([]))
    _assert_no_configuration_written()

    _write_hotkey(hotkey)
    _write(policy, b'{"schema":"cathedral_amd_sev_snp_policy_v1","generations":{}}')
    with pytest.raises(setup.SetupRefused, match="production shape"):
        _configure(hotkey, policy, _runner([]))
    _assert_no_configuration_written()


def test_setup_refuses_group_or_world_readable_hotkey_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    hotkey.chmod(0o644)

    with pytest.raises(setup.SetupRefused, match="readable only by its owner"):
        _configure(hotkey, policy, _setup_runner([]))

    _assert_no_configuration_written()
    hotkey.chmod(0o640)
    with pytest.raises(setup.SetupRefused, match="readable only by its owner"):
        _configure(hotkey, policy, _setup_runner([]))
    _assert_no_configuration_written()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda doc: {"ss58Address": doc["ss58Address"]}, "no signing secret"),
        (
            lambda doc: {**doc, "publicKey": "0x" + "00" * 32},
            "publicKey does not match its SS58 address",
        ),
        (
            lambda doc: {**doc, "accountId": "0x" + "ff" * 32},
            "accountId does not match its SS58 address",
        ),
        (
            lambda doc: {**doc, "unexpected": "field"},
            "not an unencrypted Bittensor keyfile",
        ),
        (lambda doc: [doc], "not an unencrypted Bittensor keyfile"),
        (lambda doc: {**doc, "secretSeed": "0x12"}, "secretSeed is malformed"),
        (
            lambda doc: {**doc, "privateKey": doc["privateKey"][:-2]},
            "privateKey is malformed",
        ),
        (lambda doc: {**doc, "secretPhrase": ""}, "secretPhrase is malformed"),
        (
            lambda doc: {**doc, "ss58Address": "5short"},
            "no valid public SS58 address",
        ),
        (lambda doc: {**doc, "cryptoType": 0}, "cryptoType is not sr25519"),
        (lambda doc: {**doc, "cryptoType": 2}, "cryptoType is not sr25519"),
        (lambda doc: {**doc, "cryptoType": "1"}, "cryptoType is not sr25519"),
        (lambda doc: {**doc, "cryptoType": True}, "cryptoType is not sr25519"),
        (lambda doc: {**doc, "cryptoType": 1.0}, "cryptoType is not sr25519"),
    ],
    ids=[
        "public-only",
        "public-key-mismatch",
        "account-id-mismatch",
        "unknown-field",
        "not-an-object",
        "malformed-seed",
        "malformed-private-key",
        "empty-phrase",
        "invalid-ss58",
        "ed25519-crypto-type",
        "ecdsa-crypto-type",
        "string-crypto-type",
        "bool-crypto-type",
        "float-crypto-type",
    ],
)
def test_setup_refuses_unusable_hotkey_shapes_before_mutation(
    monkeypatch, tmp_path: Path, mutate, message: str
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    document = json.loads(hotkey.read_bytes())
    assert set(document) <= setup._HOTKEY_FIELDS
    _write(hotkey, json.dumps(mutate(document)))
    calls: list[list[str]] = []

    with pytest.raises(setup.SetupRefused, match=message):
        _configure(hotkey, policy, _setup_runner(calls))

    assert calls == []
    _assert_no_configuration_written()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: {key: value for key, value in doc.items() if key != "cryptoType"},
        lambda doc: {**doc, "cryptoType": 1},
        lambda doc: {**doc, "secretPhrase": None, "secretSeed": None},
        lambda doc: {
            "privateKey": doc["privateKey"],
            "ss58Address": doc["ss58Address"],
        },
        lambda doc: {
            "secretSeed": doc["secretSeed"],
            "ss58Address": doc["ss58Address"],
        },
    ],
    ids=[
        "without-crypto-type",
        "sr25519-crypto-type",
        "null-phrase-and-seed",
        "private-key-only",
        "seed-only",
    ],
)
def test_setup_accepts_every_signing_capable_btcli_keyfile_shape(
    monkeypatch, tmp_path: Path, mutate
) -> None:
    """Older and newer bittensor-wallet writers differ only in optional fields."""

    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    document = json.loads(hotkey.read_bytes())
    body = json.dumps(mutate(document))
    _write(hotkey, body)
    calls: list[list[str]] = []

    _configure(hotkey, policy, _setup_runner(calls))

    assert (setup.ETC / "validator-hotkey").read_text() == body
    assert len(_updater_calls(calls)) == 1


@pytest.mark.parametrize(
    "body",
    [
        b"$NACL\x00\xffnot-a-real-secret-box",
        b"$ANSIBLE_VAULT;1.1;AES256\n3030\n",
        b"gAAAAABlegacy-fernet-token",
        b"not json at all",
    ],
    ids=["nacl-malformed", "ansible-vault", "legacy-fernet", "not-json"],
)
def test_setup_refuses_encrypted_or_unparseable_hotkey_before_mutation(
    monkeypatch, tmp_path: Path, body: bytes
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write(hotkey, body)

    with pytest.raises(setup.SetupRefused, match="encrypted|unencrypted Bittensor"):
        _configure(hotkey, policy, _setup_runner([]))

    _assert_no_configuration_written()


def test_setup_refuses_a_validly_encrypted_hotkey_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    _write_hotkey(hotkey, encrypt=True, password="disposable-password")
    assert hotkey.read_bytes().startswith(b"$NACL")

    with pytest.raises(
        setup.SetupRefused,
        match="encrypted; the unattended validator service cannot decrypt it",
    ):
        _configure(hotkey, policy, _setup_runner([]))

    _assert_no_configuration_written()


def test_setup_refuses_symlinked_operator_input(monkeypatch, tmp_path: Path) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    link = hotkey.parent / "key-link"
    link.symlink_to(hotkey)
    with pytest.raises(setup.SetupRefused, match="non-symlink"):
        _configure(link, policy, _setup_runner([]))


def test_setup_refuses_symlinked_hotkeys_directory_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    coldkeys = tmp_path / "operator" / "coldkeys"
    copied = _write(coldkeys / "validator", hotkey.read_bytes())
    wallet = tmp_path / "second-wallet"
    wallet.mkdir()
    (wallet / "hotkeys").symlink_to(coldkeys, target_is_directory=True)

    with pytest.raises(setup.SetupRefused, match="hotkey file is unavailable"):
        _configure(wallet / "hotkeys" / copied.name, policy, _setup_runner([]))

    _assert_no_configuration_written()


def test_setup_refuses_coldkey_and_conflicting_writer_before_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    hotkey, policy = _setup_paths(monkeypatch, tmp_path)
    coldkey = tmp_path / "operator" / "coldkeys" / "validator"
    _write(coldkey, hotkey.read_bytes())
    with pytest.raises(setup.SetupRefused, match="hotkeys directory"):
        _configure(coldkey, policy, _setup_runner([]))

    def conflicting(command, **_kwargs):
        if command[-1] == "cathedral-validator-sn39-relay.service":
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=3)

    with pytest.raises(setup.SetupRefused, match="conflicting"):
        _configure(hotkey, policy, conflicting)
    _assert_no_configuration_written()


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
        _configure(hotkey, policy, _setup_runner([]), expected=invalid)
    _assert_no_configuration_written()


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
    kwargs = {
        "netuid": 39,
        "mecid": 0,
        "dests": [41],
        "weights": [65535],
        "version_key": 10005000,
    }
    identity = {
        "schema": "cathedral_direct_validator_plan_v1",
        "anchor": {
            "block_number": 120,
            "block_hash": "0x" + "a" * 64,
            "validator": {"uid": 30, "hotkey": HOTKEY},
            "miners": [],
        },
        "qvl_digest": "b" * 64,
        "evidence_digest": "sha256:" + "c" * 64,
        "machine_ids_by_uid": [],
        "raw_scores": [],
        "uid_hotkeys": [],
        "burn_uid": None,
        "burn_weight": 0,
        "call": "SubtensorModule.set_mechanism_weights",
        "kwargs": kwargs,
    }
    intent = {
        "extrinsic_hash": "0x" + "d" * 64,
        "validator_hotkey": HOTKEY,
        "nonce": 7,
        "era_reference_block": 120,
        "mortal_period_blocks": 16,
        "kwargs": kwargs,
        "eligibility": {},
    }
    attempt_body = (
        json.dumps(
            {"identity": identity, "intent": intent},
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    attempt_id = "sha256:" + hashlib.sha256(attempt_body).hexdigest()
    block_hash = "0x" + "e" * 64
    last_attempt = {
        "attempt_id": attempt_id,
        "status": "CONFIRMED",
        "identity": identity,
        "intent": intent,
        "receipt": {
            "status": "CONFIRMED",
            "attempt_id": attempt_id,
            "extrinsic_hash": intent["extrinsic_hash"],
            "block_hash": block_hash,
            "block_number": 123,
            "recovered": False,
            "confirmation_heads": [
                [123, block_hash],
                [124, "0x" + "f" * 64],
                [125, "0x" + "1" * 64],
            ],
        },
    }
    _write(
        scope / HOTKEY / "state.json",
        json.dumps(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": None,
                "last_attempt": last_attempt,
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


@pytest.mark.parametrize(
    "mutation",
    (
        lambda last: {"status": "CONFIRMED"},
        lambda last: {**last, "status": []},
        lambda last: {**last, "receipt": {"status": "CONFIRMED"}},
        lambda last: {
            **last,
            "receipt": {**last["receipt"], "attempt_id": "sha256:" + "0" * 64},
        },
        lambda last: {
            **last,
            "receipt": {**last["receipt"], "confirmation_heads": []},
        },
    ),
)
def test_status_requires_complete_bound_confirmation_record(
    monkeypatch, tmp_path: Path, mutation
) -> None:
    _status_paths(monkeypatch, tmp_path)
    journal = status.DIRECT_SCOPE / HOTKEY / "state.json"
    document = json.loads(journal.read_text())
    document["last_attempt"] = mutation(document["last_attempt"])
    journal.write_text(json.dumps(document))

    report = status.collect(runner=_runner([]))

    assert report["result"] == "NOT_PROVEN"
    assert "extrinsic_hash" not in json.dumps(report)
    assert HOTKEY not in json.dumps(report)


def test_status_accepts_complete_recovered_confirmation(
    monkeypatch, tmp_path: Path
) -> None:
    _status_paths(monkeypatch, tmp_path)
    journal = status.DIRECT_SCOPE / HOTKEY / "state.json"
    document = json.loads(journal.read_text())
    last = document["last_attempt"]
    last["status"] = "RECOVERED_CONFIRMED"
    last["receipt"]["status"] = "RECOVERED_CONFIRMED"
    last["receipt"]["recovered"] = True
    journal.write_text(json.dumps(document))

    report = status.collect(runner=_runner([]))

    assert report["result"] == "OPERATING_CONFIRMED"
    assert report["direct"]["last_result"] == "RECOVERED_CONFIRMED"
    assert report["direct"]["block_number"] == 123


def test_status_accepts_complete_expiry_without_reporting_success(
    monkeypatch, tmp_path: Path
) -> None:
    _status_paths(monkeypatch, tmp_path)
    journal = status.DIRECT_SCOPE / HOTKEY / "state.json"
    document = json.loads(journal.read_text())
    last = document["last_attempt"]
    last["status"] = "EXPIRED_WITHOUT_INCLUSION"
    last["receipt"].update(
        {
            "status": "EXPIRED_WITHOUT_INCLUSION",
            "block_hash": None,
            "block_number": None,
            "recovered": True,
            "confirmation_heads": [],
        }
    )
    journal.write_text(json.dumps(document))

    report = status.collect(runner=_runner([]))

    assert report["result"] == "NOT_PROVEN"
    assert report["direct"]["last_result"] == "EXPIRED_WITHOUT_INCLUSION"
    assert report["direct"]["block_number"] is None


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
