"""The updater and status tool find the writer's journal from direct.env.

The netuid is deploy-time configuration: direct.env assigns it, and every tool
that locates the writer's journal and cycle lock reads it from there instead
of a compiled value. No test here writes out a subnet number.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import NETUID
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import telemetry_exporter
from cathedral_thin.independent_runtime import updater as updater_module
from cathedral_thin.independent_runtime.direct_writer import direct_state_scope
from cathedral_thin.independent_runtime.updater import (
    DIRECT_WRITER_STATE_ROOT,
    UpdateRefused,
    direct_journal_scope_root,
    load_direct_netuid,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "deploy/validator-update/direct.env.example"
OTHER_NETUID = NETUID + 1


def _status_module():
    name = "cathedral_test_netuid_config_status"
    path = ROOT / "deploy/validator-update/cathedral-validator-status"
    spec = importlib.util.spec_from_file_location(
        name, path, loader=SourceFileLoader(name, str(path))
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


status = _status_module()


def _direct_env(tmp_path: Path, body: str | bytes, mode: int = 0o600) -> Path:
    path = tmp_path / "direct.env"
    path.write_bytes(body.encode("ascii") if isinstance(body, str) else body)
    path.chmod(mode)
    return path


def _with_netuid(netuid: int) -> str:
    return "".join(
        f"CATHEDRAL_VALIDATOR_NETUID={netuid}\n"
        if line.startswith("CATHEDRAL_VALIDATOR_NETUID=")
        else line + "\n"
        for line in EXAMPLE.read_text("ascii").splitlines()
    )


@pytest.mark.parametrize("netuid", [NETUID, OTHER_NETUID])
def test_updater_reads_the_configured_netuid_and_scopes_the_journal_by_it(
    tmp_path, netuid
):
    path = _direct_env(tmp_path, _with_netuid(netuid))

    assert load_direct_netuid(path, expected_uid=os.geteuid()) == netuid
    assert direct_journal_scope_root(netuid) == (
        DIRECT_WRITER_STATE_ROOT / direct_state_scope(netuid)
    )


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("CATHEDRAL_SNP_POLICY=/etc/x\n", "exactly once"),
        (f"CATHEDRAL_VALIDATOR_NETUID={NETUID}\n" * 2, "exactly once"),
        ("CATHEDRAL_VALIDATOR_NETUID=\n", "canonical decimal"),
        (f"CATHEDRAL_VALIDATOR_NETUID=0{NETUID}\n", "canonical decimal"),
        (f"CATHEDRAL_VALIDATOR_NETUID=+{NETUID}\n", "canonical decimal"),
        (f"CATHEDRAL_VALIDATOR_NETUID={NETUID}.0\n", "canonical decimal"),
        (f"CATHEDRAL_VALIDATOR_NETUID= {NETUID}\n", "canonical decimal"),
        ("CATHEDRAL_VALIDATOR_NETUID=65536\n", "canonical decimal"),
        ("CATHEDRAL_VALIDATOR_NETUID=\N{ARABIC-INDIC DIGIT FOUR}\n", "not ASCII"),
    ],
    ids=[
        "missing",
        "repeated",
        "empty",
        "leading-zero",
        "plus",
        "decimal-point",
        "leading-space",
        "past-u16",
        "non-ascii-digit",
    ],
)
def test_updater_refuses_a_missing_or_malformed_netuid(tmp_path, body, message):
    path = _direct_env(tmp_path, body.encode("utf-8"))

    with pytest.raises(UpdateRefused, match=message):
        load_direct_netuid(path, expected_uid=os.geteuid())


def test_updater_refuses_direct_env_it_does_not_control(tmp_path):
    path = _direct_env(tmp_path, _with_netuid(NETUID), mode=0o640)
    with pytest.raises(UpdateRefused, match="not root-controlled"):
        load_direct_netuid(path, expected_uid=os.geteuid())

    path.chmod(0o600)
    with pytest.raises(UpdateRefused, match="not root-controlled"):
        load_direct_netuid(path, expected_uid=os.geteuid() + 1)

    link = tmp_path / "link.env"
    link.symlink_to(path)
    with pytest.raises(UpdateRefused, match="path is invalid"):
        load_direct_netuid(link, expected_uid=os.geteuid())
    with pytest.raises(UpdateRefused, match="unavailable"):
        load_direct_netuid(tmp_path / "absent.env", expected_uid=os.geteuid())


@pytest.mark.parametrize("value", [True, -1, 1 << 16, "7", 7.0, None])
def test_journal_scope_refuses_a_value_that_is_not_a_netuid(value):
    with pytest.raises(UpdateRefused, match="netuid is invalid"):
        direct_journal_scope_root(value)


def test_updater_cli_locks_the_journal_of_the_configured_netuid(monkeypatch, capsys):
    seen: dict[str, object] = {}

    class FakeUpdater:
        def __init__(self, **kwargs) -> None:
            seen.update(kwargs)

        def reconcile_boot(self, **_kwargs) -> str:
            return "CURRENT"

    def netuid_from(path: Path) -> int:
        seen["direct_env_file"] = path
        return OTHER_NETUID

    monkeypatch.setattr(updater_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater_module, "load_expected_hotkey_identity", lambda _path: "5Validator"
    )
    monkeypatch.setattr(updater_module, "load_direct_netuid", netuid_from)
    monkeypatch.setattr(updater_module, "SignedReleaseUpdater", FakeUpdater)
    monkeypatch.setattr(
        updater_module.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1234, pw_gid=1234),
    )

    updater_module.main(["--reconcile-boot", "--direct-env-file=/etc/x/direct.env"])

    assert seen["direct_env_file"] == Path("/etc/x/direct.env")
    assert seen["journal_scope_root"] == direct_journal_scope_root(OTHER_NETUID)
    assert "CATHEDRAL_VALIDATOR_UPDATE_CURRENT" in capsys.readouterr().out


def test_updater_cli_refuses_to_run_without_a_configured_netuid(
    monkeypatch, tmp_path, capsys
):
    constructed: list[object] = []
    monkeypatch.setattr(updater_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater_module, "load_expected_hotkey_identity", lambda _path: "5Validator"
    )
    monkeypatch.setattr(
        updater_module, "SignedReleaseUpdater", lambda **kw: constructed.append(kw)
    )

    status_code = updater_module.main(
        ["--reconcile-boot", f"--direct-env-file={tmp_path / 'absent.env'}"]
    )

    assert status_code != 0
    assert constructed == []
    assert "direct validator configuration is unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("netuid", [NETUID, OTHER_NETUID])
def test_status_reads_the_journal_of_the_configured_netuid(
    monkeypatch, tmp_path, netuid
):
    monkeypatch.setattr(status, "ETC", tmp_path)
    monkeypatch.setattr(status, "ROOT_UID", os.geteuid())
    _direct_env(tmp_path, _with_netuid(netuid))

    assert status._direct_scope() == direct_journal_scope_root(netuid)


@pytest.mark.parametrize(
    "body",
    [
        "CATHEDRAL_SNP_POLICY=/etc/x\n",
        f"CATHEDRAL_VALIDATOR_NETUID={NETUID}\n" * 2,
        f"CATHEDRAL_VALIDATOR_NETUID=0{NETUID}\n",
        "CATHEDRAL_VALIDATOR_NETUID=65536\n",
    ],
    ids=["missing", "repeated", "leading-zero", "past-u16"],
)
def test_status_refuses_a_missing_or_malformed_netuid(monkeypatch, tmp_path, body):
    monkeypatch.setattr(status, "ETC", tmp_path)
    monkeypatch.setattr(status, "ROOT_UID", os.geteuid())
    _direct_env(tmp_path, body)

    with pytest.raises(status.StatusUnavailable, match="netuid"):
        status._direct_scope()


# Runtime ---------------------------------------------------------------------

SIGNER = Keypair.create_from_uri("//Alice")


def test_one_hotkey_never_runs_two_processes_even_on_different_subnets(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    first = writer_runtime.DirectWeightWriter(
        subtensor=object(), keypair=SIGNER, netuid=NETUID
    )
    other_subnet = writer_runtime.DirectWeightWriter(
        subtensor=object(), keypair=SIGNER, netuid=OTHER_NETUID
    )
    assert first.state_path != other_subnet.state_path

    with first.process_locked():
        with pytest.raises(
            writer_runtime.DirectSubmissionAmbiguous,
            match="signer process lock",
        ):
            with other_subnet.process_locked():
                pass
    with other_subnet.process_locked():
        pass

    signer_lock = tmp_path / "signers" / SIGNER.ss58_address / "process.lock"
    assert signer_lock.is_file()
    assert signer_lock.stat().st_mode & 0o777 == 0o600


def test_signer_lock_refuses_a_group_accessible_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(writer_runtime, "DIRECT_STATE_ROOT", tmp_path)
    (tmp_path / "signers").mkdir(mode=0o700)
    (tmp_path / "signers").chmod(0o750)
    writer = writer_runtime.DirectWeightWriter(
        subtensor=object(), keypair=SIGNER, netuid=NETUID
    )

    with pytest.raises(writer_runtime.DirectValidatorError, match="owner-controlled"):
        with writer.process_locked():
            pass


EXPORTER_ARGS = (
    "--spool=/nonexistent/events.jsonl",
    "--endpoint=https://collector.invalid/v1/ingest",
    "--ingest-token-file=/nonexistent/token",
    "--sites-authorization-file=/nonexistent/sites",
    "--reader-group=cathedral-telemetry",
)


def _run_exporter(monkeypatch, capsys, flag, environment):
    """Run the exporter's main() up to the spool read and report its netuid."""

    monkeypatch.delenv("CATHEDRAL_VALIDATOR_NETUID", raising=False)
    monkeypatch.delenv("CATHEDRAL_TESTNET", raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        telemetry_exporter.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=0)
    )
    seen = []

    def stop_at_spool(_spool, *, expected_reader_gid, netuid):
        seen.append(netuid)
        raise telemetry_exporter.TelemetryExportError("stopped at the spool")

    monkeypatch.setattr(telemetry_exporter, "latest_telemetry_event", stop_at_spool)
    argv = list(EXPORTER_ARGS) + ([] if flag is None else [f"--netuid={flag}"])
    assert telemetry_exporter.main(argv) == 1
    return seen, capsys.readouterr().out


@pytest.mark.parametrize(
    ("flag", "environment", "expected"),
    [
        (None, {"CATHEDRAL_VALIDATOR_NETUID": str(OTHER_NETUID)}, OTHER_NETUID),
        (str(OTHER_NETUID), {}, OTHER_NETUID),
        (str(NETUID), {"CATHEDRAL_VALIDATOR_NETUID": str(NETUID)}, NETUID),
    ],
    ids=["environment", "flag", "both-agree"],
)
def test_exporter_checks_events_against_the_configured_netuid(
    monkeypatch, capsys, flag, environment, expected
):
    seen, _output = _run_exporter(monkeypatch, capsys, flag, environment)
    assert seen == [expected]


@pytest.mark.parametrize(
    ("flag", "environment", "message"),
    [
        (None, {}, "no netuid is configured"),
        (
            str(OTHER_NETUID),
            {"CATHEDRAL_VALIDATOR_NETUID": str(NETUID)},
            "disagrees",
        ),
        (f"0{NETUID}", {}, "canonical decimal u16"),
        (None, {"CATHEDRAL_VALIDATOR_NETUID": "65536"}, "canonical decimal u16"),
    ],
    ids=["unconfigured", "disagreeing", "leading-zero", "past-u16"],
)
def test_exporter_refuses_an_unusable_netuid(
    monkeypatch, capsys, flag, environment, message
):
    seen, output = _run_exporter(monkeypatch, capsys, flag, environment)
    assert seen == []
    assert '"status": "FAILED"' in output
    assert message in output


def test_exporter_unit_reads_the_validator_netuid():
    unit = (
        ROOT / "deploy/validator-telemetry/cathedral-validator-telemetry.service"
    ).read_text("ascii")
    assert "EnvironmentFile=/etc/cathedral-validator/direct.env" in unit.splitlines()
