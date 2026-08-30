from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
import runpy
import socket
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    METADATA_SCHEMA,
    SYSTEMCTL,
    VALIDATOR_SERVICE,
    SignedReleaseUpdater,
    UpdateRefused,
    parse_release_metadata,
    release_tree_sha256,
)

NOW = int(time.time())
PREVIOUS_DIGEST = "f" * 64
PREVIOUS_TARGET = f"releases/{PREVIOUS_DIGEST}"


def _archive(*, marker_path: Path | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        marker = f"touch {marker_path}\n" if marker_path is not None else ""
        program = f"#!/bin/sh\n{marker}exit 0\n".encode("ascii")
        info = tarfile.TarInfo("bin/cathedral-validator")
        info.mode = 0o755
        info.size = len(program)
        bundle.addfile(info, io.BytesIO(program))
        readme = b"immutable release\n"
        info = tarfile.TarInfo("README")
        info.mode = 0o644
        info.size = len(readme)
        bundle.addfile(info, io.BytesIO(readme))
    return output.getvalue()


def _validator_pex(path: Path) -> None:
    """Write a deterministic PEX-shaped validator used by release-contract tests."""

    runtime = b"""\
import argparse
import os
import socket

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qvl", required=True)
    parser.add_argument("--snp-policy", required=True)
    parser.add_argument("--snpguest", required=True)
    options, _ = parser.parse_known_args()
    if not all(os.path.isfile(item) for item in (options.qvl, options.snp_policy, options.snpguest)):
        return 2
    if not os.access(options.snpguest, os.X_OK):
        return 2
    notify = os.environ.get("NOTIFY_SOCKET")
    if not notify:
        return 2
    address = "\\0" + notify[1:] if notify.startswith("@") else notify
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.connect(address)
        client.sendall(b"READY=1\\nSTATUS=initialized; waiting for the next direct cycle")
    return 0
"""
    pex_info = canonical_document_bytes(
        {
            "distributions": {
                "bittensor-10.5.0-py3-none-any.whl": "1" * 64,
                "cathedral-0.0.0-py3-none-any.whl": "5" * 64,
                "cathedral_scaffold-1.2.3-py3-none-any.whl": "2" * 64,
                "cryptography-48.0.0-py3-none-any.whl": "3" * 64,
                "numpy-2.5.2-py3-none-any.whl": "4" * 64,
            },
            "entry_point": "cathedral_thin.independent_runtime.direct_validator:main",
            "inherit_path": "false",
            "inject_env": {},
            "interpreter_constraints": ["CPython==3.12.*"],
            "pex_path": "",
            "pex_paths": [],
            "requirements": [
                "cathedral-scaffold[snp-production] @ "
                "file:///reviewed/cathedral_scaffold-1.2.3-py3-none-any.whl",
                "cathedral@ git+https://github.com/cathedralai/"
                "cathedral-compute.git@5268443104fd7717b95ce4c398ddf6229ec4f461",
            ],
            "strip_pex_env": True,
        }
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        entries = {
            "PEX-INFO": pex_info,
            "__main__.py": (
                b"from cathedral_thin.independent_runtime.direct_validator "
                b"import main\nraise SystemExit(main())\n"
            ),
            "cathedral_thin/__init__.py": b"",
            "cathedral_thin/independent_runtime/__init__.py": b"",
            "cathedral_thin/independent_runtime/direct_validator.py": runtime,
            "cathedral_thin/independent_runtime/snp_production.py": b"",
            ".deps/cathedral_scaffold-1.2.3-py3-none-any.whl/"
            "cathedral_thin/independent_runtime/direct_validator.py": runtime,
            ".deps/cathedral_scaffold-1.2.3-py3-none-any.whl/"
            "cathedral_thin/independent_runtime/snp_production.py": b"",
        }
        for name, body in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, body)
    path.write_bytes(b"#!/usr/bin/python3.12\n" + output.getvalue())
    path.chmod(0o755)


def _tree_digest(tmp_path: Path, archive: bytes, *, name: str = "tree") -> str:
    root = tmp_path / name
    root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        bundle.extractall(root, filter="data")
    return release_tree_sha256(root)


def _sign(private: Ed25519PrivateKey, signed: dict[str, object]) -> bytes:
    signature = private.sign(canonical_document_bytes(signed))
    return canonical_document_bytes(
        {
            "signed": signed,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def _canary_metadata(
    private: Ed25519PrivateKey,
    *,
    sequence: int,
    archive: bytes,
    tree: str,
    version: str = "1.2.3",
    issued: int = NOW,
    expires: int = NOW + 3600,
) -> bytes:
    release: dict[str, object] = {
        "version": version,
        "archive_url": "https://releases.example/validator-1.2.3.tar.gz",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "tree_sha256": tree,
        "entrypoint": "bin/cathedral-validator",
    }
    return _sign(
        private,
        {
            "schema": METADATA_SCHEMA,
            "channel": "canary",
            "sequence": sequence,
            "issued_unix": issued,
            "expires_unix": expires,
            "release": release,
        },
    )


def _stable_metadata(
    private: Ed25519PrivateKey,
    *,
    sequence: int,
    archive: bytes,
    tree: str,
    canary_raw: bytes | None = None,
    version: str = "1.2.3",
) -> bytes:
    canary_raw = canary_raw or _canary_metadata(
        private, sequence=sequence, archive=archive, tree=tree, version=version
    )
    canary = parse_release_metadata(
        canary_raw,
        channel="canary",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    release: dict[str, object] = {
        "version": version,
        "archive_url": "https://releases.example/validator-1.2.3.tar.gz",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "tree_sha256": tree,
        "entrypoint": "bin/cathedral-validator",
        "promoted_canary": {
            "sequence": canary.sequence,
            "signed_sha256": canary.signed_sha256,
            "metadata_sha256": canary.metadata_sha256,
            "archive_sha256": canary.archive_sha256,
        },
    }
    return _sign(
        private,
        {
            "schema": METADATA_SCHEMA,
            "channel": "stable",
            "sequence": sequence,
            "issued_unix": NOW,
            "expires_unix": NOW + 3600,
            "release": release,
        },
    )


def _journal(path: Path, *, pending: object = None) -> None:
    path.parent.mkdir(parents=True)
    path.write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": pending,
                "last_attempt": None,
            }
        )
    )
    path.chmod(0o600)
    lock = path.with_name("cycle.lock")
    lock.touch(mode=0o600)
    lock.chmod(0o600)


def _seed_current(tmp_path: Path) -> None:
    install = tmp_path / "install"
    executable = install / PREVIOUS_TARGET / "bin" / "cathedral-validator"
    executable.parent.mkdir(parents=True, mode=0o755)
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o555)
    (install / "current").symlink_to(PREVIOUS_TARGET)


def _updater(
    tmp_path: Path,
    *,
    journal: Path,
    metadata: bytes,
    archive: bytes,
    restarts: list[tuple[str, ...]] | None = None,
    service_restarter=None,
    seed_current: bool = True,
) -> SignedReleaseUpdater:
    if seed_current and not (tmp_path / "install" / "current").exists():
        _seed_current(tmp_path)
    if service_restarter is None:
        assert restarts is not None

        def record_restart(command) -> None:
            restarts.append(tuple(command))

        service_restarter = record_restart
    return SignedReleaseUpdater(
        install_root=tmp_path / "install",
        state_root=tmp_path / "state",
        journal=journal,
        expected_uid=os.geteuid(),
        fetcher=lambda url, _maximum: metadata if url.endswith(".json") else archive,
        service_restarter=service_restarter,
    )


def _update(
    updater: SignedReleaseUpdater,
    private: Ed25519PrivateKey,
    *,
    channel: str,
    sequence: int,
    cycle_wait_seconds: float = 0.1,
) -> str:
    return updater.update(
        metadata_url=f"https://releases.example/{channel}.json",
        channel=channel,
        public_key=private.public_key(),
        pause_file=updater.state_root.parent / "pause",
        minimum_sequence=sequence,
        cycle_wait_seconds=cycle_wait_seconds,
    )


def _bootstrap(
    updater: SignedReleaseUpdater,
    private: Ed25519PrivateKey,
    *,
    channel: str,
    sequence: int,
) -> str:
    return updater.bootstrap(
        metadata_url=f"https://releases.example/{channel}.json",
        channel=channel,
        public_key=private.public_key(),
        pause_file=updater.state_root.parent / "pause",
        minimum_sequence=sequence,
        validator_uid=os.geteuid(),
        validator_gid=os.getegid(),
        cycle_wait_seconds=0.1,
    )


def test_signed_stable_release_activates_and_restarts_only_fixed_service(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    marker = tmp_path / "root-code-ran"
    archive = _archive(marker_path=marker)
    metadata = _stable_metadata(
        private,
        sequence=7,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )

    assert _update(updater, private, channel="stable", sequence=7) == "ACTIVATED"

    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert marker.exists() is False
    assert (tmp_path / "install" / "current").is_symlink()
    assert (
        tmp_path / "install" / "current" / "README"
    ).read_text() == "immutable release\n"
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"]["stable"]["sequence"] == 7


def test_clean_host_bootstrap_creates_idle_lock_and_starts_first_release(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
        seed_current=False,
    )

    assert _bootstrap(updater, private, channel="canary", sequence=1) == "ACTIVATED"

    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert journal.is_file()
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600
    cycle_lock = journal.with_name("cycle.lock")
    assert cycle_lock.is_file()
    assert stat.S_IMODE(cycle_lock.stat().st_mode) == 0o600
    direct_state = json.loads(journal.read_text())
    assert direct_state == {
        "schema": "cathedral_direct_validator_state_v1",
        "pending": None,
        "last_attempt": None,
    }
    updater_state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert updater_state["pending"] is None
    assert updater_state["channels"]["canary"]["sequence"] == 1


def test_failed_first_release_readiness_is_stopped_and_deactivated(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    calls: list[tuple[str, ...]] = []

    def fail_start(command) -> None:
        calls.append(tuple(command))
        if command[1] == "restart":
            raise OSError("first service never reached READY=1")

    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        service_restarter=fail_start,
        seed_current=False,
    )

    with pytest.raises(UpdateRefused, match="failed readiness and was deactivated"):
        _bootstrap(updater, private, channel="canary", sequence=1)

    assert calls == [
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
        (SYSTEMCTL, "stop", VALIDATOR_SERVICE),
    ]
    assert not (tmp_path / "install" / "current").exists()
    updater_state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert updater_state["pending"] is None
    assert updater_state["channels"] == {}


def test_cycle_lock_blocks_activation_until_bounded_timeout(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=4,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )
    descriptor = os.open(journal.with_name("cycle.lock"), os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(UpdateRefused, match="finish its cycle"):
            _update(
                updater,
                private,
                channel="canary",
                sequence=4,
                cycle_wait_seconds=0.0,
            )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert restarts == []
    assert os.readlink(tmp_path / "install" / "current") == PREVIOUS_TARGET


def test_final_idle_journal_check_occurs_after_cycle_lock(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal, pending={"phase": "ambiguous"})
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )

    with pytest.raises(UpdateRefused, match="unresolved"):
        _update(updater, private, channel="canary", sequence=1)

    assert restarts == []
    assert os.readlink(tmp_path / "install" / "current") == PREVIOUS_TARGET


def test_activation_crash_is_reconciled_before_new_metadata(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=9,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)

    def first_restart(_command) -> None:
        raise KeyboardInterrupt("simulated updater process crash")

    first = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        service_restarter=first_restart,
    )
    with pytest.raises(KeyboardInterrupt, match="process crash"):
        _update(first, private, channel="canary", sequence=9)
    pending = json.loads((tmp_path / "state" / "state.json").read_text())
    assert pending["pending"]["record"]["sequence"] == 9
    assert (tmp_path / "install" / "current").is_symlink()

    restarts: list[tuple[str, ...]] = []
    recovered = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )
    assert _update(recovered, private, channel="canary", sequence=9) == "CURRENT"
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"]["canary"]["sequence"] == 9
    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]


def test_readiness_failure_rolls_back_before_cycle_lock_is_released(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=10,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    calls: list[tuple[str, ...]] = []

    def fail_new_then_restart_previous(command) -> None:
        calls.append(tuple(command))
        if len(calls) == 1:
            raise OSError("new service never reached READY=1")

    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        service_restarter=fail_new_then_restart_previous,
    )

    with pytest.raises(UpdateRefused, match="prior release was restored"):
        _update(updater, private, channel="canary", sequence=10)

    assert calls == [
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
    ]
    assert os.readlink(tmp_path / "install" / "current") == PREVIOUS_TARGET
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"] == {}


def test_pending_before_symlink_is_abandoned_and_retried(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=2,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    parsed = parse_release_metadata(
        metadata,
        channel="canary",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    state_root = tmp_path / "state"
    state_root.mkdir()
    state_root.joinpath("state.json").write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_validator_updater_state_v2",
                "channels": {},
                "pending": {
                    "channel": "canary",
                    "record": {
                        "sequence": 2,
                        "archive_sha256": parsed.archive_sha256,
                        "signed_sha256": parsed.signed_sha256,
                        "metadata_sha256": parsed.metadata_sha256,
                    },
                    "previous_current": PREVIOUS_TARGET,
                    "target_current": f"releases/{parsed.archive_sha256}",
                },
            }
        )
    )
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=2) == "ACTIVATED"
    assert restarts == [
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
    ]


def test_same_sequence_different_signed_release_is_equivocation(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    tree = _tree_digest(tmp_path, archive)
    first = _stable_metadata(
        private, sequence=7, archive=archive, tree=tree, version="1.2.3"
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=first,
        archive=archive,
        restarts=restarts,
    )
    _update(updater, private, channel="stable", sequence=7)
    altered = _stable_metadata(
        private, sequence=7, archive=archive, tree=tree, version="1.2.4"
    )
    updater.fetcher = lambda _url, _maximum: altered
    with pytest.raises(UpdateRefused, match="equivocates"):
        _update(updater, private, channel="stable", sequence=7)


def test_stable_binds_exact_signed_canary_record_and_archive(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    tree = _tree_digest(tmp_path, archive)
    canary_raw = _canary_metadata(private, sequence=12, archive=archive, tree=tree)
    stable_raw = _stable_metadata(
        private,
        sequence=3,
        archive=archive,
        tree=tree,
        canary_raw=canary_raw,
    )
    canary = parse_release_metadata(
        canary_raw,
        channel="canary",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    stable = parse_release_metadata(
        stable_raw,
        channel="stable",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    assert stable.promoted_canary_sequence == 12
    assert stable.promoted_canary_signed_sha256 == canary.signed_sha256
    assert stable.promoted_canary_metadata_sha256 == canary.metadata_sha256

    envelope = json.loads(stable_raw)
    envelope["signed"]["release"]["promoted_canary"]["archive_sha256"] = "0" * 64
    envelope["signature"] = base64.b64encode(
        private.sign(canonical_document_bytes(envelope["signed"]))
    ).decode("ascii")
    with pytest.raises(UpdateRefused, match="exact promoted"):
        parse_release_metadata(
            canonical_document_bytes(envelope),
            channel="stable",
            public_key=private.public_key(),
            now_unix=NOW,
        )


def test_expired_and_below_bootstrap_release_are_refused(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    tree = _tree_digest(tmp_path, archive)
    expired = _canary_metadata(
        private,
        sequence=20,
        archive=archive,
        tree=tree,
        issued=NOW - 7200,
        expires=NOW - 3600,
    )
    with pytest.raises(UpdateRefused, match="expired"):
        parse_release_metadata(
            expired,
            channel="canary",
            public_key=private.public_key(),
            now_unix=NOW,
        )
    current = _canary_metadata(private, sequence=4, archive=archive, tree=tree)
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=current,
        archive=archive,
        restarts=restarts,
    )
    with pytest.raises(UpdateRefused, match="bootstrap"):
        updater.update(
            metadata_url="https://releases.example/canary.json",
            channel="canary",
            public_key=private.public_key(),
            pause_file=tmp_path / "pause",
            minimum_sequence=5,
            cycle_wait_seconds=0.1,
        )


def test_bad_signature_is_refused(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    raw = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive),
    )
    with pytest.raises(UpdateRefused, match="signature"):
        parse_release_metadata(
            raw,
            channel="canary",
            public_key=Ed25519PrivateKey.generate().public_key(),
            now_unix=NOW,
        )


def test_deploy_contract_is_unprivileged_hotkey_only_and_operational() -> None:
    root = Path(__file__).resolve().parents[2]
    deploy = root / "deploy" / "validator-update"
    sysusers = (deploy / "cathedral-validator.sysusers").read_text()
    assert "u cathedral-validator" in sysusers
    direct = (deploy / "cathedral-validator-direct.service").read_text()
    assert "User=cathedral-validator" in direct
    assert "Type=notify" in direct
    assert "NotifyAccess=main" in direct
    assert "Restart=on-failure" in direct
    assert "RestartPreventExitStatus=2" in direct
    assert "TimeoutStartSec=120s" in direct
    assert "LoadCredential=validator-hotkey:" in direct
    assert "Environment=PEX_ROOT=/run/cathedral-validator-pex" in direct
    assert (
        "RuntimeDirectory=cathedral-validator-wallet cathedral-validator-pex" in direct
    )
    assert "/var/lib/cathedral-validator/.cache/pex" not in direct
    assert "--wallet-path=/run/cathedral-validator-wallet" in direct
    assert "ConditionPathExists=/etc/cathedral-validator/snp-policy.json" in direct
    assert (
        "ConditionFileIsExecutable=/usr/local/lib/cathedral-validator/snpguest"
        in direct
    )
    assert "ConditionFileIsExecutable=/usr/bin/python3.12" in direct
    assert "--snp-policy=${CATHEDRAL_SNP_POLICY}" in direct
    assert "--snpguest=${CATHEDRAL_SNPGUEST}" in direct
    assert "coldkey" not in direct.lower()
    assert "ReadWritePaths=/var/lib/cathedral-validator" in direct
    assert (
        "ExecStart=/opt/cathedral-validator/current/bin/cathedral-validator" in direct
    )
    assert "Environment=CATHEDRAL_VALIDATOR_TELEMETRY_ARGS=\n" in direct
    assert "EnvironmentFile=-/etc/cathedral-validator/direct-telemetry.env" in direct
    assert direct.count("$CATHEDRAL_VALIDATOR_TELEMETRY_ARGS") == 1

    direct_env = (deploy / "direct.env.example").read_text()
    assert "CATHEDRAL_SNP_POLICY=/etc/cathedral-validator/snp-policy.json" in direct_env
    assert (
        "CATHEDRAL_SNPGUEST=/usr/local/lib/cathedral-validator/snpguest" in direct_env
    )
    telemetry_env = (deploy / "direct-telemetry.env.example").read_text()
    assert (
        'CATHEDRAL_VALIDATOR_TELEMETRY_ARGS="--telemetry-spool '
        "/var/lib/cathedral-validator-telemetry/events.jsonl "
        '--telemetry-reader-group cathedral-telemetry"' in telemetry_env
    )
    assert "CATHEDRAL_TELEMETRY_ENDPOINT" not in telemetry_env
    assert "TOKEN_FILE" not in telemetry_env

    for name, minimum in (
        ("cathedral-validator-canary-update.service", "CANARY"),
        ("cathedral-validator-update.service", "STABLE"),
    ):
        unit = (deploy / name).read_text()
        assert "ProtectHome=true" in unit
        assert (
            "ExecStart=/usr/local/lib/cathedral-validator-updater/bin/"
            "cathedral-validator-update "
        ) in unit
        assert (
            "ConditionFileIsExecutable=/usr/local/lib/"
            "cathedral-validator-updater/bin/cathedral-validator-update"
        ) in unit
        assert "/home/" not in unit
        assert "Documents/" not in unit
        assert (
            f"--minimum-sequence=${{CATHEDRAL_VALIDATOR_{minimum}_MINIMUM_SEQUENCE}}"
            in unit
        )
        assert (
            "ReadWritePaths=/opt/cathedral-validator "
            "/var/lib/cathedral-validator-update /var/lib/cathedral-validator"
        ) in unit
        assert (
            "InaccessiblePaths=/etc/cathedral-validator/validator-hotkey "
            "-/var/lib/cathedral-validator/.bittensor "
            "-/run/cathedral-validator-wallet -/run/cathedral-validator-pex"
        ) in unit


def test_real_linux_release_job_builds_and_starts_the_production_pex() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "tests.yml").read_text()
    release_job = workflow.split("  validator-release:\n", 1)[1]

    assert "continue-on-error" not in release_job
    assert "pex==2.101.1" in release_job
    assert "cathedral-scaffold[snp-production] @" in release_job
    assert "cathedral @ git+https://github.com/cathedralai/" in release_job
    assert release_job.count("CPython==3.12.*") == 2
    assert "cmp /tmp/cathedral-validator-one.pex" in release_job
    assert 'builder["_validator_pex"](pex)' in release_job
    assert 'builder["validator_release_tree"](pex, release)' in release_job
    assert "PEX_INTERPRETER=1" in release_job
    assert "PEX_ROOT=/tmp/cathedral-validator-pex-root" in release_job
    assert "CATHEDRAL_RELEASE_SMOKE_PEX_ROOT=" in release_job
    assert "tests/release_smoke/run_real_validator.py" in release_job

    smoke = (root / "tests" / "release_smoke" / "run_real_validator.py").read_text()
    assert "snp_production.load_compute_contract()" in smoke
    assert "module_path.is_relative_to(pex_root)" in smoke
    assert "module_path.is_relative_to(checkout)" in smoke

    docs = (root / "docs" / "AUTO_UPDATE.md").read_text()
    assert "Installation is not self-service or\nlaunch-ready" in docs
    assert "No reviewed updater wheelhouse, hash lock" in docs
    assert "/usr/local/lib/cathedral-validator-updater/bin/python" in docs
    assert "#!/usr/local/lib/cathedral-validator-updater/bin/python'" in docs
    assert "#!/usr/local/lib/cathedral-validator-updater/bin/python3.12" not in docs
    assert "--no-index --require-hashes" in docs
    assert "$(command -v cathedral-validator-update)" not in docs


def test_extracted_release_is_traversable_but_not_writable_by_service(
    tmp_path: Path,
) -> None:
    from cathedral_thin.independent_runtime.updater import extract_release_archive

    release = tmp_path / "release"
    extract_release_archive(_archive(), release)
    assert stat.S_IMODE(release.stat().st_mode) == 0o755
    assert stat.S_IMODE((release / "bin").stat().st_mode) == 0o755
    assert (
        stat.S_IMODE((release / "bin" / "cathedral-validator").stat().st_mode) == 0o555
    )
    assert stat.S_IMODE((release / "README").stat().st_mode) == 0o444


def test_offline_builder_is_deterministic_and_promotes_exact_canary(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    builder = runpy.run_path(
        str(root / "deploy" / "validator-update" / "build_signed_release.py")
    )
    pex = tmp_path / "cathedral-validator.pex"
    _validator_pex(pex)
    private = Ed25519PrivateKey.generate()
    archive_one = tmp_path / "one.tar.gz"
    archive_two = tmp_path / "two.tar.gz"
    canary_one = tmp_path / "canary-one.json"
    canary_two = tmp_path / "canary-two.json"
    kwargs = {
        "pex": pex,
        "archive_url": "https://releases.example/validator.tar.gz",
        "sequence": 4,
        "private_key": private,
        "issued_unix": NOW,
        "lifetime_seconds": 3600,
    }
    builder["build_canary"](archive_out=archive_one, metadata_out=canary_one, **kwargs)
    builder["build_canary"](archive_out=archive_two, metadata_out=canary_two, **kwargs)
    assert archive_one.read_bytes() == archive_two.read_bytes()
    assert canary_one.read_bytes() == canary_two.read_bytes()

    from cathedral_thin.independent_runtime.updater import extract_release_archive

    release = tmp_path / "extracted"
    extract_release_archive(archive_one.read_bytes(), release)
    manifest = json.loads((release / "RELEASE.json").read_text())
    assert manifest["schema"] == "cathedral_validator_bundle_v1"
    assert manifest["entry_point"] == (
        "cathedral_thin.independent_runtime.direct_validator:main"
    )
    assert manifest["project_distribution"].startswith("cathedral_scaffold-1.2.3")
    executable = release / "bin" / "cathedral-validator"
    assert stat.S_IMODE(executable.stat().st_mode) == 0o555

    qvl = tmp_path / "qvl"
    snpguest = tmp_path / "snpguest"
    policy = tmp_path / "snp-policy.json"
    qvl.write_bytes(b"reviewed qvl")
    snpguest.write_bytes(b"reviewed snpguest")
    snpguest.chmod(0o555)
    policy.write_text("{}")
    notify_path = Path("/tmp") / f"cv-pex-{id(tmp_path):x}.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(str(notify_path))
            server.settimeout(2.0)
            environment = dict(os.environ)
            environment["NOTIFY_SOCKET"] = str(notify_path)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(executable),
                    "--qvl",
                    str(qvl),
                    "--snp-policy",
                    str(policy),
                    "--snpguest",
                    str(snpguest),
                ],
                check=False,
                env=environment,
                capture_output=True,
                timeout=5,
            )
            assert completed.returncode == 0, completed.stderr.decode()
            assert server.recv(512) == (
                b"READY=1\nSTATUS=initialized; waiting for the next direct cycle"
            )
    finally:
        notify_path.unlink(missing_ok=True)

    stable_path = tmp_path / "stable.json"
    builder["promote_stable"](
        canary_metadata=canary_one,
        metadata_out=stable_path,
        sequence=2,
        private_key=private,
        issued_unix=NOW,
        lifetime_seconds=3600,
    )
    canary = parse_release_metadata(
        canary_one.read_bytes(),
        channel="canary",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    assert canary.version == "1.2.3"
    stable = parse_release_metadata(
        stable_path.read_bytes(),
        channel="stable",
        public_key=private.public_key(),
        now_unix=NOW,
    )
    assert stable.archive_sha256 == canary.archive_sha256
    assert stable.promoted_canary_metadata_sha256 == canary.metadata_sha256
