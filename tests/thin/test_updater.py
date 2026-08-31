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

import cathedral_thin.independent_runtime.updater as updater_module
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    DEFAULT_DIRECT_JOURNAL_SCOPE_ROOT,
    DEFAULT_OPERATION_TIMEOUT_SECONDS,
    DEFAULT_SERVICE_CONTROL_TIMEOUT_SECONDS,
    METADATA_SCHEMA,
    SYSTEMCTL,
    SYSTEMD_TIMEOUT_MARGIN_SECONDS,
    UPDATER_STATE_SCHEMA,
    VALIDATOR_SERVICE,
    SignedReleaseUpdater,
    UpdateRefused,
    direct_writer_journal_path,
    extract_release_archive,
    load_expected_hotkey_identity,
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
    parser.add_argument("--expected-hotkey", required=True)
    options, _ = parser.parse_known_args()
    if not all(os.path.isfile(item) for item in (options.qvl, options.snp_policy, options.snpguest)):
        return 2
    if not options.expected_hotkey.isascii() or not options.expected_hotkey.isalnum():
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
                "cathedral-sandbox.git@8dde6eaca27116eed53386a1fa33ec70b74a01fb",
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
            "cathedral_thin/independent_runtime/telemetry.py": b"",
            "cathedral_thin/independent_runtime/telemetry_exporter.py": b"",
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


def _record_for(
    raw: bytes, private: Ed25519PrivateKey, *, channel: str
) -> dict[str, object]:
    release = parse_release_metadata(
        raw,
        channel=channel,
        public_key=private.public_key(),
        now_unix=NOW,
    )
    return {
        "sequence": release.sequence,
        "archive_sha256": release.archive_sha256,
        "signed_sha256": release.signed_sha256,
        "metadata_sha256": release.metadata_sha256,
    }


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
        expected_hotkey=journal.parent.name,
        journal_scope_root=journal.parent.parent,
        expected_uid=os.geteuid(),
        fetcher=lambda url, _maximum: metadata if url.endswith(".json") else archive,
        service_restarter=service_restarter,
    )


def _run_reconcile_in_separate_process(
    updater: SignedReleaseUpdater,
) -> subprocess.CompletedProcess[str]:
    """Run the systemd start-gate shape in a distinct lock-owning process."""

    root = Path(__file__).resolve().parents[2]
    program = """\
import os
import sys
from pathlib import Path

from cathedral_thin.independent_runtime.updater import SignedReleaseUpdater, UpdateRefused

updater = SignedReleaseUpdater(
    install_root=Path(sys.argv[1]),
    state_root=Path(sys.argv[2]),
    expected_hotkey=sys.argv[3],
    journal_scope_root=Path(sys.argv[4]),
    expected_uid=os.geteuid(),
)
try:
    print(updater.reconcile_boot(cycle_wait_seconds=0.05, operation_timeout_seconds=2.0))
except UpdateRefused as exc:
    print(f"REFUSED: {exc}", file=sys.stderr)
    raise SystemExit(23)
"""
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(root)
        if not existing_pythonpath
        else f"{root}{os.pathsep}{existing_pythonpath}"
    )
    return subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(updater.install_root),
            str(updater.state_root),
            updater.journal.parent.name,
            str(updater.journal.parent.parent),
        ],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=5.0,
        check=False,
    )


def _lock_for_other_process(path: Path) -> int:
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


def test_updater_derives_the_only_journal_for_the_expected_hotkey(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "direct-writer" / "finney-sn39-mechanism-0"
    updater = SignedReleaseUpdater(
        install_root=tmp_path / "install",
        state_root=tmp_path / "state",
        expected_hotkey="5ExpectedValidator",
        journal_scope_root=scope,
    )

    assert updater.journal == scope / "5ExpectedValidator" / "state.json"
    assert direct_writer_journal_path("5ExpectedValidator") == (
        DEFAULT_DIRECT_JOURNAL_SCOPE_ROOT / "5ExpectedValidator" / "state.json"
    )


@pytest.mark.parametrize(
    "hotkey",
    ("", "../other", "5Validator/other", "5 validator", "\N{SNOWMAN}", "x" * 65),
)
def test_updater_rejects_unsafe_expected_hotkey(tmp_path: Path, hotkey: str) -> None:
    with pytest.raises(UpdateRefused, match="hotkey is not path-safe"):
        SignedReleaseUpdater(
            install_root=tmp_path / "install",
            state_root=tmp_path / "state",
            expected_hotkey=hotkey,
            journal_scope_root=tmp_path / "scope",
        )


def test_updater_loads_one_root_owned_public_identity(tmp_path: Path) -> None:
    identity = tmp_path / "identity.env"
    identity.write_text(
        "# Public address only.\n"
        "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=5ExpectedValidator\n"
    )
    identity.chmod(0o600)

    assert (
        load_expected_hotkey_identity(
            identity,
            expected_uid=os.geteuid(),
        )
        == "5ExpectedValidator"
    )

    identity.write_text(
        "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=5ExpectedValidator\n"
        "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=5OtherValidator\n"
    )
    with pytest.raises(UpdateRefused, match="unexpected fields"):
        load_expected_hotkey_identity(identity, expected_uid=os.geteuid())

    identity.write_text("CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=../other\n")
    with pytest.raises(UpdateRefused, match="hotkey is not path-safe"):
        load_expected_hotkey_identity(identity, expected_uid=os.geteuid())

    identity.write_text("CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=5ExpectedValidator\n")
    identity.chmod(0o640)
    with pytest.raises(UpdateRefused, match="not root-controlled"):
        load_expected_hotkey_identity(identity, expected_uid=os.geteuid())


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

    previous_umask = os.umask(0o077)
    try:
        assert _bootstrap(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    finally:
        os.umask(previous_umask)

    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert stat.S_IMODE((tmp_path / "install").stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "install" / "releases").stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    current_release = (tmp_path / "install" / "current").resolve()
    assert stat.S_IMODE(current_release.stat().st_mode) == 0o755
    assert stat.S_IMODE((current_release / "bin").stat().st_mode) == 0o755
    assert (
        stat.S_IMODE((current_release / "bin" / "cathedral-validator").stat().st_mode)
        == 0o555
    )
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


def test_selected_channel_is_immutable_and_v2_state_migrates_safely(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive(marker_path=tmp_path / "canary-marker")
    tree = _tree_digest(tmp_path, archive, name="canary-tree")
    canary = _canary_metadata(
        private,
        sequence=4,
        archive=archive,
        tree=tree,
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=canary,
        archive=archive,
        restarts=restarts,
    )

    assert _update(updater, private, channel="canary", sequence=4) == "ACTIVATED"
    state_path = tmp_path / "state" / "state.json"
    state = json.loads(state_path.read_text())
    assert state["schema"] == UPDATER_STATE_SCHEMA
    assert state["selected_channel"] == "canary"

    legacy = dict(state)
    legacy["schema"] = "cathedral_validator_updater_state_v2"
    legacy.pop("selected_channel")
    state_path.write_bytes(canonical_document_bytes(legacy))
    assert _update(updater, private, channel="canary", sequence=4) == "CURRENT"
    migrated = json.loads(state_path.read_text())
    assert migrated["schema"] == UPDATER_STATE_SCHEMA
    assert migrated["selected_channel"] == "canary"

    stable = _stable_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=tree,
    )
    updater.fetcher = lambda _url, _maximum: stable
    with pytest.raises(UpdateRefused, match="pinned to the canary"):
        _update(updater, private, channel="stable", sequence=1)

    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert json.loads(state_path.read_text())["selected_channel"] == "canary"


def test_v2_state_spanning_both_channels_is_not_migrated_by_guessing(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive, name="ambiguous-tree"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    record = _record_for(metadata, private, channel="canary")
    state_root.joinpath("state.json").write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_validator_updater_state_v2",
                "channels": {"canary": record, "stable": record},
                "pending": None,
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

    with pytest.raises(UpdateRefused, match="spans more than one release channel"):
        _update(updater, private, channel="canary", sequence=1)

    assert restarts == []
    assert json.loads(state_root.joinpath("state.json").read_text())["schema"] == (
        "cathedral_validator_updater_state_v2"
    )


def test_higher_metadata_for_current_archive_advances_without_restart(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive(marker_path=tmp_path / "same-archive")
    tree = _tree_digest(tmp_path, archive, name="same-tree")
    first = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=tree,
    )
    second = _canary_metadata(
        private,
        sequence=2,
        archive=archive,
        tree=tree,
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

    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    original_target = os.readlink(tmp_path / "install" / "current")
    original_restart_count = len(restarts)
    fetches: list[str] = []

    def metadata_only(url: str, _maximum: int) -> bytes:
        fetches.append(url)
        if url.endswith(".json"):
            return second
        raise AssertionError("same-archive metadata renewal fetched an archive")

    updater.fetcher = metadata_only
    assert _update(updater, private, channel="canary", sequence=2) == "ADVANCED"
    assert _update(updater, private, channel="canary", sequence=2) == "CURRENT"

    assert fetches == [
        "https://releases.example/canary.json",
        "https://releases.example/canary.json",
    ]
    assert len(restarts) == original_restart_count
    assert os.readlink(tmp_path / "install" / "current") == original_target
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["channels"]["canary"]["sequence"] == 2


def test_crash_uncertain_target_is_rescued_by_higher_remote_release(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "release-one")
    archive_two = _archive(marker_path=tmp_path / "release-two")
    archive_three = _archive(marker_path=tmp_path / "release-three")
    metadata_one = _canary_metadata(
        private,
        sequence=8,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=9,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="tree-two"),
    )
    metadata_three = _canary_metadata(
        private,
        sequence=10,
        archive=archive_three,
        tree=_tree_digest(tmp_path, archive_three, name="tree-three"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=8) == "ACTIVATED"

    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    def crash_after_restart_authorized(_command) -> None:
        raise KeyboardInterrupt("simulated crash after systemctl authorization")

    updater.service_restarter = crash_after_restart_authorized
    with pytest.raises(KeyboardInterrupt, match="after systemctl authorization"):
        _update(updater, private, channel="canary", sequence=9)

    target_two = f"releases/{hashlib.sha256(archive_two).hexdigest()}"
    pending = json.loads((tmp_path / "state" / "state.json").read_text())
    assert pending["pending"]["stage"] == "may_have_run"
    assert os.readlink(tmp_path / "install" / "current") == target_two

    recovery_targets: list[str] = []

    def fail_uncertain_then_start_rescue(_command) -> None:
        recovery_targets.append(os.readlink(tmp_path / "install" / "current"))
        if len(recovery_targets) == 1:
            raise OSError("uncertain target never reached readiness")

    recovered = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_three,
        archive=archive_three,
        service_restarter=fail_uncertain_then_start_rescue,
    )
    assert _update(recovered, private, channel="canary", sequence=10) == "ACTIVATED"

    target_three = f"releases/{hashlib.sha256(archive_three).hexdigest()}"
    assert recovery_targets == [target_two, target_three]
    assert os.readlink(tmp_path / "install" / "current") == target_three
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"]["canary"]["sequence"] == 10


def test_failed_rescue_preserves_the_restored_uncertain_release_record(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "fallback-one")
    archive_two = _archive(marker_path=tmp_path / "fallback-two")
    archive_three = _archive(marker_path=tmp_path / "fallback-three")
    metadata_one = _canary_metadata(
        private,
        sequence=8,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="fallback-tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=9,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="fallback-tree-two"),
    )
    metadata_three = _canary_metadata(
        private,
        sequence=10,
        archive=archive_three,
        tree=_tree_digest(tmp_path, archive_three, name="fallback-tree-three"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=[],
    )
    assert _update(updater, private, channel="canary", sequence=8) == "ACTIVATED"

    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    def interrupt_uncertain_release(_command: object) -> None:
        raise KeyboardInterrupt("leave the second release crash-uncertain")

    updater.service_restarter = interrupt_uncertain_release
    with pytest.raises(KeyboardInterrupt, match="crash-uncertain"):
        _update(updater, private, channel="canary", sequence=9)

    restart_targets: list[str] = []

    def fail_uncertain_and_rescue_then_start_fallback(_command: object) -> None:
        restart_targets.append(os.readlink(tmp_path / "install" / "current"))
        if len(restart_targets) <= 2:
            raise OSError("release readiness remained unconfirmed")

    recovered = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_three,
        archive=archive_three,
        service_restarter=fail_uncertain_and_rescue_then_start_fallback,
    )
    with pytest.raises(UpdateRefused, match="prior release was restored"):
        _update(recovered, private, channel="canary", sequence=10)

    target_two = f"releases/{hashlib.sha256(archive_two).hexdigest()}"
    target_three = f"releases/{hashlib.sha256(archive_three).hexdigest()}"
    assert restart_targets == [target_two, target_three, target_two]
    assert os.readlink(tmp_path / "install" / "current") == target_two
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"]["canary"] == _record_for(
        metadata_two, private, channel="canary"
    )
    assert recovered.reconcile_boot(cycle_wait_seconds=0.1) == "RECONCILED"


def test_boot_reconcile_rolls_back_only_before_restart_is_authorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "boot-one")
    archive_two = _archive(marker_path=tmp_path / "boot-two")
    metadata_one = _canary_metadata(
        private,
        sequence=1,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="boot-tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="boot-tree-two"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    target_one = os.readlink(tmp_path / "install" / "current")
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    real_write_state = updater_module._write_update_state

    def crash_before_authorization(root: Path, state: dict[str, object]) -> None:
        pending = state.get("pending")
        if isinstance(pending, dict) and pending.get("stage") == "may_have_run":
            raise KeyboardInterrupt("simulated crash before authorization is durable")
        real_write_state(root, state)

    monkeypatch.setattr(
        updater_module, "_write_update_state", crash_before_authorization
    )
    with pytest.raises(KeyboardInterrupt, match="before authorization is durable"):
        _update(updater, private, channel="canary", sequence=2)
    monkeypatch.setattr(updater_module, "_write_update_state", real_write_state)

    target_two = f"releases/{hashlib.sha256(archive_two).hexdigest()}"
    pending = json.loads((tmp_path / "state" / "state.json").read_text())
    assert pending["pending"]["stage"] == "prepared"
    assert os.readlink(tmp_path / "install" / "current") == target_two
    direct_state = json.loads(journal.read_text())
    direct_state["pending"] = {"recover_with": "previous-release"}
    journal.write_bytes(canonical_document_bytes(direct_state))

    assert updater.reconcile_boot(cycle_wait_seconds=0.1) == "RECONCILED"
    assert os.readlink(tmp_path / "install" / "current") == target_one
    reconciled = json.loads((tmp_path / "state" / "state.json").read_text())
    assert reconciled["pending"] is None
    assert reconciled["channels"]["canary"]["sequence"] == 1
    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert json.loads(journal.read_text())["pending"] == {
        "recover_with": "previous-release"
    }


def test_boot_reconcile_treats_legacy_pending_as_may_have_run(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "legacy-one")
    archive_two = _archive(marker_path=tmp_path / "legacy-two")
    metadata_one = _canary_metadata(
        private,
        sequence=1,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="legacy-tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="legacy-tree-two"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )
    restart_attempts: list[tuple[str, ...]] = []

    def crash_after_authorization(command) -> None:
        restart_attempts.append(tuple(command))
        raise KeyboardInterrupt("simulated reboot after restart authorization")

    updater.service_restarter = crash_after_authorization
    with pytest.raises(KeyboardInterrupt, match="after restart authorization"):
        _update(updater, private, channel="canary", sequence=2)

    state_path = tmp_path / "state" / "state.json"
    uncertain = json.loads(state_path.read_text())
    assert uncertain["pending"]["stage"] == "may_have_run"
    legacy_pending = dict(uncertain["pending"])
    legacy_pending.pop("stage")
    state_path.write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_validator_updater_state_v2",
                "channels": uncertain["channels"],
                "pending": legacy_pending,
            }
        )
    )
    direct_state = json.loads(journal.read_text())
    direct_state["pending"] = {"recover_with": "authorized-target"}
    journal.write_bytes(canonical_document_bytes(direct_state))

    assert updater.reconcile_boot(cycle_wait_seconds=0.1) == "RECONCILED"
    reconciled = json.loads(state_path.read_text())
    assert reconciled["schema"] == UPDATER_STATE_SCHEMA
    assert reconciled["selected_channel"] == "canary"
    assert reconciled["pending"] is None
    assert reconciled["channels"]["canary"]["sequence"] == 2
    assert restart_attempts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]
    assert json.loads(journal.read_text())["pending"] == {
        "recover_with": "authorized-target"
    }


@pytest.mark.parametrize("roll_back", (False, True), ids=("new-target", "rollback"))
def test_separate_start_gate_accepts_only_updater_authorized_target_while_locks_held(
    tmp_path: Path,
    roll_back: bool,
) -> None:
    """Catch the real systemd nested-lock failure with process-owned flocks."""

    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "gate-one")
    archive_two = _archive(marker_path=tmp_path / "gate-two")
    metadata_one = _canary_metadata(
        private,
        sequence=1,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="gate-tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="gate-tree-two"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    committed_target = os.readlink(tmp_path / "install" / "current")
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )

    def crash_after_authorization(_command) -> None:
        raise KeyboardInterrupt("hold the root-authorized restart boundary")

    updater.service_restarter = crash_after_authorization
    with pytest.raises(KeyboardInterrupt, match="root-authorized restart"):
        _update(updater, private, channel="canary", sequence=2)

    state_path = tmp_path / "state" / "state.json"
    pending_state = json.loads(state_path.read_text())
    assert pending_state["pending"]["stage"] == "may_have_run"
    if roll_back:
        current = tmp_path / "install" / "current"
        current.unlink()
        current.symlink_to(committed_target)

    updater_lock = _lock_for_other_process(tmp_path / "state" / "updater.lock")
    cycle_lock = _lock_for_other_process(journal.with_name("cycle.lock"))
    try:
        result = _run_reconcile_in_separate_process(updater)
        prepared_state = json.loads(state_path.read_text())
        prepared_state["pending"]["stage"] = "prepared"
        state_path.write_bytes(canonical_document_bytes(prepared_state))
        prepared_guard = _run_reconcile_in_separate_process(updater)
        state_path.write_bytes(canonical_document_bytes(pending_state))
        journal_document = json.loads(journal.read_text())
        journal_document["pending"] = {"signed_intent": "unresolved"}
        journal.write_bytes(canonical_document_bytes(journal_document))
        unresolved_journal_guard = _run_reconcile_in_separate_process(updater)
        journal_document["pending"] = None
        journal.write_bytes(canonical_document_bytes(journal_document))
        fcntl.flock(cycle_lock, fcntl.LOCK_UN)
        os.close(cycle_lock)
        cycle_lock = -1
        missing_cycle_guard = _run_reconcile_in_separate_process(updater)
    finally:
        if cycle_lock >= 0:
            fcntl.flock(cycle_lock, fcntl.LOCK_UN)
            os.close(cycle_lock)
        fcntl.flock(updater_lock, fcntl.LOCK_UN)
        os.close(updater_lock)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "START_AUTHORIZED"
    assert prepared_guard.returncode == 23
    assert "did not finish before timeout" in prepared_guard.stderr
    assert unresolved_journal_guard.returncode == 23
    assert "unresolved or ambiguous submission" in unresolved_journal_guard.stderr
    assert missing_cycle_guard.returncode == 23
    assert "did not finish before timeout" in missing_cycle_guard.stderr
    # The child gate is read-only. The lock-owning parent commits or clears this
    # record only after systemd reports whether the service became ready.
    assert json.loads(state_path.read_text()) == pending_state


@pytest.mark.parametrize("roll_back", (False, True), ids=("activate", "roll-back"))
def test_update_restart_callback_runs_start_gate_under_the_real_outer_locks(
    tmp_path: Path,
    roll_back: bool,
) -> None:
    """Exercise the same nested process/lock shape as systemctl restart."""

    private = Ed25519PrivateKey.generate()
    archive_one = _archive(marker_path=tmp_path / "nested-one")
    archive_two = _archive(marker_path=tmp_path / "nested-two")
    metadata_one = _canary_metadata(
        private,
        sequence=1,
        archive=archive_one,
        tree=_tree_digest(tmp_path, archive_one, name="nested-tree-one"),
    )
    metadata_two = _canary_metadata(
        private,
        sequence=2,
        archive=archive_two,
        tree=_tree_digest(tmp_path, archive_two, name="nested-tree-two"),
    )
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata_one,
        archive=archive_one,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"
    committed_target = os.readlink(tmp_path / "install" / "current")
    updater.fetcher = lambda url, _maximum: (
        metadata_two if url.endswith(".json") else archive_two
    )
    gated_targets: list[str] = []

    def nested_systemd_start(command) -> None:
        assert tuple(command) == (SYSTEMCTL, "restart", VALIDATOR_SERVICE)
        gated_targets.append(os.readlink(tmp_path / "install" / "current"))
        result = _run_reconcile_in_separate_process(updater)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "START_AUTHORIZED"
        if roll_back and len(gated_targets) == 1:
            raise OSError("new service failed readiness after its start gate")

    updater.service_restarter = nested_systemd_start
    if roll_back:
        with pytest.raises(UpdateRefused, match="prior release was restored"):
            _update(updater, private, channel="canary", sequence=2)
    else:
        assert _update(updater, private, channel="canary", sequence=2) == "ACTIVATED"

    target_two = f"releases/{hashlib.sha256(archive_two).hexdigest()}"
    assert gated_targets == (
        [target_two, committed_target] if roll_back else [target_two]
    )
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["pending"] is None
    assert state["channels"]["canary"]["sequence"] == (1 if roll_back else 2)
    assert os.readlink(tmp_path / "install" / "current") == (
        committed_target if roll_back else target_two
    )


def test_separate_start_gate_rejects_unrelated_start_while_updater_lock_is_held(
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
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
    )
    assert _update(updater, private, channel="canary", sequence=1) == "ACTIVATED"

    updater_lock = _lock_for_other_process(tmp_path / "state" / "updater.lock")
    cycle_lock = _lock_for_other_process(journal.with_name("cycle.lock"))
    try:
        result = _run_reconcile_in_separate_process(updater)
    finally:
        fcntl.flock(cycle_lock, fcntl.LOCK_UN)
        os.close(cycle_lock)
        fcntl.flock(updater_lock, fcntl.LOCK_UN)
        os.close(updater_lock)

    assert result.returncode == 23
    assert "did not finish before timeout" in result.stderr


def test_first_install_start_gate_accepts_exact_authorized_target_with_locks_held(
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

    gate_results: list[str] = []

    def nested_first_systemd_start(command) -> None:
        assert tuple(command) == (SYSTEMCTL, "restart", VALIDATOR_SERVICE)
        pending = json.loads((tmp_path / "state" / "state.json").read_text())
        assert pending["channels"] == {}
        assert pending["pending"]["previous_current"] is None
        assert pending["pending"]["stage"] == "may_have_run"
        result = _run_reconcile_in_separate_process(updater)
        assert result.returncode == 0, result.stderr
        gate_results.append(result.stdout.strip())

    updater.service_restarter = nested_first_systemd_start
    assert _bootstrap(updater, private, channel="canary", sequence=1) == "ACTIVATED"

    assert gate_results == ["START_AUTHORIZED"]
    committed = json.loads((tmp_path / "state" / "state.json").read_text())
    assert committed["pending"] is None
    assert committed["channels"]["canary"]["sequence"] == 1


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


def test_corrupt_inactive_release_directory_is_repaired_from_signed_archive(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive(marker_path=tmp_path / "repair-marker")
    metadata = _canary_metadata(
        private,
        sequence=3,
        archive=archive,
        tree=_tree_digest(tmp_path, archive, name="repair-tree"),
    )
    digest = hashlib.sha256(archive).hexdigest()
    corrupt = tmp_path / "install" / "releases" / digest
    corrupt.mkdir(parents=True, mode=0o755)
    (corrupt / "README").write_text("truncated\n")
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

    assert _update(updater, private, channel="canary", sequence=3) == "ACTIVATED"
    assert (corrupt / "README").read_text() == "immutable release\n"
    assert (corrupt / "bin" / "cathedral-validator").is_file()
    assert restarts == [(SYSTEMCTL, "restart", VALIDATOR_SERVICE)]


def test_corrupt_current_release_directory_is_never_deleted(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive(marker_path=tmp_path / "protected-marker")
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive, name="protected-tree"),
    )
    digest = hashlib.sha256(archive).hexdigest()
    target = f"releases/{digest}"
    corrupt = tmp_path / "install" / target
    corrupt.mkdir(parents=True, mode=0o755)
    sentinel = corrupt / "do-not-delete"
    sentinel.write_text("current release\n")
    (tmp_path / "install" / "current").symlink_to(target)
    journal = tmp_path / "journal" / "state.json"
    _journal(journal)
    restarts: list[tuple[str, ...]] = []
    updater = _updater(
        tmp_path,
        journal=journal,
        metadata=metadata,
        archive=archive,
        restarts=restarts,
        seed_current=False,
    )

    with pytest.raises(UpdateRefused, match="current release tree"):
        _update(updater, private, channel="canary", sequence=1)

    assert sentinel.read_text() == "current release\n"
    assert os.readlink(tmp_path / "install" / "current") == target
    assert restarts == []


def test_operation_deadline_stops_work_after_a_slow_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Ed25519PrivateKey.generate()
    archive = _archive()
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(tmp_path, archive, name="deadline-tree"),
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
    clock = [0.0]
    monkeypatch.setattr(updater_module.time, "monotonic", lambda: clock[0])

    def slow_fetch(_url: str, _maximum: int) -> bytes:
        clock[0] = 2.0
        return metadata

    updater.fetcher = slow_fetch
    with pytest.raises(UpdateRefused, match="deadline expired during release download"):
        updater.update(
            metadata_url="https://releases.example/canary.json",
            channel="canary",
            public_key=private.public_key(),
            pause_file=tmp_path / "pause",
            minimum_sequence=1,
            cycle_wait_seconds=0.1,
            operation_timeout_seconds=1.0,
        )

    assert restarts == []
    assert os.readlink(tmp_path / "install" / "current") == PREVIOUS_TARGET


def test_systemctl_timeout_is_bounded_by_both_service_and_operation_deadlines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_timeouts: list[float] = []

    def fake_run(command, **kwargs) -> None:
        assert command == [SYSTEMCTL, "restart", VALIDATOR_SERVICE]
        assert kwargs["check"] is True
        observed_timeouts.append(kwargs["timeout"])

    monkeypatch.setattr(updater_module.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(updater_module.subprocess, "run", fake_run)
    updater = SignedReleaseUpdater(
        install_root=tmp_path / "install",
        state_root=tmp_path / "state",
        expected_hotkey="5ExpectedValidator",
        journal_scope_root=tmp_path / "journal-scope",
    )

    updater._restart_service(deadline_monotonic=1_000.0)
    updater._restart_service(deadline_monotonic=250.0)

    assert observed_timeouts == [DEFAULT_SERVICE_CONTROL_TIMEOUT_SECONDS, 250.0]


def test_https_fetch_uses_single_raw_reads_and_rechecks_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    calls = {"read": 0, "read1": 0}

    class FakeResponse:
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def geturl(self) -> str:
            return "https://releases.example/archive"

        def read(self, _size: int) -> bytes:
            calls["read"] += 1
            raise AssertionError("buffered read must not be used when read1 exists")

        def read1(self, _size: int) -> bytes:
            calls["read1"] += 1
            clock[0] = 2.0
            return b"partial"

    class FakeOpener:
        def open(self, _request, *, timeout: float):
            assert timeout == 1.0
            return FakeResponse()

    monkeypatch.setattr(updater_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        updater_module.urllib.request,
        "build_opener",
        lambda *_handlers: FakeOpener(),
    )

    with pytest.raises(UpdateRefused, match="deadline expired during HTTPS download"):
        updater_module.fetch_bounded_https(
            "https://releases.example/archive",
            maximum_bytes=100,
            timeout_seconds=20.0,
            deadline_monotonic=1.0,
        )

    assert calls == {"read": 0, "read1": 1}


def test_boot_reconcile_cli_accepts_no_release_channel_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reconciliations: list[dict[str, float]] = []

    class FakeUpdater:
        def __init__(self, **_kwargs) -> None:
            pass

        def reconcile_boot(self, **kwargs) -> str:
            reconciliations.append(kwargs)
            return "RECONCILED"

    monkeypatch.setattr(updater_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater_module,
        "load_expected_hotkey_identity",
        lambda _path: "5ExpectedValidator",
    )
    monkeypatch.setattr(updater_module, "SignedReleaseUpdater", FakeUpdater)

    refused = updater_module.main(
        ["--reconcile-boot", "--channel=canary", "--identity-file=/ignored"]
    )
    assert refused == 2
    assert "does not accept a caller-selected channel" in capsys.readouterr().err
    assert reconciliations == []

    accepted = updater_module.main(
        [
            "--reconcile-boot",
            "--identity-file=/ignored",
            "--cycle-wait-seconds=17",
            "--operation-timeout-seconds=41",
        ]
    )
    assert accepted == 0
    assert "CATHEDRAL_VALIDATOR_UPDATE_RECONCILED" in capsys.readouterr().out
    assert reconciliations == [
        {"cycle_wait_seconds": 17.0, "operation_timeout_seconds": 41.0}
    ]


def test_deploy_contract_is_unprivileged_hotkey_only_and_operational() -> None:
    root = Path(__file__).resolve().parents[2]
    deploy = root / "deploy" / "validator-update"
    sysusers = (deploy / "cathedral-validator.sysusers").read_text()
    assert "u cathedral-validator" in sysusers
    direct = (deploy / "cathedral-validator-direct.service").read_text()
    assert "Requires=cathedral-validator-boot-reconcile.service" in direct
    assert (
        "After=network-online.target cathedral-validator-boot-reconcile.service"
        in direct
    )
    assert "User=cathedral-validator" in direct
    assert "Type=notify" in direct
    assert "NotifyAccess=main" in direct
    assert "Restart=on-failure" in direct
    assert "RestartPreventExitStatus=2" in direct
    assert "TimeoutStartSec=120s" in direct
    assert "LoadCredential=validator-hotkey:" in direct
    assert "\nCondition" not in direct
    assert "AssertPathExists=/etc/cathedral-validator/direct.env" in direct
    assert "AssertPathExists=/etc/cathedral-validator/identity.env" in direct
    assert "AssertPathExists=/etc/cathedral-validator/validator-hotkey" in direct
    assert "EnvironmentFile=/etc/cathedral-validator/identity.env" in direct
    assert direct.rindex("EnvironmentFile=/etc/cathedral-validator/identity.env") > (
        direct.rindex("EnvironmentFile=-/etc/cathedral-validator/direct-telemetry.env")
    )
    assert "Environment=HOME=/var/lib/cathedral-validator" in direct
    assert "Environment=PEX_ROOT=/run/cathedral-validator-pex" in direct
    assert (
        "RuntimeDirectory=cathedral-validator-wallet cathedral-validator-pex" in direct
    )
    assert "/var/lib/cathedral-validator/.cache/pex" not in direct
    assert "--wallet-path=/run/cathedral-validator-wallet" in direct
    assert "--expected-hotkey=${CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY}" in direct
    assert "AssertPathExists=/etc/cathedral-validator/snp-policy.json" in direct
    assert (
        "AssertFileIsExecutable=/opt/cathedral-validator/current/bin/"
        "cathedral-tdx-verifier" in direct
    )
    assert (
        "AssertFileIsExecutable=/opt/cathedral-validator/current/bin/snpguest" in direct
    )
    assert "AssertFileIsExecutable=/usr/bin/python3.12" in direct
    assert (
        "AssertFileIsExecutable=/opt/cathedral-validator/current/bin/"
        "cathedral-validator" in direct
    )
    assert "--snp-policy=${CATHEDRAL_SNP_POLICY}" in direct
    assert "--qvl=/opt/cathedral-validator/current/bin/cathedral-tdx-verifier" in direct
    assert "--snpguest=/opt/cathedral-validator/current/bin/snpguest" in direct
    assert "${CATHEDRAL_VALIDATOR_QVL}" not in direct
    assert "${CATHEDRAL_SNPGUEST}" not in direct
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
    telemetry_env = (deploy / "direct-telemetry.env.example").read_text()
    assert (
        'CATHEDRAL_VALIDATOR_TELEMETRY_ARGS="--telemetry-spool '
        "/var/lib/cathedral-validator-telemetry/events.jsonl "
        '--telemetry-reader-group cathedral-telemetry"' in telemetry_env
    )
    assert "CATHEDRAL_TELEMETRY_ENDPOINT" not in telemetry_env
    assert "TOKEN_FILE" not in telemetry_env
    identity_env = (deploy / "identity.env.example").read_text()
    assert "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=YOUR_HOTKEY_SS58" in identity_env
    assert "PRIVATE" not in identity_env
    update_env = (deploy / "update.env.example").read_text()
    assert "CATHEDRAL_VALIDATOR_DIRECT_JOURNAL" not in update_env

    for name, minimum in (
        ("cathedral-validator-canary-update.service", "CANARY"),
        ("cathedral-validator-update.service", "STABLE"),
    ):
        unit = (deploy / name).read_text()
        assert "ProtectHome=true" in unit
        assert "\nCondition" not in unit
        assert "AssertPathExists=/etc/cathedral-validator/update.env" in unit
        assert "AssertPathExists=/etc/cathedral-validator/identity.env" in unit
        assert (
            "AssertPathExists=/etc/cathedral-validator/"
            "runtime-release-public-key.pem" in unit
        )
        assert "EnvironmentFile=/etc/cathedral-validator/identity.env" not in unit
        assert "--identity-file=/etc/cathedral-validator/identity.env" in unit
        assert (
            "--public-key=/etc/cathedral-validator/"
            "runtime-release-public-key.pem" in unit
        )
        assert "update-public-key.pem" not in unit
        assert "--expected-hotkey" not in unit
        assert "--journal" not in unit
        assert (
            "ExecStart=/usr/local/lib/cathedral-validator-updater/bin/"
            "cathedral-validator-update "
        ) in unit
        assert (
            "AssertFileIsExecutable=/usr/local/lib/"
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
        assert (
            f"TimeoutStartSec={int(DEFAULT_OPERATION_TIMEOUT_SECONDS + SYSTEMD_TIMEOUT_MARGIN_SECONDS)}s"
            in unit
        )

    assert DEFAULT_SERVICE_CONTROL_TIMEOUT_SECONDS >= 150 + 120 + 30

    boot_reconcile = (deploy / "cathedral-validator-boot-reconcile.service").read_text()
    assert "\nCondition" not in boot_reconcile
    assert "Before=cathedral-validator-direct.service" in boot_reconcile
    assert (
        "ExecStart=/usr/local/lib/cathedral-validator-updater/bin/"
        "cathedral-validator-update --reconcile-boot "
        "--identity-file=/etc/cathedral-validator/identity.env\n"
    ) in boot_reconcile
    for forbidden in (
        "--channel",
        "--metadata-url",
        "--public-key",
        "--minimum-sequence",
        "--bootstrap-first-install",
    ):
        assert forbidden not in boot_reconcile
    assert (
        f"TimeoutStartSec={int(DEFAULT_OPERATION_TIMEOUT_SECONDS + SYSTEMD_TIMEOUT_MARGIN_SECONDS)}s"
        in boot_reconcile
    )
    assert "LoadCredential=" not in boot_reconcile
    assert "EnvironmentFile=" not in boot_reconcile
    assert (
        "InaccessiblePaths=/etc/cathedral-validator/validator-hotkey "
        "-/var/lib/cathedral-validator/.bittensor "
        "-/run/cathedral-validator-wallet -/run/cathedral-validator-pex"
        in boot_reconcile
    )


def test_real_linux_release_job_builds_and_starts_the_production_pex() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "tests.yml").read_text()
    release_job = workflow.split("  validator-release:\n", 1)[1]

    assert "continue-on-error" not in release_job
    assert "pex==2.101.1" in release_job
    assert "--lock requirements/validator-release-cpython312-linux-x86_64.pex.lock" in (
        release_job
    )
    assert "runtime_lock=Path(" in release_job
    assert "runtime_distributions=Path(" in release_job
    assert "CPython==3.12.*" in release_job
    assert "cmp /tmp/cathedral-validator-one.pex" in release_job
    assert 'builder["_validator_pex"](pex)' in release_job
    assert 'builder["validator_release_tree"](' in release_job
    assert 'qvl=Path("/tmp/cathedral-tdx-verifier")' in release_job
    assert 'snpguest=Path("/tmp/snpguest")' in release_job
    assert 'source_revision=os.environ["GITHUB_SHA"]' in release_job
    assert "PEX_INTERPRETER=1" in release_job
    assert "PEX_ROOT=/tmp/cathedral-validator-pex-root" in release_job
    assert "CATHEDRAL_RELEASE_SMOKE_PEX_ROOT=" in release_job
    assert "CATHEDRAL_RELEASE_SMOKE_CHECKOUT=" in release_job
    assert release_job.count("HOME=/tmp/cathedral-validator-nobody-home") == 2
    assert "sudo -u nobody env" in release_job
    assert "tests/release_smoke/run_real_validator.py" in release_job
    assert "/tmp/cathedral-validator-release-smoke.py" in release_job
    assert (
        "-m cathedral_thin.independent_runtime.telemetry_exporter --help" in release_job
    )

    smoke = (root / "tests" / "release_smoke" / "run_real_validator.py").read_text()
    assert "snp_production.load_compute_contract()" in smoke
    assert "module_path.is_relative_to(pex_root)" in smoke
    assert "module_path.is_relative_to(checkout)" in smoke
    assert "CATHEDRAL_RELEASE_SMOKE_CHECKOUT" in smoke

    docs = (root / "docs" / "AUTO_UPDATE.md").read_text()
    assert "public bootstrap artifacts are not published yet" in docs
    assert "Do not install\nor enable updater units from a source checkout" in docs
    assert "signed manifest" in docs
    assert "two distinct Ed25519 keys" in docs
    assert "/etc/cathedral-validator/runtime-release-public-key.pem" in docs
    assert "/etc/cathedral-validator/update-public-key.pem" not in docs
    assert (
        "/usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update"
        in docs
    )
    assert "The updater has no access to the hotkey" in docs
    assert "releases.cathedral.com" not in docs
    assert "$(command -v cathedral-validator-update)" not in docs


def test_extracted_release_is_traversable_but_not_writable_by_service(
    tmp_path: Path,
) -> None:
    from cathedral_thin.independent_runtime.updater import extract_release_archive

    release = tmp_path / "release"
    previous_umask = os.umask(0o077)
    try:
        extract_release_archive(_archive(), release)
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE(release.stat().st_mode) == 0o755
    assert stat.S_IMODE((release / "bin").stat().st_mode) == 0o755
    assert (
        stat.S_IMODE((release / "bin" / "cathedral-validator").stat().st_mode) == 0o555
    )
    assert stat.S_IMODE((release / "README").stat().st_mode) == 0o444


def test_extraction_fsyncs_every_file_and_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_types: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        observed_types.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
        real_fsync(descriptor)

    monkeypatch.setattr(updater_module.os, "fsync", recording_fsync)
    extract_release_archive(_archive(), tmp_path / "durable-release")

    assert observed_types.count(stat.S_IFREG) >= 2
    assert observed_types.count(stat.S_IFDIR) >= 2


def test_offline_builder_rejects_decoy_telemetry_module_paths(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    builder = runpy.run_path(
        str(root / "deploy" / "validator-update" / "build_signed_release.py")
    )
    pex = tmp_path / "cathedral-validator.pex"
    _validator_pex(pex)
    original = pex.read_bytes()
    output = io.BytesIO()
    telemetry_paths = {
        "cathedral_thin/independent_runtime/telemetry.py",
        "cathedral_thin/independent_runtime/telemetry_exporter.py",
    }
    with zipfile.ZipFile(io.BytesIO(original), mode="r") as source:
        with zipfile.ZipFile(
            output, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as target:
            for member in source.infolist():
                if member.filename not in telemetry_paths:
                    target.writestr(member, source.read(member.filename))
            for path in sorted(telemetry_paths):
                target.writestr(f"decoy/{path}", b"")
    pex.write_bytes(b"#!/usr/bin/python3.12\n" + output.getvalue())
    pex.chmod(0o755)

    with pytest.raises(builder["UpdateRefused"], match="private telemetry runtime"):
        builder["_validator_pex"](pex)


def test_offline_builder_is_deterministic_and_promotes_exact_canary(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    builder = runpy.run_path(
        str(root / "deploy" / "validator-update" / "build_signed_release.py")
    )
    pex = tmp_path / "cathedral-validator.pex"
    _validator_pex(pex)
    qvl = tmp_path / "cathedral-tdx-verifier"
    qvl.write_bytes(b"#!/bin/sh\n# reviewed qvl\n")
    qvl.chmod(0o755)
    snpguest = tmp_path / "snpguest"
    snpguest.write_bytes(b"#!/bin/sh\n# reviewed snpguest\n")
    snpguest.chmod(0o755)
    private = Ed25519PrivateKey.generate()
    archive_dir_one = tmp_path / "archive-one"
    archive_dir_two = tmp_path / "archive-two"
    canary_one = tmp_path / "canary-one.json"
    canary_two = tmp_path / "canary-two.json"
    archive_dir_one.mkdir()
    archive_dir_two.mkdir()
    archive_dir_one.chmod(0o700)
    archive_dir_two.chmod(0o700)
    runtime_lock = (
        root / "requirements/validator-release-cpython312-linux-x86_64.pex.lock"
    )
    with zipfile.ZipFile(io.BytesIO(pex.read_bytes()), mode="r") as bundle:
        pex_info = bundle.read("PEX-INFO")
    pex_document = json.loads(pex_info)
    kwargs = {
        "pex": pex,
        "qvl": qvl,
        "snpguest": snpguest,
        "runtime_lock": runtime_lock,
        "runtime_distributions": tmp_path / "validator-release-distributions.json",
        "source_revision": "a" * 40,
        "archive_url_template": (
            "https://github.com/cathedralai/cathedral-validator/releases/download/"
            "validator-{archive_sha256}/"
            "cathedral-validator-{archive_sha256}.tar.gz"
        ),
        "sequence": 4,
        "private_key": private,
        "issued_unix": NOW,
        "lifetime_seconds": 3600,
    }
    kwargs["runtime_distributions"].write_text(
        json.dumps(
            {
                "schema": "cathedral_validator_pex_distributions_v1",
                "runtime_lock_sha256": hashlib.sha256(
                    runtime_lock.read_bytes()
                ).hexdigest(),
                "pex_sha256": hashlib.sha256(pex.read_bytes()).hexdigest(),
                "pex_info_sha256": hashlib.sha256(pex_info).hexdigest(),
                "distributions": pex_document["distributions"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    archive_one = builder["build_canary"](
        archive_out_dir=archive_dir_one, metadata_out=canary_one, **kwargs
    )
    archive_two = builder["build_canary"](
        archive_out_dir=archive_dir_two, metadata_out=canary_two, **kwargs
    )
    assert archive_one.read_bytes() == archive_two.read_bytes()
    assert canary_one.read_bytes() == canary_two.read_bytes()

    from cathedral_thin.independent_runtime.updater import extract_release_archive

    release = tmp_path / "extracted"
    extract_release_archive(archive_one.read_bytes(), release)
    manifest = json.loads((release / "RELEASE.json").read_text())
    assert manifest["schema"] == "cathedral_validator_bundle_v2"
    assert manifest["entry_point"] == (
        "cathedral_thin.independent_runtime.direct_validator:main"
    )
    assert manifest["telemetry_module"] == (
        "cathedral_thin.independent_runtime.telemetry_exporter"
    )
    assert manifest["project_distribution"].startswith("cathedral_scaffold-1.2.3")
    assert manifest["source_revision"] == "a" * 40
    assert manifest["qvl_path"] == "bin/cathedral-tdx-verifier"
    assert manifest["snpguest_path"] == "bin/snpguest"
    assert (release / manifest["qvl_path"]).read_bytes() == qvl.read_bytes()
    assert (release / manifest["snpguest_path"]).read_bytes() == snpguest.read_bytes()
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
                    "--expected-hotkey",
                    "5ReleaseFixtureValidator",
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
        enforce_content_addressed=True,
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
