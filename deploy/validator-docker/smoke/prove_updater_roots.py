#!/usr/bin/python3.12
"""Prove the image updater accepts volume directories and refuses dest symlinks.

The image bakes /opt/cathedral-validator and /var/lib/cathedral-validator-update
as compatibility symlinks. SignedReleaseUpdater rejects those as install and
state roots. PID1 must pass the real volume directories. This probe runs inside
the image with the signed updater venv and does not talk to the network.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import pwd
import tarfile
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    METADATA_SCHEMA,
    SignedReleaseUpdater,
    UpdateRefused,
    release_tree_sha256,
)

VOLUME_INSTALL = Path("/var/lib/cathedral/releases")
VOLUME_STATE = Path("/var/lib/cathedral/update")
VOLUME_HOME = Path("/var/lib/cathedral/validator")
IMAGE_INSTALL = Path("/opt/cathedral-validator")
IMAGE_STATE = Path("/var/lib/cathedral-validator-update")
HOTKEY = "5SmokeUpdaterRoots"
ARCHIVE_URL = "https://releases.example/validator.tar.gz"
METADATA_URL = "https://releases.example/canary.json"


def _archive(*, marker: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        program = f"#!/bin/sh\necho {marker}\nexit 0\n".encode("ascii")
        info = tarfile.TarInfo("bin/cathedral-validator")
        info.mode = 0o755
        info.size = len(program)
        bundle.addfile(info, io.BytesIO(program))
        readme = f"immutable release {marker}\n".encode("ascii")
        info = tarfile.TarInfo("README")
        info.mode = 0o644
        info.size = len(readme)
        bundle.addfile(info, io.BytesIO(readme))
    return output.getvalue()


def _tree_digest(archive: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="cathedral-smoke-tree-") as raw:
        root = Path(raw)
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
    version: str,
) -> bytes:
    now = int(time.time())
    return _sign(
        private,
        {
            "schema": METADATA_SCHEMA,
            "channel": "canary",
            "sequence": sequence,
            "issued_unix": now,
            "expires_unix": now + 3600,
            "release": {
                "version": version,
                "archive_url": ARCHIVE_URL,
                "archive_sha256": hashlib.sha256(archive).hexdigest(),
                "tree_sha256": tree,
                "entrypoint": "bin/cathedral-validator",
            },
        },
    )


def _prepare_volume_directories() -> None:
    for path, mode in (
        (VOLUME_INSTALL, 0o755),
        (VOLUME_STATE, 0o700),
        (VOLUME_HOME, 0o700),
    ):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
    if not IMAGE_INSTALL.is_symlink() or IMAGE_INSTALL.resolve() != VOLUME_INSTALL:
        raise SystemExit("image install dest is not the volume releases directory")
    if not IMAGE_STATE.is_symlink() or IMAGE_STATE.resolve() != VOLUME_STATE:
        raise SystemExit("image state dest is not the volume update directory")


def _updater(
    *,
    install_root: Path,
    state_root: Path,
    metadata: bytes,
    archive: bytes,
    expected_uid: int,
) -> SignedReleaseUpdater:
    def restarter(_command: object) -> None:
        return None

    def fetcher(url: str, _maximum: int) -> bytes:
        if url.endswith(".json"):
            return metadata
        return archive

    return SignedReleaseUpdater(
        install_root=install_root,
        state_root=state_root,
        expected_hotkey=HOTKEY,
        expected_uid=expected_uid,
        fetcher=fetcher,
        service_restarter=restarter,
    )


def _refuse_symlink_roots(private: Ed25519PrivateKey, expected_uid: int) -> None:
    archive = _archive(marker="symlink")
    metadata = _canary_metadata(
        private,
        sequence=1,
        archive=archive,
        tree=_tree_digest(archive),
        version="1.0.0",
    )
    updater = _updater(
        install_root=IMAGE_INSTALL,
        state_root=IMAGE_STATE,
        metadata=metadata,
        archive=archive,
        expected_uid=expected_uid,
    )
    for method, kwargs in (
        (
            updater.bootstrap,
            {
                "metadata_url": METADATA_URL,
                "channel": "canary",
                "public_key": private.public_key(),
                "pause_file": VOLUME_STATE / "pause",
                "minimum_sequence": 1,
                "validator_uid": expected_uid,
                "validator_gid": os.getegid(),
                "first_install_metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "cycle_wait_seconds": 0.1,
                "operation_timeout_seconds": 30,
            },
        ),
        (
            updater.update,
            {
                "metadata_url": METADATA_URL,
                "channel": "canary",
                "public_key": private.public_key(),
                "pause_file": VOLUME_STATE / "pause",
                "minimum_sequence": 1,
                "cycle_wait_seconds": 0.1,
                "operation_timeout_seconds": 30,
            },
        ),
        (
            updater.reconcile_boot,
            {"cycle_wait_seconds": 0.1, "operation_timeout_seconds": 5},
        ),
    ):
        try:
            method(**kwargs)
        except UpdateRefused as exc:
            if "not root-controlled" not in str(exc):
                raise SystemExit(f"symlink root refused for the wrong reason: {exc}")
        else:
            raise SystemExit(f"{method.__name__} accepted a symlink root")


def _bootstrap_update_reconcile(
    private: Ed25519PrivateKey, *, expected_uid: int, validator_gid: int
) -> tuple[str, str, str]:
    first_archive = _archive(marker="first")
    first_metadata = _canary_metadata(
        private,
        sequence=1,
        archive=first_archive,
        tree=_tree_digest(first_archive),
        version="1.0.0",
    )
    second_archive = _archive(marker="second")
    second_metadata = _canary_metadata(
        private,
        sequence=2,
        archive=second_archive,
        tree=_tree_digest(second_archive),
        version="1.0.1",
    )
    first = _updater(
        install_root=VOLUME_INSTALL,
        state_root=VOLUME_STATE,
        metadata=first_metadata,
        archive=first_archive,
        expected_uid=expected_uid,
    )
    bootstrapped = first.bootstrap(
        metadata_url=METADATA_URL,
        channel="canary",
        public_key=private.public_key(),
        pause_file=VOLUME_STATE / "pause",
        minimum_sequence=1,
        validator_uid=pwd.getpwnam("cathedral-validator").pw_uid,
        validator_gid=validator_gid,
        first_install_metadata_sha256=hashlib.sha256(first_metadata).hexdigest(),
        cycle_wait_seconds=0.1,
        operation_timeout_seconds=30,
    )
    second = _updater(
        install_root=VOLUME_INSTALL,
        state_root=VOLUME_STATE,
        metadata=second_metadata,
        archive=second_archive,
        expected_uid=expected_uid,
    )
    updated = second.update(
        metadata_url=METADATA_URL,
        channel="canary",
        public_key=private.public_key(),
        pause_file=VOLUME_STATE / "pause",
        minimum_sequence=1,
        cycle_wait_seconds=0.1,
        operation_timeout_seconds=30,
    )
    reconciled = second.reconcile_boot(
        cycle_wait_seconds=0.1, operation_timeout_seconds=5
    )
    return bootstrapped, updated, reconciled


def main() -> int:
    previous_umask = os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise SystemExit("updater root probe must run as root")
        account = pwd.getpwnam("cathedral-validator")
        _prepare_volume_directories()
        private = Ed25519PrivateKey.generate()
        _refuse_symlink_roots(private, expected_uid=0)
        print(
            "CATHEDRAL_VALIDATOR_SMOKE_UPDATER_ROOTS symlink_roots_refused=true",
            flush=True,
        )
        bootstrapped, updated, reconciled = _bootstrap_update_reconcile(
            private, expected_uid=0, validator_gid=account.pw_gid
        )
        if (bootstrapped, updated, reconciled) != (
            "ACTIVATED",
            "ACTIVATED",
            "RECONCILED",
        ):
            raise SystemExit(
                "volume roots did not bootstrap, update, and reconcile: "
                f"{bootstrapped} {updated} {reconciled}"
            )
        print(
            "CATHEDRAL_VALIDATOR_SMOKE_UPDATER_ROOTS "
            f"bootstrap={bootstrapped} update={updated} reconcile={reconciled}",
            flush=True,
        )
        return 0
    except UpdateRefused as exc:
        raise SystemExit(f"CATHEDRAL_VALIDATOR_UPDATE_REFUSED: {exc}") from exc
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
