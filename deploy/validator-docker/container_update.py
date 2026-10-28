#!/usr/bin/python3.12
"""Run one signed updater operation from the container supervisor.

This file is image-bootstrap code. It imports SignedReleaseUpdater from the
verified updater venv and plugs service_restarter so a container never calls
systemctl. The signed channel, idle-journal wait, and current swap are
unchanged.
"""

from __future__ import annotations

import argparse
import os
import pwd
import socket
import sys
from pathlib import Path
from typing import Sequence

from cathedral_thin.independent_runtime.updater import (
    SYSTEMCTL,
    VALIDATOR_SERVICE,
    SignedReleaseUpdater,
    UpdateRefused,
    load_expected_hotkey_identity,
    load_pinned_public_key,
)


def _fixed_action(command: Sequence[str]) -> str:
    if tuple(command) not in {
        (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
        (SYSTEMCTL, "stop", VALIDATOR_SERVICE),
    }:
        raise UpdateRefused("validator service command is not fixed")
    return str(command[1])


def _socket_restarter(socket_path: Path) -> object:
    def restarter(command: Sequence[str]) -> None:
        action = _fixed_action(command)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(300)
            client.connect(os.fspath(socket_path))
            client.sendall(f"{action}\n".encode("ascii"))
            reply = b""
            while b"\n" not in reply:
                chunk = client.recv(256)
                if not chunk:
                    raise UpdateRefused("container service control closed")
                reply += chunk
                if len(reply) > 256:
                    raise UpdateRefused("container service control reply is too large")
        except OSError as exc:
            raise UpdateRefused("container service control failed") from exc
        finally:
            client.close()
        text = reply.decode("ascii", errors="replace").split("\n", 1)[0]
        if text != "ok":
            raise UpdateRefused(f"container validator service {action} failed: {text}")

    return restarter


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Container updater entry that uses service_restarter"
    )
    parser.add_argument("--channel", choices=("canary", "stable"))
    parser.add_argument("--metadata-url")
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--minimum-sequence", type=int)
    parser.add_argument("--bootstrap-first-install", action="store_true")
    parser.add_argument("--reconcile-boot", action="store_true")
    parser.add_argument("--first-install-metadata-sha256")
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--pause-file", type=Path)
    parser.add_argument("--container-service-control", type=Path, required=True)
    options = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("the updater must run as root")
    try:
        expected_hotkey = load_expected_hotkey_identity(options.identity_file)
        updater = SignedReleaseUpdater(
            install_root=options.install_root,
            state_root=options.state_root,
            expected_hotkey=expected_hotkey,
            service_restarter=_socket_restarter(options.container_service_control),
        )
        if options.reconcile_boot:
            if any(
                value is not None
                for value in (
                    options.channel,
                    options.metadata_url,
                    options.public_key,
                    options.minimum_sequence,
                    options.first_install_metadata_sha256,
                )
            ):
                raise UpdateRefused(
                    "boot reconciliation does not accept a caller-selected channel"
                )
            status = updater.reconcile_boot()
            print(f"CATHEDRAL_VALIDATOR_UPDATE_{status}")
            return 0
        if any(
            value is None
            for value in (
                options.channel,
                options.metadata_url,
                options.public_key,
                options.minimum_sequence,
            )
        ):
            raise UpdateRefused(
                "release update requires channel, metadata URL, public key, "
                "and minimum sequence"
            )
        key = load_pinned_public_key(options.public_key)
        arguments = {
            "metadata_url": options.metadata_url,
            "channel": options.channel,
            "public_key": key,
            "pause_file": options.pause_file
            or Path("/etc/cathedral-validator/update.pause"),
            "minimum_sequence": options.minimum_sequence,
        }
        if options.bootstrap_first_install:
            if options.first_install_metadata_sha256 is None:
                raise UpdateRefused(
                    "first-install bootstrap requires the exact stable metadata "
                    "digest bound by the signed bootstrap"
                )
            try:
                validator = pwd.getpwnam("cathedral-validator")
            except KeyError as exc:
                raise UpdateRefused(
                    "cathedral-validator service account does not exist"
                ) from exc
            status = updater.bootstrap(
                **arguments,
                validator_uid=validator.pw_uid,
                validator_gid=validator.pw_gid,
                first_install_metadata_sha256=options.first_install_metadata_sha256,
            )
        else:
            if options.first_install_metadata_sha256 is not None:
                raise UpdateRefused(
                    "the first-install metadata digest applies only to "
                    "--bootstrap-first-install"
                )
            status = updater.update(**arguments)
    except UpdateRefused as exc:
        print(f"CATHEDRAL_VALIDATOR_UPDATE_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"CATHEDRAL_VALIDATOR_UPDATE_{status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
