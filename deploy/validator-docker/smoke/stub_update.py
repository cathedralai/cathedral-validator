#!/usr/bin/python3.12
"""Smoke-only updater. Bound over container_update.py. No network.

The signed updater refuses symlink install and state roots. This stub does
the same check so the smoke proves PID1 passed the real volume directories.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke updater (offline stub)")
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--container-service-control", type=Path, required=True)
    parser.add_argument("--reconcile-boot", action="store_true")
    parser.add_argument("--channel")
    parser.add_argument("--metadata-url")
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--minimum-sequence", type=int)
    parser.add_argument("--bootstrap-first-install", action="store_true")
    parser.add_argument("--first-install-metadata-sha256")
    parser.add_argument("--pause-file", type=Path)
    options = parser.parse_args(argv)
    if options.install_root.is_symlink() or options.state_root.is_symlink():
        print(
            "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: "
            "update installation directory is not root-controlled",
            file=sys.stderr,
        )
        return 2
    if not options.install_root.is_dir() or not options.state_root.is_dir():
        print(
            "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: update roots are missing",
            file=sys.stderr,
        )
        return 2
    if options.metadata_url:
        print(
            "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: smoke updater has no release channel",
            file=sys.stderr,
        )
        return 2
    record = {
        "reconcile_boot": options.reconcile_boot,
        "install_root": str(options.install_root),
        "state_root": str(options.state_root),
        "install_root_is_symlink": False,
        "state_root_is_symlink": False,
    }
    marker = options.state_root / "smoke-updater.json"
    marker.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    if options.reconcile_boot:
        print("CATHEDRAL_VALIDATOR_UPDATE_RECONCILED")
        return 0
    print("CATHEDRAL_VALIDATOR_UPDATE_UNCHANGED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
