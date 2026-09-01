#!/usr/bin/env python3
"""Bounded state waiter used by the disposable live updater controller."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

MAX_WAIT_SECONDS = 600


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument(
        "--install-root", type=Path, default=Path("/opt/cathedral-validator")
    )
    parser.add_argument("--timeout-seconds", type=float)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--committed", nargs=2, metavar=("CHANNEL", "SEQUENCE"))
    group.add_argument("--pending-target")
    group.add_argument("--snapshot", metavar="CHANNEL")
    args = parser.parse_args()
    if args.snapshot is not None:
        state = json.loads(args.state.read_text(encoding="ascii"))
        channels = state.get("channels")
        record = channels.get(args.snapshot) if isinstance(channels, dict) else None
        sequence = record.get("sequence") if isinstance(record, dict) else None
        current = args.install_root / "current"
        target = os.readlink(current) if current.is_symlink() else None
        print(
            json.dumps(
                {
                    "channel": args.snapshot,
                    "current": target,
                    "record": record,
                    "sequence": sequence,
                    "pending": state.get("pending"),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if (
        args.timeout_seconds is None
        or not 1 <= args.timeout_seconds <= MAX_WAIT_SECONDS
    ):
        raise SystemExit("state wait timeout is outside the live-test bound")
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        try:
            state = json.loads(args.state.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            time.sleep(0.25)
            continue
        if args.committed is not None:
            channel, raw_sequence = args.committed
            sequence = int(raw_sequence)
            channels = state.get("channels")
            record = channels.get(channel) if isinstance(channels, dict) else None
            if (
                isinstance(record, dict)
                and record.get("sequence") == sequence
                and state.get("pending") is None
            ):
                return 0
        else:
            pending = state.get("pending")
            if (
                isinstance(pending, dict)
                and pending.get("stage") == "may_have_run"
                and pending.get("target_current") == f"releases/{args.pending_target}"
            ):
                return 0
        time.sleep(0.25)
    raise SystemExit("timed out waiting for exact updater state")


if __name__ == "__main__":
    raise SystemExit(main())
