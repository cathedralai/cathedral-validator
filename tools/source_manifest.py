#!/usr/bin/env python3
"""Build or verify the canonical repository source digest manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"


def tracked_files() -> list[Path]:
    raw = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        stderr=subprocess.DEVNULL,
    )
    paths: list[Path] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        if relative == MANIFEST.relative_to(ROOT):
            continue
        absolute = ROOT / relative
        if absolute.is_file():
            paths.append(relative)
    return sorted(paths, key=lambda path: path.as_posix())


def render() -> bytes:
    lines = []
    for relative in tracked_files():
        digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative.as_posix()}\n")
    return "".join(lines).encode("utf-8")


def write(payload: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix="MANIFEST.sha256.", dir=ROOT)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, MANIFEST)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        write(expected)
        return 0
    try:
        actual = MANIFEST.read_bytes()
    except OSError as exc:
        raise SystemExit("MANIFEST.sha256 is unavailable") from exc
    if actual != expected:
        raise SystemExit(
            "MANIFEST.sha256 is stale; run tools/source_manifest.py --write"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
