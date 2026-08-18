#!/usr/bin/env python3
"""Reproduce the immutable, root-signed SN39 launch decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Direct execution sets sys.path[0] to ``scripts/`` rather than the pristine
# release root. Bind imports to the checkout that contains this reviewed
# runner; the reproducer subsequently verifies that checkout is the exact
# root-signed revision and has no tracked, untracked, or ignored changes.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.assert_sn39_public_reproduction import (  # noqa: E402
    ReproductionError,
    ReproductionNotProven,
    assert_public_reproduction,
)


def run(
    *,
    release_sha256: str | None = None,
    release_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify signed release, archive state, and frozen public evidence."""
    return assert_public_reproduction(
        release_sha256=release_sha256,
        release_result=release_result,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-sha256",
        help=(
            "reproduce a versioned release under /releases/sha256; "
            "omit only for the historical root release"
        ),
    )
    args = parser.parse_args()
    try:
        result = run(release_sha256=args.release_sha256)
    except ReproductionNotProven as exc:
        print(f"SN39 public reproduction: NOT_PROVEN: {exc}", file=sys.stderr)
        return 3
    except ReproductionError as exc:
        print(f"SN39 public reproduction: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "SN39 public reproduction: PASS "
        + json.dumps(result, sort_keys=True, separators=(",", ":"))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
