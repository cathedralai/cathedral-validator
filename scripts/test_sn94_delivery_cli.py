#!/usr/bin/env python3
"""CLI fail-closed contract; no network or wallet access."""

import json
import subprocess
import sys
from pathlib import Path

result = subprocess.run(
    [
        str(Path(sys.executable).parent / "cathedral-validator"),
        "delivery-plan",
        "--policy",
        "/nonexistent/sn94-policy",
    ],
    text=True,
    capture_output=True,
    timeout=10,
)
try:
    body = json.loads(result.stdout)
except ValueError:
    raise SystemExit("FAIL: validator delivery-plan has no stable fail-closed CLI")
assert result.returncode == 2 and body["code"] == "delivery_plan_refused"
assert body["chain_write"] is False
print(
    json.dumps(
        {
            "status": "PASS",
            "scope": "invalid delivery policy refuses without wallet or chain",
        }
    )
)
