#!/usr/bin/env python3
"""Exercise the service pre-activation refusal without wallet/service access."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

result = subprocess.run(
    [
        str(Path(sys.executable).parent / "cathedral-validator"),
        "service-config-check",
        "--config",
        "/nonexistent/sn94-service-config.json",
    ],
    capture_output=True,
    text=True,
    check=False,
)
assert result.returncode == 2, result.returncode
assert json.loads(result.stdout) == {
    "code": "service_config_refused",
    "chain_write": False,
}, result.stdout
print(
    json.dumps(
        {
            "status": "PASS",
            "scope": "missing service config refuses before wallet or service",
        }
    )
)
