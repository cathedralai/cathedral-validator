#!/usr/bin/env python3
"""Probe CLI validation must run without wallet, network, or a stored secret."""
import json
import os
from pathlib import Path
import subprocess
import sys

environment = dict(os.environ)
environment.pop("CATHEDRAL_API_KEY", None)
result = subprocess.run([str(Path(sys.executable).parent / "cathedral-validator"),
    "delivery-probe", "--api-url", "https://example.invalid", "--image", "alpine:3.22", "--max-spend-usd", "0.01"],
    env=environment, capture_output=True, text=True, timeout=10)
try:
    document = json.loads(result.stdout)
except ValueError:
    raise SystemExit("FAIL: delivery-probe has no stable fail-closed CLI")
assert result.returncode == 2 and document["code"] == "probe_configuration_refused"
assert document["chain_write"] is False
print(json.dumps({"status": "PASS", "scope": "missing key refuses before network or wallet"}))
