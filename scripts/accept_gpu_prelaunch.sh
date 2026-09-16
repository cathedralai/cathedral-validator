#!/usr/bin/env bash
# Item-local source/packaging acceptance. No chain client, rental or live work.
set -euo pipefail
cd "$(dirname "$0")/.."
gpu_python="${CATHEDRAL_GPU_PYTHON:-python3}"
"$gpu_python" - <<'PY'
import importlib.metadata
import json
from pathlib import Path
import tomllib

requirement = tomllib.loads(Path('pyproject.toml').read_text())['project']['optional-dependencies']['gpu'][0]
expected = requirement.rsplit('@', 1)[1]
provenance = json.loads(importlib.metadata.distribution('cathedral').read_text('direct_url.json') or '{}')
assert provenance.get('url') == 'https://github.com/cathedralai/cathedral-sandbox.git'
assert provenance.get('vcs_info', {}).get('commit_id') == expected
from cathedral.gpu_provider import G4ProviderVerifier
from cathedral.gpu_work import CudaWorkExecutor
assert G4ProviderVerifier and CudaWorkExecutor
print('Installed GPU contract:', expected)
PY
"$gpu_python" -m pytest -q \
  tests/thin/test_gpu_qualification.py \
  tests/thin/test_independent_validator_request.py \
  tests/integration/test_gpu_worker_wire.py
"$gpu_python" -m cathedral_thin.independent_runtime.gpu_qualification --help >/dev/null
