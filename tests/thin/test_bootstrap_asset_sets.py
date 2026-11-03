"""The installer accepts exactly two bootstrap asset sets: with and without the
shipped SN94 SNP policy. Bootstrap sequence 4 and earlier predate the policy;
the Docker image still installs sequence 4 until sequence 5 is published."""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_PATH = ROOT / "deploy" / "validator-update" / "install_updater_bundle.py"
_NAME = "install_updater_bundle_under_test"
_SPEC = importlib.util.spec_from_file_location(
    _NAME, _PATH, loader=SourceFileLoader(_NAME, str(_PATH))
)
installer = importlib.util.module_from_spec(_SPEC)
# Dataclass looks the module up in sys.modules while the class body runs.
sys.modules[_NAME] = installer
_SPEC.loader.exec_module(installer)

WHEEL = "payload/wheelhouse/cathedral_validator-0-py3-none-any.whl"


def _records(paths: set[str]) -> list[dict[str, object]]:
    return [
        {"mode": "0644", "path": path, "sha256": "0" * 64, "size": 1}
        for path in sorted(paths | {WHEEL})
    ]


def test_current_set_carries_the_shipped_policy() -> None:
    assert "payload/examples/sn94-snp-policy.json" in installer.EXPECTED_NON_WHEEL_PATHS
    parsed = installer._manifest_records(
        _records(set(installer.EXPECTED_NON_WHEEL_PATHS))
    )
    assert "payload/examples/sn94-snp-policy.json" in parsed


def test_legacy_set_without_the_policy_is_still_accepted() -> None:
    legacy = set(installer.LEGACY_NON_WHEEL_PATHS)
    assert "payload/examples/sn94-snp-policy.json" not in legacy
    assert legacy == set(installer.EXPECTED_NON_WHEEL_PATHS) - {
        "payload/examples/sn94-snp-policy.json"
    }
    installer._manifest_records(_records(legacy))


@pytest.mark.parametrize(
    "drop",
    [
        "payload/examples/direct.env.example",
        "payload/operator/cathedral-validator-setup",
    ],
)
def test_any_other_missing_asset_is_refused(drop: str) -> None:
    with pytest.raises(installer.InstallRefused, match="fixed bootstrap asset set"):
        installer._manifest_records(
            _records(set(installer.EXPECTED_NON_WHEEL_PATHS) - {drop})
        )


def test_an_extra_asset_is_refused() -> None:
    extra = set(installer.EXPECTED_NON_WHEEL_PATHS) | {"payload/examples/extra.json"}
    with pytest.raises(installer.InstallRefused, match="fixed bootstrap asset set"):
        installer._manifest_records(_records(extra))
