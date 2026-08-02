"""The canonical validator release cannot route to or be claimed by legacy code."""

from __future__ import annotations

import hashlib
import pathlib
import runpy
import tomllib
from importlib import metadata

import pytest

from scaffold import sn39_public_reproduction, validator_thin


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPUTE_REVISION = "26ebdbb885746f1835ea67ff314e384b4838560f"
COMPUTE_ARCHIVE_SHA256 = (
    "02b95787cf2247d264bb45b1938b20ff005b1ac127261264dfe5e5a9b4aab240"
)


def test_validator_console_script_belongs_to_this_repository() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project["project"]["scripts"]
    assert scripts["cathedral-validator"] == "scaffold.cli:main"


def test_active_operator_docs_route_only_to_cathedral_validator() -> None:
    for name in (
        "README.md",
        "VALIDATOR.md",
        "VALIDATOR-ONBOARDING.md",
        "BOUNDARY.md",
        "REVIEW.md",
        "docs/PROVENANCE.md",
        "docs/THIN_SUBNET_RUNBOOK.md",
        "docs/SN39_MAINNET_RELEASE_20260724.md",
        "deploy/sn39/beta/OPERATIONS.md",
    ):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "github.com/cathedralai/cathedral.git" not in text
        assert "github.com/cathedralai/cathedral/blob" not in text
        assert "cathedral-computer-validator" not in text
        assert "cathedralsubnet-production-ready" not in text
        assert "cathedralconfidential.git" not in text
        assert "git clone <repo-url>" not in text
        assert "sync-from-upstream" not in text


def test_legacy_validator_sync_assets_are_absent() -> None:
    for relative in (
        "MANIFEST.origin.tsv",
        "tools/manifest.sh",
        "tools/sync-from-upstream.sh",
        "tools/upstream-manifest.txt",
    ):
        assert not (ROOT / relative).exists(), relative


def test_compute_pin_reserves_the_validator_command() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependency = project["project"]["optional-dependencies"]["provenance"][0]
    assert COMPUTE_REVISION in dependency
    assert f"sha256={COMPUTE_ARCHIVE_SHA256}" in dependency


def test_installed_compute_distribution_does_not_claim_validator_command() -> None:
    distribution = metadata.distribution("cathedral")
    scripts = {
        entry.name: entry.value
        for entry in distribution.entry_points
        if entry.group == "console_scripts"
    }
    assert scripts["cathedral-compute-validator"] == "cathedral.neuron.validator:main"
    assert "cathedral-validator" not in scripts


def test_compute_release_pin_is_coherent_across_every_authority_site() -> None:
    archive_url = (
        "https://github.com/cathedralai/cathedral-compute/archive/"
        f"{COMPUTE_REVISION}.tar.gz"
    )
    lock_path = ROOT / "requirements/sn39-reproduction.lock"
    lock_text = lock_path.read_text(encoding="utf-8")
    lock_digest = "sha256:" + hashlib.sha256(lock_path.read_bytes()).hexdigest()
    builder = runpy.run_path(str(ROOT / "scripts/build_sn39_release_manifest.py"))

    assert archive_url in lock_text
    assert f"--hash=sha256:{COMPUTE_ARCHIVE_SHA256}" in lock_text
    assert builder["EXPECTED_CATHEDRAL_URL"] == archive_url
    assert builder["EXPECTED_CATHEDRAL_ARCHIVE_SHA256"] == COMPUTE_ARCHIVE_SHA256
    assert validator_thin.SN39_PRODUCER_REVISION == COMPUTE_REVISION
    assert sn39_public_reproduction.EXPECTED_PRODUCER_REVISION == COMPUTE_REVISION
    assert (
        sn39_public_reproduction.EXPECTED_STARTUP["provenance_source_revision"]
        == COMPUTE_REVISION
    )
    assert (
        sn39_public_reproduction.EXPECTED_RELEASE_PINS["reproduction_dependencies"]
        == lock_digest
    )

    for relative in (
        "config/validator-mainnet-sn39-launch.toml",
        "config/validator-mainnet-sn39.toml",
        "config/validator-thin-sn39-relay.toml",
    ):
        config = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
        assert config["provenance"]["source_revision"] == COMPUTE_REVISION

    for relative in (
        "config/validator-mainnet-sn39-launch.toml",
        "config/validator-mainnet-sn39.toml",
    ):
        config = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
        assert config["provenance"]["max_anchor_lag_blocks"] == 600


def test_release_builder_binds_required_public_key_files(
    tmp_path: pathlib.Path,
) -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build_sn39_release_manifest.py"))
    validate = builder["validate_installed_release_files"]
    install_root = pathlib.Path("/etc/cathedral-validator/provenance")
    assert builder["PROVENANCE_INSTALL_ROOT"] == install_root
    reviewed = tmp_path / "reviewed.json"
    installed = tmp_path / "installed.json"
    reviewed.write_bytes(b"reviewed-key-bytes")

    with pytest.raises(SystemExit, match="required release file is unavailable"):
        validate(((installed, reviewed),))

    installed.write_bytes(b"tampered-key-bytes")
    with pytest.raises(SystemExit, match="differs from reviewed release"):
        validate(((installed, reviewed),))

    installed.write_bytes(reviewed.read_bytes())
    validate(((installed, reviewed),))

    guide = (ROOT / "docs/SN39_MAINNET_RELEASE_20260724.md").read_text(encoding="utf-8")
    main_config = tomllib.loads(
        (ROOT / "config/validator-mainnet-sn39.toml").read_text(encoding="utf-8")
    )
    for name in ("registry-keys.json", "report-keys.json", "index-keys.json"):
        assert f'"$release/config/provenance/{name}"' in guide
        assert f"/etc/cathedral-validator/provenance/{name}" in guide
    assert main_config["provenance"]["registry_keys"] == str(
        install_root / "registry-keys.json"
    )
    assert main_config["provenance"]["report_keys"] == str(
        install_root / "report-keys.json"
    )
    assert main_config["provenance"]["index_keys"] == str(
        install_root / "index-keys.json"
    )
