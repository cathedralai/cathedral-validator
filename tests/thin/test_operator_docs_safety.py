"""The public validator has one short, runnable operator path."""

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "VALIDATOR-ONBOARDING.md").exists()
    assert not (ROOT / "REVIEW.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "wallet-host-quickstart.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "docker").exists()


def test_readme_is_the_small_public_guide() -> None:
    guide = (ROOT / "README.md").read_text(encoding="utf-8")
    words = " ".join(guide.split())
    run_block = guide.split("## Run the validator", 1)[1].split("```bash", 1)[1]
    run_block = run_block.split("```", 1)[0]
    assert guide.count("## ") == 4
    assert guide.startswith("# Cathedral Validator\n")
    assert "## One recurring path" in guide
    assert "## Run the validator" in guide
    assert "## Install the pinned QVL" in guide
    assert "## Current proof boundary" in guide
    assert "deploy/sn39/install-validator" not in guide
    assert "CONFIRMED" in guide
    assert "does not download a signed weight vector" in words
    assert "scored every serving miner" not in guide
    assert "scores every serving miner" in guide
    assert "YOUR_WALLET" in guide
    assert "YOUR_HOTKEY" in guide
    assert "--once" not in run_block
    assert "Add `--once` only for a bounded" in guide
    assert "cathedral-tdx-verifier-v1.0.0" in guide
    assert (
        "https://github.com/cathedralai/cathedral-sandbox/releases/download/"
        "cathedral-tdx-verifier-v1.0.0/"
        "cathedral-tdx-verifier-linux-amd64" in guide
    )
    assert "sha256sum --check -" in guide
    assert "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148" in guide
    assert "issue #185" not in guide
    assert "not self-service" not in guide
    assert "authorized Cathedral operator" not in guide
    assert "Where to get help" not in guide
    assert "--dry-run" not in guide
    assert "--broadcast" not in guide
    assert "--offline" not in guide
    assert "cathedral-sandbox/blob/main/MINING.md" not in guide
    assert "cathedral-validator/blob/main/VALIDATOR.md" not in guide


def test_old_validator_page_is_only_a_compatibility_pointer() -> None:
    pointer = (ROOT / "VALIDATOR.md").read_text(encoding="utf-8")
    assert pointer == (
        "# Cathedral Validator\n\n"
        "The public installation and operating guide is on the "
        "[repository home page](README.md).\n"
    )


def test_former_public_installer_is_a_fail_closed_tombstone() -> None:
    path = ROOT / "deploy" / "sn39" / "install-validator"
    source = path.read_text(encoding="utf-8")
    assert os.access(path, os.X_OK)
    subprocess.run(["bash", "-n", str(path)], check=True)
    result = subprocess.run([str(path)], text=True, capture_output=True, check=False)
    assert result.returncode == 2
    assert "RETIRED" in result.stderr
    assert "No files or services were changed" in result.stderr
    assert "cathedral-validator-sn39-relay.service" not in source
    assert "--relay" not in source
    assert "systemctl" not in source
    assert "install " not in source


def test_active_operator_surfaces_exclude_removed_commands() -> None:
    active = [
        *ROOT.glob("*.md"),
        *(ROOT / "docs").glob("*.md"),
        *(ROOT / "deploy").rglob("README.md"),
    ]
    retired = (
        "cathedral-validator serve",
        "cathedral-uid30-fleet-submit",
        "cathedral-publisher-serve",
        "cathedral-candidate-snapshot",
        "--relay --release",
        "cathedral-validator-sn39-relay.service",
    )
    for path in active:
        text = path.read_text(encoding="utf-8")
        for command in retired:
            assert command not in text, f"{command} remains in {path.relative_to(ROOT)}"


def test_retired_guides_are_only_historical_pointers() -> None:
    for relative in (
        "docs/PROVENANCE.md",
        "docs/SN39_MULTICOMPUTE.md",
        "docs/VIOLET_EXTERNAL_SCORES.md",
        "deploy/publisher/README.md",
        "deploy/sn39/README.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert text.startswith("# Retired"), relative
        assert "README.md" in text, relative


def test_tracked_documentation_has_no_removed_onboarding_anchors() -> None:
    markdown = [
        *ROOT.glob("*.md"),
        *(ROOT / "docs").rglob("*.md"),
        *(ROOT / "deploy").rglob("*.md"),
    ]
    for path in markdown:
        text = path.read_text(encoding="utf-8")
        assert "README.md#quickstart" not in text, path.relative_to(ROOT)
        assert "VALIDATOR.md#" not in text, path.relative_to(ROOT)
