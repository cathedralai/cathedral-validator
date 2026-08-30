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


def test_validator_page_is_a_small_public_guide() -> None:
    guide = (ROOT / "VALIDATOR.md").read_text(encoding="utf-8")
    assert guide.count("## ") == 3
    assert "## 1. What it does" in guide
    assert "## 2. What you need" in guide
    assert "## 3. Install, run, and know it is working" in guide
    assert "deploy/sn39/install-validator" in guide
    assert "WEIGHTS_SUBMITTED" in guide
    assert "never needs\n  your coldkey" in guide
    assert "not self-service" not in guide
    assert "authorized Cathedral operator" not in guide
    assert "Where to get help" not in guide
    assert "--dry-run" not in guide
    assert "--broadcast" not in guide
    assert "--offline" not in guide


def test_public_installer_is_one_live_path() -> None:
    path = ROOT / "deploy" / "sn39" / "install-validator"
    source = path.read_text(encoding="utf-8")
    assert os.access(path, os.X_OK)
    subprocess.run(["bash", "-n", str(path)], check=True)
    assert "--hotkey" in source
    assert "--relay --release" in source
    assert "requirements/sn39-build.lock" in source
    assert "requirements/sn39-reproduction.lock" in source
    assert 'staged_venv="$(mktemp -d' in source
    assert '"${staged_venv}/bin/python" -m pip install' in source
    assert 'systemctl enable "${SERVICE}"' in source
    assert 'systemctl is-active --quiet "${SERVICE}"' in source
    assert "/.bittensor/wallets/validator/hotkeys/default" in source
    assert 'hotkey_source="$(realpath -e -- "${hotkey_source}")"' in source
    assert "*/wallets/*/hotkeys/*" in source
    assert source.index("cathedral-sn39-release verify") < source.rindex(
        'systemctl start "${SERVICE}"'
    )
    assert "restore_targets" in source
    assert "systemctl mask --now --force" in source
    assert "--dry-run" not in source
    assert "--broadcast" not in source
    assert "--offline" not in source
    assert "cathedral-sn39-public-status.service" not in source
    assert 'cathedral-validator-sn39.service"' not in source


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


def test_readme_is_a_small_centered_product_front_door() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("\n") == 7
    assert '<div align="center">' in readme
    assert "<strong>Bittensor SN39</strong>" in readme
    assert (
        "<strong>Racing to build the fastest sandbox fleet on earth</strong>" in readme
    )
    assert "<strong>With machines that prove what they run</strong>" in readme
    assert "cathedralai/cathedral-sandbox/blob/main/MINING.md" in readme
    assert "cathedralai/cathedral-validator/blob/main/VALIDATOR.md" in readme
    assert "cathedral.computer" not in readme
    assert "cathedral-distill" not in readme
    assert "--broadcast" not in readme
