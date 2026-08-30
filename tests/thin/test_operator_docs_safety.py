"""The public validator has one short, runnable operator path."""

import json
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
    assert guide.count("## ") == 5
    assert guide.startswith("# Cathedral Validator\n")
    assert "## One recurring path" in guide
    assert "## Run the validator" in guide
    assert "## Install the pinned QVL" in guide
    assert "## Install the pinned AMD verifier and policy" in guide
    assert "## Current proof boundary" in guide
    assert "Linux/amd64 host with CPython 3.12" in guide
    assert (
        "git clone https://github.com/cathedralai/cathedral-validator.git" in run_block
    )
    assert "cd cathedral-validator" in run_block
    assert "python3.12 -m venv .venv" in run_block
    assert "[the QVL setup](#install-the-pinned-qvl)" in guide
    assert "[the AMD setup](#install-the-pinned-amd-verifier-and-policy)" in guide
    assert "Do not copy the coldkey" in guide
    assert "The validator opens `wallet.hotkey` only" in guide
    assert "It never reads or signs with a coldkey" in words
    assert "--wallet-path /absolute/hotkey-only/wallets" in guide
    assert "There is no non-writing launch mode" in guide
    assert "`CONFIRMED` or `RECOVERED_CONFIRMED`" in guide
    assert "`NOT_PROVEN` means success was not established" in guide
    assert "`EXPIRED_WITHOUT_INCLUSION` means recovery proved" in guide
    assert "For `--once`, only the two confirmed statuses exit zero" in guide
    assert "[Validator auto-update](docs/AUTO_UPDATE.md)" in guide
    assert "Auto-update remains unavailable until" in words
    assert "You can still run the validator from this checkout" in words
    assert "Do not enable updater units from the checkout" in words
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
    assert "restart supervisor" in guide
    assert "`CONTRADICTION_STOPPED`" in guide
    assert "terminal exit with status 2" in guide
    assert "`Restart=on-failure`" in guide
    assert "`RestartPreventExitStatus=2`" in guide
    assert "must never clear the journal" in guide
    assert "before any manual journal clearance" in guide
    assert (
        "https://github.com/cathedralai/cathedral-sandbox/releases/download/"
        "cathedral-tdx-verifier-v1.0.0/"
        "cathedral-tdx-verifier-linux-amd64" in guide
    )
    assert "sha256sum --check -" in guide
    assert "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148" in guide
    assert "70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0" in guide
    assert "[snpguest 0.10.0 release]" in guide
    assert "No shared SNP admission policy is published" in guide
    assert (
        "cathedral-sandbox/blob/8dde6eaca27116eed53386a1fa33ec70b74a01fb/"
        "docs/AMD_SEV_SNP_FRIEND_TEST.md" in guide
    )
    assert "[AMD verification rehearsal](docs/AMD_SEV_SNP_DEV_PREVIEW.md)" in guide
    assert "require `PROVEN_DEVELOPMENT_NO_WRITE`" in guide
    assert "Never pass the placeholder file to the validator" in words
    assert "release assets are public and match the exact" in words
    assert "--snp-policy" in run_block
    assert "--snpguest" in run_block
    assert ".[snp-production]" in run_block
    assert "issue #185" not in guide
    assert "not self-service" not in guide
    assert "authorized Cathedral operator" not in guide
    assert "Where to get help" not in guide
    assert "--dry-run" not in guide
    assert "--broadcast" not in guide
    assert "--offline" not in guide
    assert "cathedral-sandbox/blob/main/MINING.md" not in guide
    assert "cathedral-validator/blob/main/VALIDATOR.md" not in guide


def test_readme_updater_link_preserves_the_unpublished_boundary() -> None:
    guide = (ROOT / "README.md").read_text(encoding="utf-8")
    updater = (ROOT / "docs" / "AUTO_UPDATE.md").read_text(encoding="utf-8")

    assert "[Validator auto-update](docs/AUTO_UPDATE.md)" in guide
    assert updater.startswith(
        "# Validator auto-update\n\n"
        "Status: implementation candidate. Installation is not self-service or\n"
        "launch-ready."
    )
    assert "Do not enable these units from a repository\ncheckout" in updater
    assert "It never receives a coldkey" in updater


def test_readme_snp_policy_template_is_strict_json_with_the_runtime_shape() -> None:
    guide = (ROOT / "README.md").read_text(encoding="utf-8")
    section = guide.split("## Install the pinned AMD verifier and policy", 1)[1]
    policy = json.loads(section.split("```json", 1)[1].split("```", 1)[0])

    assert set(policy) == {"schema", "generations"}
    assert policy["schema"] == "cathedral_amd_sev_snp_policy_v1"
    assert set(policy["generations"]) == {"REPLACE_WITH_milan_genoa_OR_turin"}
    generation = policy["generations"]["REPLACE_WITH_milan_genoa_OR_turin"]
    assert set(generation) == {"allowed_measurements", "minimum_tcb"}
    assert generation["allowed_measurements"] == ["REPLACE_WITH_96_LOWERCASE_HEX"]
    assert generation["minimum_tcb"] == "0xREPLACE_WITH_16_LOWERCASE_HEX"


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
