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
    assert guide.count("## ") == 5
    assert guide.startswith("# Cathedral Validator\n")
    for heading in (
        "## What it does",
        "## What you need",
        "## Install and start",
        "## What to expect",
        "## Updates",
    ):
        assert heading in guide
    assert (
        "Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3"
        in guide
    )
    assert "Never copy a coldkey, mnemonic, or coldkey password" in guide
    assert "service receives only the hotkey file" in words
    assert "There is no alternate scoring mode and no non-writing mode" in words
    assert "`CONFIRMED` or `RECOVERED_CONFIRMED`" in words
    assert "`NOT_PROVEN` means success is unresolved" in guide
    assert "`EXPIRED_WITHOUT_INCLUSION` means" in guide
    assert "[Validator auto-update](docs/AUTO_UPDATE.md)" in guide
    assert "Do not install or enable updater services from a source checkout" in words
    assert "BEGIN GENERATED VALIDATOR INSTALL" in guide
    assert "END GENERATED VALIDATOR INSTALL" in guide
    assert "deploy/sn39/install-validator" not in guide
    assert "CONFIRMED" in guide
    assert "does not download a weight vector" in words
    assert "scored every serving miner" not in guide
    assert "finds serving miners" in guide
    assert "zero burn" in guide
    assert "`CONTRADICTION_STOPPED`" in guide
    assert "`RestartPreventExitStatus=2`" in guide
    assert "Never delete or replace the journal" in guide
    assert "/var/lib/cathedral-validator/.local/state/cathedral-validator/" in guide
    assert "cathedral-validator-boot-reconcile.service" in guide
    assert "pinned TDX verifier, and pinned SNP verifier together" in words
    assert "bootstrap updater, systemd units, host Python" in words
    assert "Each host chooses `stable` or `canary` once" in guide
    assert "git clone" not in guide
    assert "python3.12 -m venv" not in guide
    assert "cathedral-tdx-verifier-v1.0.0" not in guide
    assert "snpguest 0.10.0" not in guide
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
    assert updater.startswith("# Validator auto-update\n\nStatus:")
    assert "public bootstrap artifacts are not published yet" in updater
    assert "Do not install\nor enable updater units from a source checkout" in updater
    assert "BEGIN GENERATED UPDATER BOOTSTRAP" in updater
    assert "END GENERATED UPDATER BOOTSTRAP" in updater
    assert "releases.cathedral.com" not in updater
    assert "signed installation path" in guide
    assert "The updater has no access to the hotkey" in updater
    assert "repository home page is the only operator install guide" in updater


def test_readme_snp_policy_template_is_strict_json_with_the_runtime_shape() -> None:
    guide = (ROOT / "docs" / "AUTO_UPDATE.md").read_text(encoding="utf-8")
    section = guide.split("## Before installation", 1)[1]
    policy = json.loads(section.split("```json", 1)[1].split("```", 1)[0])

    assert set(policy) == {"schema", "generations"}
    assert policy["schema"] == "cathedral_amd_sev_snp_policy_v1"
    assert set(policy["generations"]) == {"genoa"}
    generation = policy["generations"]["genoa"]
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


def test_auto_update_doc_covers_bootstrap_and_release_boundaries() -> None:
    guide = (ROOT / "docs" / "AUTO_UPDATE.md").read_text(encoding="utf-8")
    maintainer = (ROOT / "docs" / "RELEASE_MAINTAINER.md").read_text(encoding="utf-8")

    assert "RECONCILED" in guide
    assert "START_AUTHORIZED" in guide
    assert "It does not hide unresolved recovery" in guide
    assert "exact updater-controlled nested" in guide
    assert "[Release maintainer guide](RELEASE_MAINTAINER.md)" in guide
    assert "--archive-out-dir" not in guide
    assert "--runtime-lock" not in guide
    assert "two offline encrypted backups" in maintainer
    assert (
        "--runtime-lock /secure/candidate/runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock"
        in maintainer
    )
    assert (
        "--runtime-distributions /secure/candidate/runtime/cathedral-validator.pex-distributions.json"
        in maintainer
    )
    assert "--archive-out-dir /secure/signed" in maintainer
    assert "--lifetime-seconds 604800" in maintainer
    assert (
        "--minimum-bootstrap-sequence REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE"
        in maintainer
    )
    assert (
        "sudo /usr/bin/python3.12 deploy/validator-update/install_updater_bundle.py"
        in maintainer
    )
    assert (
        "\npython deploy/validator-update/install_updater_bundle.py" not in maintainer
    )
    assert "cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz" in maintainer
    assert (
        "Routine validator and verifier releases are unattended after bootstrap"
        in maintainer
    )


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
