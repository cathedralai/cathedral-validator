"""The public validator has one short, runnable operator path."""

import hashlib
import json
import re
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
INSTALL_SCRIPT_URL = (
    "https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/"
    "scripts/install.sh"
)
BOOTSTRAP_KEY_FINGERPRINT = (
    "sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013"
)


_BOOTSTRAP_TAG = re.compile(r"validator-bootstrap-production-s(\d+)-([0-9a-f]{64})\b")
_MINIMUM_SEQUENCE = re.compile(r"--minimum-bootstrap-sequence (\d+)\b")
_HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


def _published_bootstrap_sequence(page: str) -> int:
    """Return the one published bootstrap sequence a page agrees on.

    The sequence advances with every bootstrap publication, so pinning its
    current value here would only add a fourth copy of a generated number.
    What must hold is that every tag, digest, and installer argument on the
    page names the same published bootstrap.
    """

    tags = set(_BOOTSTRAP_TAG.findall(page))
    assert len(tags) == 1, tags
    (sequence, manifest_digest) = tags.pop()
    assert manifest_digest in page
    for argument in _MINIMUM_SEQUENCE.findall(page):
        assert argument == sequence
    return int(sequence)


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def _install_script() -> str:
    return INSTALL_SCRIPT.read_text(encoding="utf-8")


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "VALIDATOR-ONBOARDING.md").exists()
    assert not (ROOT / "REVIEW.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "wallet-host-quickstart.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "docker").exists()


def test_readme_is_the_small_public_guide() -> None:
    guide = _readme()
    words = " ".join(guide.split())
    # Count real second-level headings. A substring count also matches "### ",
    # so it would forbid subsections rather than keep the guide short.
    assert [line for line in guide.splitlines() if line.startswith("## ")] == [
        "## What it does",
        "## What you need",
        "## Install",
        "## Operate",
        "## Updates",
        "## Trust",
    ]
    assert guide.startswith("# Cathedral Validator\n")
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
    assert "`CONTRADICTION_STOPPED`" in guide
    assert "Never delete or replace the journal" in guide
    assert "[Validator auto-update](docs/AUTO_UPDATE.md)" in guide
    assert "Do not install or enable updater services from a source checkout" in words
    assert "Publication pending" not in guide
    assert "REPLACE_WITH" not in guide
    assert "sudo cathedral-validator-setup" in guide
    assert "--confirm-direct-write" in guide
    assert "sudo cathedral-validator-status" in guide
    assert "deploy/sn39/install-validator" not in guide
    assert "does not download a weight vector" in words
    assert "scored every serving miner" not in guide
    assert "finds serving miners" in guide
    assert "zero burn" in guide
    assert "pinned TDX verifier, and pinned SNP verifier together" in words
    assert "bootstrap updater, systemd units, host Python" in words
    assert "Public setup follows `stable` only" in guide
    assert BOOTSTRAP_KEY_FINGERPRINT in guide
    # A first-time operator sees exactly two 64-hex values: the install script
    # digest and the bootstrap signing key fingerprint. Every other digest
    # belongs in the script or in docs/AUTO_UPDATE.md.
    assert len(_HEX64.findall(guide)) == 2
    assert "git clone" not in guide
    assert "python3.12 -m venv" not in guide
    assert "install_updater_bundle.py" not in guide
    assert "BEGIN GENERATED" not in guide
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


def test_readme_pins_the_install_script_by_digest() -> None:
    guide = _readme()
    script = _install_script()
    digest = hashlib.sha256(INSTALL_SCRIPT.read_bytes()).hexdigest()

    # The README is the trust root for the script exactly as it was for the
    # inline block: the digest line must name the bytes in the tree.
    assert INSTALL_SCRIPT_URL in guide
    assert f"echo '{digest}  install.sh' | sha256sum -c" in guide
    assert "sudo bash install.sh" in guide
    assert "--proto '=https' --tlsv1.2" in guide

    assert os.access(INSTALL_SCRIPT, os.X_OK)
    assert script.startswith("#!/usr/bin/env bash\n")
    first_command = next(
        line for line in script.splitlines() if line and not line.startswith("#")
    )
    assert first_command == "set -euo pipefail"
    assert f"--expected-bootstrap-key-fingerprint {BOOTSTRAP_KEY_FINGERPRINT}" in script
    assert script.count(BOOTSTRAP_KEY_FINGERPRINT) == 2
    assert "REPLACE_WITH" not in script
    assert _published_bootstrap_sequence(script) >= 1
    subprocess.run(["bash", "-n", str(INSTALL_SCRIPT)], check=True)


def test_install_script_uses_unpredictable_root_controlled_staging() -> None:
    install = _install_script()

    assert (
        "BOOTSTRAP_DIR=$(sudo /usr/bin/mktemp -d "
        "/var/tmp/cathedral-bootstrap.XXXXXXXXXX)" in install
    )
    # The staging path must not be readonly: an operator who retries after a
    # flaky download in the same shell would otherwise hit a fatal assignment
    # to a readonly variable, or reuse a path the trap already removed.
    assert "readonly BOOTSTRAP_DIR" not in install
    # A failed verification must leave the downloaded bytes on disk to inspect.
    assert (
        'trap \'printf "bootstrap staging kept for inspection: %s\\n" '
        '"$BOOTSTRAP_DIR" >&2\' ERR' in install
    )
    assert "trap cleanup EXIT" not in install
    assert "^/var/tmp/cathedral-bootstrap\\.[[:alnum:]]{10}$" in install
    assert 'sudo /usr/bin/rm -rf -- "$BOOTSTRAP_DIR"' in install
    assert install.endswith("cleanup\ntrap - ERR\n")
    assert "/var/tmp/cathedral-bootstrap/" not in install
    assert "sudo install -d" not in install
    for filename in (
        "updater-bootstrap.tar.gz",
        "updater-bootstrap.manifest.json",
        "updater-bootstrap.manifest.sig",
        "bootstrap-signing-public-key.pem",
        "install_updater_bundle.py",
    ):
        assert f'"$BOOTSTRAP_DIR/{filename}"' in install


def test_install_script_authenticates_bundle_before_extracting_installer(
    tmp_path: Path,
) -> None:
    install = _install_script()

    signature_check = install.index("sudo openssl pkeyutl -verify")
    signed_bundle_check = install.index("bundle does not match the signed manifest")
    installer_extraction = install.index("tar -xOf")
    assert signature_check < signed_bundle_check < installer_extraction
    assert 'manifest.get("bundle")' in install
    assert 'bundle_claim.get("size")' in install
    assert 'bundle_claim.get("sha256")' in install
    assert "os.fstat(stream.fileno()).st_size" in install
    assert 'hashlib.file_digest(stream, "sha256").hexdigest()' in install

    bundle_check = install.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    compile(bundle_check, "<install.sh bootstrap bundle check>", "exec")

    bundle_path = tmp_path / "updater-bootstrap.tar.gz"
    manifest_path = tmp_path / "updater-bootstrap.manifest.json"
    bundle_path.write_bytes(b"signed bootstrap bundle")
    manifest_path.write_text(
        json.dumps(
            {
                "bundle": {
                    "size": bundle_path.stat().st_size,
                    "sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                }
            }
        ),
        encoding="ascii",
    )
    command = [sys.executable, "-", str(manifest_path), str(bundle_path)]
    accepted = subprocess.run(
        command, input=bundle_check, text=True, capture_output=True, check=False
    )
    assert accepted.returncode == 0, accepted.stderr

    bundle_path.write_bytes(b"substituted bundle")
    refused = subprocess.run(
        command, input=bundle_check, text=True, capture_output=True, check=False
    )
    assert refused.returncode != 0
    assert "bundle does not match the signed manifest" in refused.stderr


def test_readme_updater_link_preserves_the_unpublished_boundary() -> None:
    guide = _readme()
    updater = (ROOT / "docs" / "AUTO_UPDATE.md").read_text(encoding="utf-8")

    assert "[Validator auto-update](docs/AUTO_UPDATE.md)" in guide
    assert updater.startswith("# Validator auto-update\n\nStatus:")
    assert "public bootstrap artifacts are published" in updater
    assert "Publication pending" not in updater
    assert "REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE" not in updater
    assert _published_bootstrap_sequence(updater) == _published_bootstrap_sequence(
        _install_script()
    )
    assert BOOTSTRAP_KEY_FINGERPRINT in updater
    assert "`scripts/install.sh`, is pinned by digest on the README" in updater
    assert "Do not install\nor enable updater units from a source checkout" in updater
    assert "BEGIN GENERATED UPDATER BOOTSTRAP" in updater
    assert "END GENERATED UPDATER BOOTSTRAP" in updater
    assert "releases.cathedral.com" not in updater
    assert "The updater has no access to the hotkey" in updater
    assert "repository home page is the only operator install guide" in updater
    assert "sudo cathedral-validator-setup" in updater
    assert "sudo cathedral-validator-status" in updater
    assert "--channel=stable" not in updater
    assert "sudo systemctl enable" not in updater


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
    # Operating detail that left the README lives here.
    assert "/var/lib/cathedral-validator/.local/state/cathedral-validator/" in guide
    assert (
        "direct-writer/finney-sn39-mechanism-0/<validator-hotkey>/state.json" in guide
    )
    assert "`RestartPreventExitStatus=2`" in guide
    assert "cathedral-validator-boot-reconcile.service" in guide
    assert "Never delete or replace the journal" in guide
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
    # The regeneration rule now names the script and the README digest pin.
    assert "regenerate `scripts/install.sh`" in maintainer
    assert "replace the digest in its\n`sha256sum -c` line" in maintainer
    assert "regenerate the block in `README.md`" not in maintainer


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
