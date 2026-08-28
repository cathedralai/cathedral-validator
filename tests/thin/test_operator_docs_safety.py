"""Operator documentation must not expose removed or chain-writing shortcuts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()


def test_install_verification_does_not_start_the_broadcaster() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("### Verify before enabling", 1)[1].split(
        "## What it does", 1
    )[0]
    assert "/usr/local/libexec/cathedral-sn39-release verify" in section
    assert "systemctl start cathedral-validator-sn39-relay.service\n" not in section
    assert "invokes `continuous --broadcast`" in section


def test_existing_journal_is_never_reset_for_migration() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    words = " ".join(readme.split())
    assert (
        "Never hand-edit, move, archive, replace, or reset live submission state"
        in words
    )
    assert "archive the previous state file and start fresh" not in readme
