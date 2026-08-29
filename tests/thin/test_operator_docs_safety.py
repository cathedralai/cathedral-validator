"""Operator documentation must not expose removed or chain-writing shortcuts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "VALIDATOR-ONBOARDING.md").exists()
    assert not (ROOT / "REVIEW.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "wallet-host-quickstart.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "docker").exists()


def test_validator_page_is_a_small_live_testing_status() -> None:
    guide = (ROOT / "VALIDATOR.md").read_text(encoding="utf-8")
    assert guide.count("\n") == 7
    assert "Public validator operation is not self-service" in guide
    assert "authorized Cathedral operator" in guide
    assert "http" not in guide
    assert "--broadcast" not in guide
    assert "Further reading" not in guide


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
