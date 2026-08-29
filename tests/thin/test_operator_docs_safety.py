"""Operator documentation must not expose removed or chain-writing shortcuts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()


def test_readme_is_a_small_product_front_door() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("\n") == 5
    assert "https://cathedral.computer/" in readme
    assert "cathedralai/cathedral-sandbox/blob/main/MINING.md" in readme
    assert "cathedralai/cathedral-validator/blob/main/VALIDATOR.md" in readme
    assert "cathedralai/cathedral-distill" in readme
    assert "--broadcast" not in readme
