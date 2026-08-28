"""The deploy tree exposes one SN39 origin publisher, not fallback roles."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "publisher"


def test_only_the_canonical_origin_unit_is_shipped() -> None:
    assert sorted(path.name for path in DEPLOY.glob("*.service")) == [
        "cathedral-scorer-sn39.service"
    ]
    assert sorted(path.name for path in DEPLOY.glob("*.env.example")) == [
        "cathedral-scorer-sn39.env.example"
    ]


def test_canonical_unit_blocks_legacy_installed_origins() -> None:
    unit = (DEPLOY / "cathedral-scorer-sn39.service").read_text(encoding="utf-8")
    assert (
        "Conflicts=cathedral-publisher.service cathedral-weight-feed-publish.service"
        in unit
    )
    assert (
        "systemctl is-active --quiet cathedral-publisher.service cathedral-weight-feed-publish.service"
        in unit
    )
    assert "--workers 1 --no-access-log" in unit
    assert "WEB_CONCURRENCY" not in unit


def test_every_shipped_origin_entrypoint_is_single_worker() -> None:
    image = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    server = (ROOT / "scaffold" / "publisher" / "server.py").read_text(encoding="utf-8")
    environment = (DEPLOY / "cathedral-scorer-sn39.env.example").read_text(
        encoding="utf-8"
    )
    assert "--workers 1 --no-access-log" in image
    assert "workers=1" in server
    assert "WEB_CONCURRENCY=" not in environment


def test_operator_document_installs_only_the_canonical_unit() -> None:
    readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
    install = readme.split("## Install", 1)[1].split("## Allocation contract", 1)[0]
    assert "deploy/publisher/*.service" not in install
    assert "cathedral-scorer-sn39.service" in install
    assert "systemctl enable --now cathedral-scorer-sn39.service" in install
    assert "run them on distinct ports" not in readme


def test_operator_document_retires_and_masks_both_legacy_names() -> None:
    readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
    retirement = readme.split("## Retire legacy unit names", 1)[1].split(
        "## Install", 1
    )[0]
    for unit in (
        "cathedral-publisher.service",
        "cathedral-weight-feed-publish.service",
    ):
        assert unit in retirement
    assert "systemctl disable --now" in retirement
    assert "systemctl mask" in retirement
    assert "is-active" in retirement
    assert "is-enabled" in retirement
    assert "= masked" in retirement
    assert '"$(readlink "$unit_path")" = /dev/null' in retirement
    assert "recovery copy already exists" in retirement
    assert 'mv -- "$unit_path" "$saved_path"' in retirement
