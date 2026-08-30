"""The deploy tree exposes one SN39 origin publisher, not fallback roles."""

from pathlib import Path

from scaffold.publisher import launch_profile


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
    assert "Environment=CATHEDRAL_ENV=production" in unit


def test_every_shipped_origin_entrypoint_is_single_worker() -> None:
    image = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    server = (ROOT / "scaffold" / "publisher" / "server.py").read_text(encoding="utf-8")
    environment = (DEPLOY / "cathedral-scorer-sn39.env.example").read_text(
        encoding="utf-8"
    )
    assert "--workers 1 --no-access-log" in image
    assert "CATHEDRAL_ENV=production" in image
    assert "CATHEDRAL_LAUNCH_PROFILE=v2-converged" in image
    assert "workers=1" in server
    assert "WEB_CONCURRENCY=" not in environment


def test_production_image_has_no_sqlite_fallback_or_volume_setup() -> None:
    image = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (DEPLOY / "entrypoint.sh").read_text(encoding="utf-8")
    unit = (DEPLOY / "cathedral-scorer-sn39.service").read_text(encoding="utf-8")
    server = (ROOT / "scaffold" / "publisher" / "server.py").read_text(encoding="utf-8")

    assert "CATHEDRAL_DB_PATH" not in image
    assert "CATHEDRAL_DB_PATH" not in entrypoint
    assert "CATHEDRAL_DB_PATH" not in unit
    assert "CATHEDRAL_DB_PATH" not in server
    assert "/data" not in image
    assert "sqlite" not in entrypoint.lower()
    assert "setpriv --reuid=cathedral" in entrypoint


def test_shipped_environment_selects_one_strict_profile() -> None:
    environment = (DEPLOY / "cathedral-scorer-sn39.env.example").read_text(
        encoding="utf-8"
    )
    assert "CATHEDRAL_LAUNCH_PROFILE=v2-converged" in environment
    assert "CATHEDRAL_SERVICE_ROLE=all" in environment
    assert "CATHEDRAL_CYBERGYM_INGEST_ENABLED=false" in environment
    assert "CATHEDRAL_V2_SUBMIT_TOKEN_SECRET=<v2-submit-token-secret>" in environment
    assert "CATHEDRAL_V2_PERMINER_SEED_SECRET=<v2-per-miner-seed-secret>" in environment
    assert "DATABASE_URL=postgresql://<user>:<pass>@<host>:5432/<db>" in environment
    assert "CATHEDRAL_WEIGHTS_MODE=proportional" in environment
    assert "CATHEDRAL_PERMINER_SCORING_MODE=bonus" in environment
    assert "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS=off" in environment
    assert "CATHEDRAL_V2_CHALLENGE_SOURCE=planted" in environment
    assert "CATHEDRAL_V2_VERIFY_WORKER_ENABLED=true" in environment
    assert "CATHEDRAL_VALIDATED_SUPPLY_ENABLED=true" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_ENABLED=true" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED=true" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_MODE=confidential_primary" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_SOURCE=cathedral_confidential_tdx" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM=true" in environment
    assert "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED=true" in environment
    assert "CATHEDRAL_WEIGHT_POLICY_BURN_UID=\n" in environment
    assert "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2=10" in environment
    assert "CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS=1800" in environment


def test_shipped_unit_and_environment_cover_every_production_pin() -> None:
    values: dict[str, str] = {}
    for line in (
        (DEPLOY / "cathedral-scorer-sn39.env.example")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name, value = stripped.split("=", 1)
            values[name] = value
    for line in (
        (DEPLOY / "cathedral-scorer-sn39.service")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        stripped = line.strip()
        if stripped.startswith("Environment="):
            name, value = stripped.removeprefix("Environment=").split("=", 1)
            values[name] = value

    for name, expected in launch_profile._PRODUCTION_PINNED_VALUES.items():
        assert values.get(name) == expected, name
    for name, expected in launch_profile._PRODUCTION_PINNED_NUMERICS.items():
        assert float(values[name]) == expected, name


def test_operator_document_is_a_retired_historical_pointer() -> None:
    readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("# Retired SN39 weight publisher deployment\n")
    assert "current validator guide" in readme
    assert "historical release reconstruction" in readme
    assert "systemctl" not in readme
    assert "cathedral-publisher-serve" not in readme
