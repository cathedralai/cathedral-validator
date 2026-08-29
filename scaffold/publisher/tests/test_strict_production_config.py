from __future__ import annotations

import base64
import hashlib
import json
import os
import tomllib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from scaffold import validator_thin
from scaffold.publisher import app as app_mod
from scaffold.publisher import attest, launch_profile, real_corpus, rows, weights
from scaffold.publisher.auth import canonical_claim_bytes
from scaffold.publisher.store import Store


SIGNING_KEY_HEX = bytes(range(32)).hex()
DIVERGENT_SIGNING_KEY_HEX = bytes(range(1, 33)).hex()
SN39_BURN_HOTKEY = validator_thin.SN39_BURN_HOTKEY
REPO_ROOT = Path(__file__).resolve().parents[3]
EMPTY_BUNDLE_HASH = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
RETIRED_PRODUCTION_FLAGS = {
    "CATHEDRAL_ARENA_EVAL_ENABLED",
    "CATHEDRAL_ARENA_PAYOUT_ENABLED",
    "CATHEDRAL_ASYNC_VERIFY_ENABLED",
    "CATHEDRAL_ATTEST_ENABLED",
    "CATHEDRAL_ATTEST_ALLOW_STUB",
    "CATHEDRAL_AUDIT_SCANNER_ENABLED",
    "CATHEDRAL_ABUSE_LIMIT_ENABLED",
    "CATHEDRAL_CYBERGYM_INGEST_ENABLED",
    "CATHEDRAL_EXTERNAL_SCORES_ALLOW_UNAUTHENTICATED",
    "CATHEDRAL_MECH_WEIGHTSET_ALLOW_MAINNET",
    "CATHEDRAL_PERMINER_ENABLED",
    "CATHEDRAL_PER_HOTKEY_LIMIT_ENABLED",
    "CATHEDRAL_PERMINER_SHADOW",
    "CATHEDRAL_PM_ASYNC_SHADOW",
    "CATHEDRAL_PM_SUBMIT_ASYNC_ENABLED",
    "CATHEDRAL_REFILL_ENABLED",
    "CATHEDRAL_RETENTION_ENABLED",
    "CATHEDRAL_SAT_GENERATOR_ENABLED",
    "CATHEDRAL_SEED_ON_BOOT",
    "CATHEDRAL_SUBMIT_ASYNC_ENABLED",
    "CATHEDRAL_SUBMIT_HARD_CAP_BYPASS",
    "CATHEDRAL_V2_INGRESS_ALLOW_MULTI_WORKER",
    "CATHEDRAL_V2_INGRESS_DISABLE_PROCESS_LOCK",
    "CATHEDRAL_V2_SUBMIT_BACKPRESSURE_ENABLED",
    "CATHEDRAL_V2_SHADOW_V1_ENABLED",
}


def _strict_env(monkeypatch, *, production: bool = True) -> None:
    monkeypatch.setattr(
        launch_profile,
        "_SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX",
        rows.public_key_hex(SIGNING_KEY_HEX),
    )
    for name in ("ENV", "APP_ENV", "CATHEDRAL_PRODUCTION"):
        monkeypatch.delenv(name, raising=False)
    for name in (
        "CATHEDRAL_EVAL_SIGNING_KEY",
        "CATHEDRAL_PERMINER_ENABLED",
        "CATHEDRAL_PERMINER_WEIGHT_T1",
        "CATHEDRAL_V2_PERMINER_WEIGHT_T1",
        "CATHEDRAL_DB_PATH",
        "CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY",
        "CATHEDRAL_WEIGHTS_TIER_WEIGHTS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CATHEDRAL_LAUNCH_PROFILE", "v2-converged")
    monkeypatch.setenv("CATHEDRAL_SERVICE_ROLE", "all")
    monkeypatch.setenv(
        "CATHEDRAL_PUBLISHER_GENERATION_ID", "sn39-test-generation-01"
    )
    monkeypatch.setenv("CATHEDRAL_CYBERGYM_INGEST_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_TEE_GPU_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_MATERIALIZED_SNAPSHOT_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_DASHBOARD_SNAPSHOT_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_V2_VERIFY_WORKER_ENABLED", "true")
    if production:
        monkeypatch.setenv("CATHEDRAL_ENV", "production")
        monkeypatch.setenv("DATABASE_URL", "postgresql://unused.invalid/publisher")
    else:
        monkeypatch.delenv("CATHEDRAL_ENV", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "CATHEDRAL_V2_SUBMIT_TOKEN_SECRET",
        "submit-token-0123456789-ABCDEFGHIJKLMN",
    )
    monkeypatch.setenv(
        "CATHEDRAL_V2_PERMINER_SEED_SECRET",
        "perminer-seed-0123456789-ABCDEFGHIJKLM",
    )
    monkeypatch.setenv("CATHEDRAL_ALLOCATION_CONTRACT", "v2")
    monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "true")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_MODE", "proportional")
    monkeypatch.setenv("CATHEDRAL_PERMINER_SCORING_MODE", "bonus")
    monkeypatch.setenv("CATHEDRAL_PERMINER_BONUS_MULT", "0.2")
    monkeypatch.setenv("CATHEDRAL_PERMINER_HISTORY_FLOOR", "0.25")
    monkeypatch.setenv("CATHEDRAL_PERMINER_REQUIRE_COLDKEY", "true")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_WINDOW_HOURS", "24")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_TIER2_MULT", "3")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_TIER_WEIGHTS", "")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "off")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS", "600")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE", "false")
    monkeypatch.setenv("CATHEDRAL_V2_CHALLENGE_SOURCE", "planted")
    monkeypatch.setenv("CATHEDRAL_V2_REAL_FRACTION", "0")
    monkeypatch.setenv("CATHEDRAL_V2_REQUIRE_SOLVER_META", "false")
    monkeypatch.setenv("CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST", "")
    monkeypatch.setenv("CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS", "300")
    monkeypatch.setenv("CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES", "16384")
    monkeypatch.setenv("CATHEDRAL_SUBMIT_MAX_CONCURRENCY", "24")
    monkeypatch.setenv("CATHEDRAL_SUBMIT_HARD_CAP", "8")
    monkeypatch.setenv("CATHEDRAL_SUBMIT_BUSY_WAIT_SECS", "0.35")
    monkeypatch.setenv("CATHEDRAL_V2_BLOB_UPLOAD_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED", "false")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_ENABLED", "true")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED", "true")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MODE", "confidential_primary")
    monkeypatch.setenv(
        "CATHEDRAL_EXTERNAL_SCORES_SOURCE", "cathedral_confidential_tdx"
    )
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM", "true")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED", "true")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE", "false")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS", "3600")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS", "3600")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS", "120")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES", "4096")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES", "1048576")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED", "true")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETWORK", "finney")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETUID", "39")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_KEY_ID", "cathedral-weight-policy")
    monkeypatch.setenv("CATHEDRAL_CLIENT_IP_MODE", "headers")
    monkeypatch.setenv("CATHEDRAL_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("CATHEDRAL_RATELIMIT_RPM", "120")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY", SN39_BURN_HOTKEY)
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_BURN_UID", "")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2", "10")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS", "1800")
    monkeypatch.setenv(
        "CATHEDRAL_EXTERNAL_SCORES_TOKEN_CATHEDRAL_CONFIDENTIAL_TDX",
        "confidential-token-0123456789-ABCDEFGH",
    )
    monkeypatch.setenv(
        "CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET_CATHEDRAL_CONFIDENTIAL_TDX",
        "confidential-hmac-0123456789-ABCDEFGHI",
    )
    monkeypatch.delenv("CATHEDRAL_V2_DATABASE_URL", raising=False)
    monkeypatch.delenv("CATHEDRAL_V2_DB_PATH", raising=False)


def _add_eval_run(store: Store, hotkey: str, ran_at: str) -> None:
    def write(conn):
        conn.execute(
            "INSERT INTO eval_runs("
            "id, ran_at, eval_output_schema_version, miner_hotkey, task_type, row_json"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                ran_at,
                6,
                hotkey,
                "synthetic_boolean_v1",
                json.dumps({"weighted_score": 1.0}),
            ),
        )

    store.write(write)


def _build_production_test_app(tmp_path, monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_EVAL_SIGNING_KEY", SIGNING_KEY_HEX)
    sqlite_path = str(tmp_path / "publisher.sqlite")

    class PostgresContractStore:
        backend = "postgres"
        path = os.environ["DATABASE_URL"]

        def __init__(self):
            self._store = Store(sqlite_path, prefer_env_database_url=False)

        def __getattr__(self, name):
            return getattr(self._store, name)

    monkeypatch.setattr(
        app_mod,
        "Store",
        lambda _path, **_kwargs: PostgresContractStore(),
    )
    return app_mod.build_app(
        database_path="publisher.db",
        signing_key_hex=SIGNING_KEY_HEX,
    )


def _production_read_headers():
    from bittensor_wallet import Keypair

    keypair = Keypair.create_from_uri("//StrictProductionBitsetOnly")
    submitted_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    message = canonical_claim_bytes(
        bundle_hash=EMPTY_BUNDLE_HASH,
        card_id="synthetic_boolean_v1",
        miner_hotkey=keypair.ss58_address,
        submitted_at=submitted_at,
        challenge_id="",
        dimacs_solution_sha256="",
    )
    return {
        "X-Cathedral-Hotkey": keypair.ss58_address,
        "X-Cathedral-Signature": base64.b64encode(keypair.sign(message)).decode(),
        "X-Cathedral-Submitted-At": submitted_at,
    }


def test_production_signer_and_burn_pins_match_canonical_relay_config():
    relay = tomllib.loads(
        (REPO_ROOT / "config" / "validator-thin-sn39-relay.toml").read_text(
            encoding="utf-8"
        )
    )

    assert (
        launch_profile._SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX
        == relay["weight_policy"]["public_key_hex"]
    )
    assert launch_profile._SN39_WEIGHT_POLICY_KEY_ID == relay["weight_policy"]["key_id"]
    assert launch_profile._SN39_BURN_HOTKEY == relay["provenance"]["burn_hotkey"]


def test_production_requires_named_profile(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_ENV", "production")
    monkeypatch.delenv("CATHEDRAL_LAUNCH_PROFILE", raising=False)

    assert launch_profile.validate_env() == [
        "production requires an explicit CATHEDRAL_LAUNCH_PROFILE; "
        "set CATHEDRAL_LAUNCH_PROFILE=v2-converged"
    ]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_ENV", "prod"),
        ("CATHEDRAL_ENV", "mainnet"),
        ("CATHEDRAL_ENV", "PRODUCTION"),
        ("CATHEDRAL_ENV", " production "),
        ("ENV", "prod"),
        ("ENV", "production"),
        ("ENV", "mainnet"),
        ("APP_ENV", "prod"),
        ("APP_ENV", "production"),
        ("APP_ENV", "mainnet"),
        ("CATHEDRAL_PRODUCTION", "true"),
        ("CATHEDRAL_PRODUCTION", "treu"),
        ("CATHEDRAL_PRODUCTION", "false"),
    ],
)
def test_legacy_or_ambiguous_production_markers_fail_closed(
    monkeypatch, name, value
):
    _strict_env(monkeypatch, production=False)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(
        name in error and "set exactly CATHEDRAL_ENV=production" in error
        for error in errors
    )
    assert launch_profile.production() is False
    assert attest._production_mode() is False


def test_attestation_uses_canonical_production_detector(monkeypatch):
    _strict_env(monkeypatch)

    assert launch_profile.production() is True
    assert attest._production_mode() is True


def test_production_requires_shared_postgres_configuration(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.delenv("DATABASE_URL")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("production requires DATABASE_URL" in error for error in errors)


def test_production_rejects_non_postgres_database_url(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///publisher.db")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("must select the Postgres backend" in error for error in errors)


def test_production_rejects_padded_postgres_database_url(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL", " postgresql://user:pass@db.internal/publisher "
    )

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("must not contain surrounding whitespace" in error for error in errors)


def test_production_rejects_legacy_database_path_selector(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_DB_PATH", "postgresql://other-db/publisher")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("forbids legacy CATHEDRAL_DB_PATH" in error for error in errors)


@pytest.mark.parametrize(
    ("eval_key", "weight_key", "argument_key"),
    [
        (SIGNING_KEY_HEX, DIVERGENT_SIGNING_KEY_HEX, SIGNING_KEY_HEX),
        (SIGNING_KEY_HEX, SIGNING_KEY_HEX, DIVERGENT_SIGNING_KEY_HEX),
    ],
)
def test_production_rejects_divergent_signer_sources_before_open(
    monkeypatch, eval_key, weight_key, argument_key
):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_EVAL_SIGNING_KEY", eval_key)
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY", weight_key)

    def fail_if_opened(*_args, **_kwargs):
        raise AssertionError("divergent signer configuration must not open storage")

    monkeypatch.setattr(app_mod, "Store", fail_if_opened)

    with pytest.raises(
        RuntimeError,
        match="production requires one canonical Ed25519 signing identity",
    ) as exc_info:
        app_mod.build_app(
            database_path="publisher.db",
            signing_key_hex=argument_key,
        )

    message = str(exc_info.value)
    assert eval_key not in message
    assert weight_key not in message
    assert argument_key not in message


def test_production_rejects_direct_database_source_override_before_open(monkeypatch):
    _strict_env(monkeypatch)

    def fail_if_opened(*_args, **_kwargs):
        raise AssertionError("mismatched database source must not be opened")

    monkeypatch.setattr(app_mod, "Store", fail_if_opened)

    with pytest.raises(RuntimeError, match="exact validated DATABASE_URL"):
        app_mod.build_app(
            database_path="postgresql://other-db/publisher",
            signing_key_hex=SIGNING_KEY_HEX,
        )


def test_production_rejects_store_backend_mismatch(monkeypatch):
    _strict_env(monkeypatch)

    class UnexpectedSqliteStore:
        backend = "sqlite"

    monkeypatch.setattr(
        app_mod,
        "Store",
        lambda _path, **_kwargs: UnexpectedSqliteStore(),
    )

    with pytest.raises(RuntimeError, match="opened storage backend 'sqlite'"):
        app_mod.build_app(
            database_path="publisher.db", signing_key_hex=SIGNING_KEY_HEX
        )


def test_production_exposes_only_scored_bitset_miner_and_canonical_weight_paths(
    tmp_path, monkeypatch
):
    client = TestClient(_build_production_test_app(tmp_path, monkeypatch))
    jwks = client.get("/.well-known/cathedral-jwks.json").json()
    assert {key["public_key_hex"] for key in jwks["keys"]} == {
        rows.public_key_hex(SIGNING_KEY_HEX)
    }
    placeholder_headers = {
        "X-Cathedral-Hotkey": "unused",
        "X-Cathedral-Signature": "unused",
        "X-Cathedral-Submitted-At": "unused",
        "X-Cathedral-Blob-Sha256": "0" * 64,
    }

    assert client.post(
        "/v2/agents/submit-manifest",
        json={},
        headers=placeholder_headers,
    ).status_code == 404
    assert client.post(
        "/v2/blobs/solutions",
        content=b"unused",
        headers=placeholder_headers,
    ).status_code == 404
    assert client.get(
        "/v2/agents/submit-manifest/receipts/unused"
    ).status_code == 404
    assert client.post("/v2/admin/verify/tick").status_code == 404
    assert client.get("/v2/validator/weights/next").status_code == 404
    assert client.get("/v2/verify/metrics").status_code == 404
    assert client.get("/v2/audit/epochs/1").status_code == 404
    assert client.get("/v2/receipts/epochs/1").status_code == 404
    assert client.get("/v2/receipts/latest").status_code == 404
    assert client.post("/v1/agents/submit").status_code == 404
    assert client.get("/v1/agents/receipts/unused").status_code == 404
    assert client.get("/v1/synthetic-boolean/active-challenges").status_code == 404
    assert client.get("/v1/synthetic-boolean/active-cnf").status_code == 404
    assert client.get("/v1/challenges/unused/cnf?t=unused").status_code == 404
    assert client.get("/sat/latest.json").status_code == 404
    assert client.post("/v1/tee-gpu/offers").status_code == 404

    board = client.get(
        "/v2/synthetic-boolean/per-miner/challenges?limit=1",
        headers=_production_read_headers(),
    )
    assert board.status_code == 200, board.text
    payload = board.json()
    assert payload["submit_path"] == "/v2/agents/submit-bitset"
    assert payload["submit_bitset_path"] == "/v2/agents/submit-bitset"
    assert "manifest_submit_path" not in payload
    assert "blob_upload_path" not in payload
    assert payload["cnf_access_path"] is None


def test_production_protocol_positive_allowlist_is_exact(tmp_path, monkeypatch):
    app = _build_production_test_app(tmp_path, monkeypatch)
    expected = {
        ("GET", "/v1/validator/weights/next"),
        ("GET", "/v2/synthetic-boolean/per-miner/challenges"),
        ("GET", "/v2/synthetic-boolean/per-miner/cnf"),
        ("POST", "/v2/agents/submit-bitset"),
        ("GET", "/v2/agents/submit-bitset/receipts/{receipt_id}"),
    }

    support = {
        ("GET", "/.well-known/cathedral-jwks.json"),
        ("GET", "/health"),
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/v1/admin/synthetic-boolean/submit-metrics"),
        ("GET", "/v1/admin/validator-health"),
        ("POST", "/v1/external-scores/violet"),
        ("GET", "/v1/leaderboard/explain"),
        ("GET", "/v1/leaderboard/recent"),
        ("GET", "/v1/leaderboard/top"),
    }

    assert app_mod.PRODUCTION_PROTOCOL_ALLOWED_ROUTE_TEMPLATES == expected
    assert app_mod.PRODUCTION_SUPPORT_ALLOWED_ROUTE_TEMPLATES == support
    assert app_mod.PRODUCTION_ALLOWED_ROUTE_TEMPLATES == expected | support
    registered = {
        (method, route.path)
        for route in app.routes
        if hasattr(route, "methods")
        for method in route.methods
    }
    assert registered & (expected | support) == expected | support
    assert all(
        app_mod.production_route_allowed(method, path)
        == ((method, path) in expected | support)
        for method, path in registered
    )
    assert not app_mod.production_route_allowed(
        "GET", "/v2/agents/submit-bitset/receipts/one/future-route"
    )


def test_production_rejects_every_legacy_prefixed_allowed_route_before_strip(
    tmp_path, monkeypatch
):
    client = TestClient(_build_production_test_app(tmp_path, monkeypatch))

    for method, route_template in sorted(app_mod.PRODUCTION_ALLOWED_ROUTE_TEMPLATES):
        path = route_template.replace("{receipt_id}", "receipt-one")
        legacy_path = f"/api/cathedral{path}"
        assert not app_mod.production_route_allowed(method, legacy_path)

        response = client.request(method, legacy_path)

        assert response.status_code == 404, (method, legacy_path, response.text)
        assert response.headers["x-cathedral-rejection-reason"] == (
            "route_not_in_production_protocol"
        )

    assert client.get("/api/cathedral").status_code == 404


def test_production_v2_bitset_submit_saturates_at_effective_hard_cap(
    tmp_path, monkeypatch
):
    import asyncio
    import threading
    import time

    app = _build_production_test_app(tmp_path, monkeypatch)
    entered = 0
    entered_lock = threading.Lock()
    all_slots_held = threading.Event()
    release = threading.Event()

    async def hold_inner_app(scope, receive, send):
        nonlocal entered
        with entered_lock:
            entered += 1
            if entered == 8:
                all_slots_held.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    with TestClient(app) as client:
        layer = app.middleware_stack
        while layer is not None and type(layer).__name__ != (
            "_HotPathBackpressureMiddleware"
        ):
            next_layer = getattr(layer, "_app", None)
            if next_layer is None:
                next_layer = getattr(layer, "app", None)
            layer = next_layer
        assert layer is not None, "submit backpressure middleware is not installed"
        layer._app = hold_inner_app

        responses = [None] * 8
        failures = [None] * 8

        def hold_slot(index):
            try:
                responses[index] = client.post(
                    "/v2/agents/submit-bitset", content=b"{}"
                )
            except BaseException as exc:  # surfaced below after releasing all slots
                failures[index] = exc

        holders = [threading.Thread(target=hold_slot, args=(index,)) for index in range(8)]
        try:
            for holder in holders:
                holder.start()
            assert all_slots_held.wait(timeout=5), (
                f"only {entered} of 8 production bitset slots were acquired"
            )

            started = time.monotonic()
            saturated = client.post("/v2/agents/submit-bitset", content=b"{}")
            elapsed = time.monotonic() - started
        finally:
            release.set()
            for holder in holders:
                holder.join(timeout=5)

    assert saturated.status_code == 429, saturated.text
    assert saturated.headers["x-cathedral-rejection-reason"] == "submit_busy_retry"
    assert elapsed >= 0.3, f"busy response returned too early: {elapsed:.3f}s"
    assert not any(holder.is_alive() for holder in holders)
    assert failures == [None] * 8
    assert [response.status_code for response in responses] == [204] * 8


def test_production_submit_metrics_report_pinned_effective_cap(tmp_path, monkeypatch):
    admin_token = "publisher-admin-0123456789-ABCDEFGHI"
    monkeypatch.setenv("CATHEDRAL_PUBLISHER_ADMIN_TOKEN", admin_token)
    client = TestClient(_build_production_test_app(tmp_path, monkeypatch))

    response = client.get(
        "/v1/admin/synthetic-boolean/submit-metrics",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["configured_max_concurrency"] == 24
    assert payload["hard_cap"] == 8
    assert payload["max_concurrency"] == 8
    assert payload["busy_wait_secs"] == 0.35


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_ENABLED", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_MODE", "blend"),
        ("CATHEDRAL_EXTERNAL_SCORES_SOURCE", "violet_audio"),
        ("CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED", "treu"),
        ("CATHEDRAL_WEIGHT_POLICY_BURN_UID", "204"),
        ("CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY", "wrong-burn-hotkey"),
        ("CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2", "0"),
    ],
)
def test_production_rejects_incomplete_validated_supply_v1_contract(
    monkeypatch, name, value
):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "separately named" in error for error in errors)


def test_production_requires_registered_hotkey_filter_pin(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.delenv("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(
        "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED" in error
        and "<unset>" in error
        for error in errors
    )


@pytest.mark.parametrize(
    ("name", "alternate"),
    [
        ("CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED", "false"),
        ("CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST", "miner-hotkey"),
        ("CATHEDRAL_V2_REQUIRE_SOLVER_META", "true"),
        ("CATHEDRAL_V2_BLOB_UPLOAD_ENABLED", "true"),
        ("CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED", "true"),
        ("CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED", "true"),
        ("CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE", "true"),
        ("CATHEDRAL_PERMINER_REQUIRE_COLDKEY", "false"),
        ("CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE", "true"),
        ("CATHEDRAL_PERMINER_BONUS_MULT", "0.9"),
        ("CATHEDRAL_PERMINER_HISTORY_FLOOR", "0.9"),
        ("CATHEDRAL_WEIGHTS_WINDOW_HOURS", "48"),
        ("CATHEDRAL_WEIGHTS_TIER2_MULT", "2"),
        ("CATHEDRAL_WEIGHTS_TIER_WEIGHTS", "1=1,2=3"),
        ("CATHEDRAL_V2_REAL_FRACTION", "1"),
        ("CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS", "600"),
        ("CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES", "32768"),
        ("CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS", "7200"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS", "7200"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS", "600"),
        ("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS", "3600"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES", "1"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES", "512"),
        ("CATHEDRAL_CLIENT_IP_MODE", "railway"),
        ("CATHEDRAL_TRUSTED_PROXY_HOPS", "2"),
        ("CATHEDRAL_RATELIMIT_RPM", "0"),
        ("CATHEDRAL_SUBMIT_MAX_CONCURRENCY", "0"),
        ("CATHEDRAL_SUBMIT_HARD_CAP", "0"),
        ("CATHEDRAL_SUBMIT_BUSY_WAIT_SECS", "0"),
        ("CATHEDRAL_TEE_GPU_ENABLED", "true"),
        ("CATHEDRAL_MATERIALIZED_SNAPSHOT_ENABLED", "true"),
        ("CATHEDRAL_DASHBOARD_SNAPSHOT_ENABLED", "true"),
    ],
)
def test_production_rejects_protocol_and_freshness_drift(
    monkeypatch, name, alternate
):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, alternate)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "separately named" in error for error in errors)


@pytest.mark.parametrize(
    "name",
    [
        "CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED",
        "CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST",
        "CATHEDRAL_V2_REQUIRE_SOLVER_META",
        "CATHEDRAL_V2_BLOB_UPLOAD_ENABLED",
        "CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED",
        "CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED",
        "CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE",
        "CATHEDRAL_PERMINER_REQUIRE_COLDKEY",
        "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE",
        "CATHEDRAL_PERMINER_BONUS_MULT",
        "CATHEDRAL_PERMINER_HISTORY_FLOOR",
        "CATHEDRAL_WEIGHTS_WINDOW_HOURS",
        "CATHEDRAL_WEIGHTS_TIER2_MULT",
        "CATHEDRAL_WEIGHTS_TIER_WEIGHTS",
        "CATHEDRAL_V2_REAL_FRACTION",
        "CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS",
        "CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES",
        "CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS",
        "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES",
        "CATHEDRAL_CLIENT_IP_MODE",
        "CATHEDRAL_TRUSTED_PROXY_HOPS",
        "CATHEDRAL_RATELIMIT_RPM",
        "CATHEDRAL_SUBMIT_MAX_CONCURRENCY",
        "CATHEDRAL_SUBMIT_HARD_CAP",
        "CATHEDRAL_SUBMIT_BUSY_WAIT_SECS",
        "CATHEDRAL_TEE_GPU_ENABLED",
        "CATHEDRAL_MATERIALIZED_SNAPSHOT_ENABLED",
        "CATHEDRAL_DASHBOARD_SNAPSHOT_ENABLED",
    ],
)
def test_production_requires_explicit_protocol_and_freshness_pins(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.delenv(name)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "unset" in error for error in errors)


@pytest.mark.parametrize("value", [None, "read", "submit", "worker"])
def test_production_pins_single_all_service_role(monkeypatch, value):
    _strict_env(monkeypatch)
    if value is None:
        monkeypatch.delenv("CATHEDRAL_SERVICE_ROLE")
    else:
        monkeypatch.setenv("CATHEDRAL_SERVICE_ROLE", value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("CATHEDRAL_SERVICE_ROLE" in error for error in errors)


def test_production_requires_verify_worker_pin(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.delenv("CATHEDRAL_V2_VERIFY_WORKER_ENABLED")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("CATHEDRAL_V2_VERIFY_WORKER_ENABLED" in error for error in errors)


def test_production_pins_weight_policy_key_id(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_KEY_ID", "cathedarl-weight-policy")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("CATHEDRAL_WEIGHT_POLICY_KEY_ID" in error for error in errors)


@pytest.mark.parametrize(
    "name",
    [
        "CATHEDRAL_WEIGHT_POLICY_KEY_ID",
        "CATHEDRAL_WEIGHT_POLICY_NETWORK",
        "CATHEDRAL_WEIGHT_POLICY_NETUID",
    ],
)
def test_production_rejects_padded_trust_pins(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, f" {os.environ[name]} ")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "separately named" in error for error in errors)


def test_production_pins_derived_weight_policy_public_key(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setattr(
        launch_profile,
        "_SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX",
        "00" * 32,
    )

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("canonical validators pin" in error for error in errors)


@pytest.mark.parametrize(
    ("name", "alternate"),
    [
        ("CATHEDRAL_ALLOCATION_CONTRACT", "v3"),
        ("CATHEDRAL_WEIGHTS_MODE", "flat_recent"),
        ("CATHEDRAL_WEIGHTS_MODE", "row_score_recent"),
        ("CATHEDRAL_PERMINER_SCORING_MODE", "pm_primary"),
        ("CATHEDRAL_PERMINER_SCORING_MODE", "assigned_only"),
        ("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "mark"),
        ("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "filter"),
        ("CATHEDRAL_V2_CHALLENGE_SOURCE", "combinatorial"),
        ("CATHEDRAL_V2_CHALLENGE_SOURCE", "corpus"),
    ],
)
def test_production_rejects_valid_alternate_policy_values(monkeypatch, name, alternate):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, alternate)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(
        name in error
        and alternate in error
        and "separately named and reviewed launch profile" in error
        for error in errors
    )


@pytest.mark.parametrize("name", launch_profile._PROFILE_OWNED_ON_FLAGS)
@pytest.mark.parametrize("value", ["false", "treu", " "])
def test_profile_owned_boolean_cannot_disable_or_misspell_v2(
    monkeypatch, name, value
):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error for error in errors)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_WEIGHTS_MODE", "proportionl"),
        ("CATHEDRAL_PERMINER_SCORING_MODE", "primary"),
        ("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "filters"),
        ("CATHEDRAL_V2_CHALLENGE_SOURCE", "generated"),
        ("CATHEDRAL_V2_PERMINER_METHOD_T1", "ajm_typo"),
    ],
)
def test_strict_profile_rejects_mode_typos(monkeypatch, name, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and value in error for error in errors)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_WEIGHTS_WINDOW_HOURS", "twenty-four"),
        ("CATHEDRAL_WEIGHTS_TIER2_MULT", "nan"),
        ("CATHEDRAL_PERMINER_ALLOTMENT_T1", "1.5"),
        ("CATHEDRAL_PERMINER_WEIGHT_T3", "heavy"),
        ("CATHEDRAL_PERMINER_RECOVER_INDEX_CACHE", "64.5"),
        ("CATHEDRAL_V2_COLORING_NODES_T1", "many"),
        ("CATHEDRAL_V2_ERROR_BACKOFF_FLOOR_SECS", "nan"),
        ("CATHEDRAL_V2_ERROR_BACKOFF_CAP_SECS", "soon"),
        ("CATHEDRAL_DASHBOARD_PM_LIMIT", "many"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS", "forever"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS", "forever"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES", "many"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES", "10G"),
        ("CATHEDRAL_SUBMIT_MAX_CONCURRENCY", "lots"),
        ("CATHEDRAL_SUBMIT_HARD_CAP", "lots"),
        ("CATHEDRAL_SUBMIT_BUSY_WAIT_SECS", "forever"),
    ],
)
def test_strict_profile_rejects_malformed_numbers(monkeypatch, name, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and value in error for error in errors)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS", "-1"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS", "-1"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES", "0"),
        ("CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES", "0"),
        ("CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS", "0"),
        ("CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS", "-1"),
        ("CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS", "3601"),
    ],
)
def test_strict_profile_rejects_out_of_range_numbers(monkeypatch, name, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and value in error for error in errors)


def test_verify_lock_seconds_accepts_runtime_decimal(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_V2_VERIFY_LOCK_SECS", "1.5")

    assert launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX) == []


@pytest.mark.parametrize(
    "value",
    [
        '{"1":1,"2":"oops"}',
        "1=1,2=oops",
        '{"1":1,"0":2}',
        '{"1":1,"2":null}',
    ],
)
def test_tier_weights_fail_atomically(monkeypatch, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_TIER_WEIGHTS", value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("invalid atomic CATHEDRAL_WEIGHTS_TIER_WEIGHTS" in e for e in errors)


@pytest.mark.parametrize("value", ['{"1":1,"2":3}', "1=1,2=3"])
def test_valid_tier_weight_maps_remain_available_in_nonproduction(monkeypatch, value):
    _strict_env(monkeypatch, production=False)
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_TIER_WEIGHTS", value)

    assert launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX) == []


@pytest.mark.parametrize("value", ['{"1":1,"2":3}', "1=1,2=3"])
def test_production_rejects_even_valid_alternate_tier_weight_maps(monkeypatch, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_TIER_WEIGHTS", value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(
        "CATHEDRAL_WEIGHTS_TIER_WEIGHTS" in error
        and "separately named" in error
        for error in errors
    )


def test_app_float_parser_rejects_nonfinite_under_strict_profile(monkeypatch):
    _strict_env(monkeypatch, production=False)
    monkeypatch.setenv("CATHEDRAL_TEST_RUNTIME_FLOAT", "inf")

    with pytest.raises(RuntimeError, match="invalid finite numeric"):
        app_mod._env_float("CATHEDRAL_TEST_RUNTIME_FLOAT", 1.0)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CATHEDRAL_EVAL_SIGNING_KEY", "<ed25519-signing-key>"),
        ("CATHEDRAL_V2_SUBMIT_TOKEN_SECRET", "<v2-submit-token-secret>"),
        ("CATHEDRAL_V2_PERMINER_SEED_SECRET", "replace-me-with-a-secret"),
        (
            "CATHEDRAL_EXTERNAL_SCORES_TOKEN_CATHEDRAL_CONFIDENTIAL_TDX",
            "<confidential-tdx-token>",
        ),
        (
            "CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET_CATHEDRAL_CONFIDENTIAL_TDX",
            "short",
        ),
    ],
)
def test_production_rejects_placeholder_or_weak_secrets(monkeypatch, name, value):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error or "per-miner seed secret" in error for error in errors)


def test_production_rejects_example_database_placeholder(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://<user>:<pass>@<host>:5432/<db>"
    )

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("DATABASE_URL is still a documented placeholder" in e for e in errors)


def test_every_retired_or_bypass_mode_is_in_the_production_denylist():
    assert RETIRED_PRODUCTION_FLAGS <= launch_profile._PRODUCTION_FORBIDDEN_TRUTHY


@pytest.mark.parametrize(
    "name",
    [
        "CATHEDRAL_TEE_GPU_CHUTES_EXECUTE_ENABLED",
        "CATHEDRAL_TEE_GPU_INTAKE_ALLOWLIST",
        "CATHEDRAL_TEE_GPU_INTAKE_CODE",
        "CATHEDRAL_TEE_GPU_PUBLIC_CATALOG_ENABLED",
        "CATHEDRAL_TEE_GPU_REQUIRE_CRYPTO_EVIDENCE",
        "CATHEDRAL_TEE_GPU_REQUIRE_EVIDENCE",
        "CATHEDRAL_TEE_GPU_VERIFY_CMD",
    ],
)
def test_production_rejects_every_tee_gpu_or_chutes_configuration(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, "operator-configured")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "separately named profile" in error for error in errors)


@pytest.mark.parametrize("name", sorted(RETIRED_PRODUCTION_FLAGS))
def test_production_rejects_enabled_development_bypasses(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, "true")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "forbidden in production" in error for error in errors)


@pytest.mark.parametrize("name", sorted(RETIRED_PRODUCTION_FLAGS))
@pytest.mark.parametrize("value", ["treu", " "])
def test_production_rejects_malformed_retired_mode_booleans(
    monkeypatch, name, value
):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "invalid boolean" in error for error in errors)


@pytest.mark.parametrize("name", sorted(RETIRED_PRODUCTION_FLAGS))
def test_explicit_false_bypass_is_harmless(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, "false")

    assert launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX) == []


@pytest.mark.parametrize(
    "name", sorted(launch_profile._V2_PERMINER_PROFILE_OVERRIDE_ENVS)
)
def test_production_rejects_perminer_contract_overrides(monkeypatch, name):
    _strict_env(monkeypatch)
    monkeypatch.setenv(name, "operator-override")

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(name in error and "profile owns" in error for error in errors)


def test_production_perminer_pin_is_idempotent_but_still_detects_drift(
    monkeypatch,
):
    from scaffold.publisher import v2_pipeline

    _strict_env(monkeypatch)

    assert launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX) == []
    assert v2_pipeline.pin_v2_pm_env() is True
    assert launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX) == []

    monkeypatch.setenv("CATHEDRAL_PERMINER_WEIGHT_T2", "99")
    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any(
        "CATHEDRAL_PERMINER_WEIGHT_T2" in error and "profile owns" in error
        for error in errors
    )


def test_compatibility_mode_keeps_legacy_typo_fallbacks(monkeypatch):
    monkeypatch.delenv("CATHEDRAL_LAUNCH_PROFILE", raising=False)
    monkeypatch.delenv("CATHEDRAL_ENV", raising=False)
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_MODE", "proportionl")
    monkeypatch.setenv("CATHEDRAL_PERMINER_SCORING_MODE", "primary")
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "filters")
    monkeypatch.setenv("CATHEDRAL_V2_CHALLENGE_SOURCE", "generated")

    assert weights.mode() == "proportional"
    assert weights.perminer_scoring_mode() == "bonus"
    assert weights.payable_hotkeys_mode() == "off"
    assert real_corpus.challenge_source() == "planted"


def test_effective_submit_summary_matches_compatibility_empty_value_behavior(
    monkeypatch,
):
    _strict_env(monkeypatch, production=False)
    monkeypatch.setenv("CATHEDRAL_SUBMIT_MAX_CONCURRENCY", "")
    monkeypatch.setenv("CATHEDRAL_SUBMIT_HARD_CAP", "")
    monkeypatch.setenv("CATHEDRAL_SUBMIT_BUSY_WAIT_SECS", "")

    payload = launch_profile.effective_config_summary(
        database_path="publisher.db",
        service_role="all",
        storage_backend="sqlite",
        signing_key_hex=SIGNING_KEY_HEX,
    )

    assert payload["protocol"]["submit_max_concurrency_configured"] == 0
    assert payload["protocol"]["submit_hard_cap"] == 0
    assert payload["protocol"]["submit_max_concurrency_effective"] == 0
    assert payload["protocol"]["submit_busy_wait_secs"] == 0.0


def test_strict_empty_proportional_ledger_never_pays_legacy_flat_feed(
    tmp_path, monkeypatch
):
    now = datetime(2026, 8, 29, tzinfo=timezone.utc)
    store = Store(str(tmp_path / "publisher.sqlite"), prefer_env_database_url=False)
    _add_eval_run(
        store,
        "legacy-flat-hotkey",
        weights._ms_iso(now - timedelta(minutes=1)),
    )
    monkeypatch.setenv("CATHEDRAL_WEIGHTS_MODE", "proportional")
    monkeypatch.setenv("CATHEDRAL_PERMINER_BONUS_MULT", "0")

    monkeypatch.delenv("CATHEDRAL_LAUNCH_PROFILE", raising=False)
    assert weights.compose_scores(store, now=now) == {"legacy-flat-hotkey": 1.0}

    _strict_env(monkeypatch, production=False)
    assert weights.compose_scores(store, now=now) == {}
    since = weights._ms_iso(now - timedelta(hours=weights.window_hours()))
    assert weights._effective_mode(store, since) == "proportional_empty"
    vector = weights.build_signed_vector(
        store,
        signing_key_hex=SIGNING_KEY_HEX,
        now=now,
    )
    assert vector["policy_metadata"]["effective_mode"] == "proportional_empty"
    assert vector["policy_metadata"]["proportional_ledger_empty"] is True


def test_startup_emits_redacted_effective_configuration(tmp_path, monkeypatch, capsys):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_EVAL_SIGNING_KEY", SIGNING_KEY_HEX)
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET", "hmac-do-not-log")
    sqlite_path = str(tmp_path / "publisher.sqlite")

    class PostgresContractStore:
        backend = "postgres"
        path = os.environ["DATABASE_URL"]

        def __init__(self):
            self._store = Store(sqlite_path, prefer_env_database_url=False)

        def __getattr__(self, name):
            return getattr(self._store, name)

    monkeypatch.setattr(
        app_mod,
        "Store",
        lambda _path, **_kwargs: PostgresContractStore(),
    )

    app = app_mod.build_app(
        database_path="publisher.db",
        signing_key_hex=SIGNING_KEY_HEX,
    )

    output = capsys.readouterr().out
    config_line = next(
        line for line in output.splitlines() if line.startswith("[publisher_config] ")
    )
    payload = json.loads(config_line.split(" ", 1)[1])
    serialized = json.dumps(payload, sort_keys=True)
    assert payload["environment"] == "production"
    assert payload["launch_profile"] == "v2-converged"
    assert payload["service_role"] == "all"
    assert payload["storage_backend"] == "postgres"
    fingerprints = payload["replica_identity"]
    assert fingerprints == launch_profile.replica_identity_summary()
    assert fingerprints["schema"] == "cathedral_publisher_replica_identity_v1"
    assert fingerprints["publisher_generation_id"] == "sn39-test-generation-01"
    assert len(fingerprints["database_identity_fingerprint"]) == 64
    assert "submit_token_secret_fingerprint" not in fingerprints
    assert "perminer_seed_secret_fingerprint" not in fingerprints
    assert payload["signer"]["key_id"] == "cathedral-weight-policy"
    assert payload["signer"]["public_key_hex"] == rows.public_key_hex(SIGNING_KEY_HEX)
    assert payload["economics"]["weights_mode"] == "proportional"
    assert payload["economics"]["validated_supply_enabled"] is True
    assert payload["economics"]["forced_burn_percentage"] == 10.0
    assert payload["economics"]["external_scores_enabled"] is True
    assert payload["economics"]["external_scores_ingest_enabled"] is True
    assert payload["economics"]["external_scores_require_registered"] is True
    assert payload["economics"]["external_scores_require_evidence"] is False
    assert payload["economics"]["external_scores_source"] == "cathedral_confidential_tdx"
    assert payload["economics"]["external_scores_window_secs"] == 3600.0
    assert payload["economics"]["external_scores_max_report_age_secs"] == 3600.0
    assert payload["economics"]["external_scores_max_report_future_secs"] == 120.0
    assert payload["economics"]["external_scores_max_scores"] == 4096
    assert payload["economics"]["external_scores_max_body_bytes"] == 1048576
    assert payload["economics"]["registration_snapshot_max_age_secs"] == 600.0
    assert payload["economics"]["coldkey_collapse_enabled"] is False
    assert payload["economics"]["perminer_bonus_multiplier"] == 0.2
    assert payload["economics"]["perminer_history_floor"] == 0.25
    assert payload["economics"]["perminer_require_coldkey"] is True
    assert payload["economics"]["weights_window_hours"] == 24.0
    assert payload["economics"]["weights_tier2_multiplier"] == 3.0
    assert payload["economics"]["burn_hotkey"] == SN39_BURN_HOTKEY
    assert payload["economics"]["burn_uid"] is None
    assert payload["protocol"]["verify_worker_enabled"] is True
    assert payload["protocol"]["real_challenge_fraction"] == 0.0
    assert payload["protocol"]["weights_origin_failclosed"] is True
    assert payload["protocol"]["submit_token_allowlist_enabled"] is False
    assert payload["protocol"]["submit_token_ttl_secs"] == 300.0
    assert payload["protocol"]["submit_bitset_max_body_bytes"] == 16384.0
    assert payload["protocol"]["submit_max_concurrency_configured"] == 24
    assert payload["protocol"]["submit_hard_cap"] == 8
    assert payload["protocol"]["submit_max_concurrency_effective"] == 8
    assert payload["protocol"]["submit_busy_wait_secs"] == 0.35
    assert payload["protocol"]["require_solver_metadata"] is False
    assert payload["protocol"]["manifest_blob_compat_enabled"] is False
    assert payload["protocol"]["cnf_artifacts_enabled"] is False
    assert payload["protocol"]["results_publish_enabled"] is False
    assert payload["protocol"]["client_ip_mode"] == "headers"
    assert payload["protocol"]["trusted_proxy_hops"] == 1
    assert payload["protocol"]["global_ratelimit_rpm"] == 120
    assert payload["protocol"]["perminer_contract"] == (
        launch_profile.V2_CONVERGED_PERMINER_CONTRACT
    )
    assert payload["protocol"]["perminer_contract_sha256"] == (
        "f2e8a3e6c8a4901e6a3358026952f3ac0a5ad3b2f27c21d6ae5f01eed99488a1"
    )
    assert payload["secrets"]["CATHEDRAL_EVAL_SIGNING_KEY"] == "<redacted:set>"
    assert (
        payload["secrets"]["CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET"] == "<redacted:set>"
    )
    assert "hmac-do-not-log" not in serialized
    assert SIGNING_KEY_HEX not in serialized
    assert "unused.invalid" not in serialized
    client = TestClient(app)
    health = client.get("/health").json()
    assert health["replica_identity"] == fingerprints
    readiness = client.get("/health/ready").json()
    assert readiness["replica_identity"] == fingerprints


def test_effective_configuration_redacts_database_url(monkeypatch):
    _strict_env(monkeypatch)
    database_url = "postgresql://user:db-secret@example/db"
    monkeypatch.setenv("DATABASE_URL", database_url)

    payload = launch_profile.effective_config_summary(
        database_path="publisher.db",
        service_role="all",
        storage_backend="postgres",
        signing_key_hex=SIGNING_KEY_HEX,
    )
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["storage_backend"] == "postgres"
    assert payload["secrets"]["DATABASE_URL"] == "<redacted:set>"
    assert database_url not in serialized
    assert "db-secret" not in serialized

    first_fingerprint = payload["replica_identity"][
        "database_identity_fingerprint"
    ]
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://other-user:rotated@example/db"
    )
    rotated = launch_profile.effective_config_summary(
        database_path="publisher.db",
        service_role="all",
        storage_backend="postgres",
        signing_key_hex=SIGNING_KEY_HEX,
    )
    assert rotated["replica_identity"]["database_identity_fingerprint"] == (
        first_fingerprint
    )


def test_replica_identity_never_derives_public_secret_fingerprints(monkeypatch):
    _strict_env(monkeypatch)
    original = launch_profile.replica_identity_summary()

    replacement_submit = "submit-token-replica-drift-ABCDEFGHIJKLMN"
    replacement_seed = "perminer-seed-replica-drift-ABCDEFGHIJKLM"
    monkeypatch.setenv("CATHEDRAL_V2_SUBMIT_TOKEN_SECRET", replacement_submit)
    monkeypatch.setenv("CATHEDRAL_V2_PERMINER_SEED_SECRET", replacement_seed)
    changed = launch_profile.replica_identity_summary()
    changed_serialized = json.dumps(changed, sort_keys=True)

    assert changed == original
    assert replacement_submit not in changed_serialized
    assert replacement_seed not in changed_serialized
    assert hashlib.sha256(
        f"cathedral-v2-submit-token-v1\0{replacement_submit}".encode()
    ).hexdigest() not in changed_serialized
    assert hashlib.sha256(
        f"cathedral-v2-perminer-seed-v1\0{replacement_seed}".encode()
    ).hexdigest() not in changed_serialized

    monkeypatch.setenv(
        "CATHEDRAL_PUBLISHER_GENERATION_ID", "sn39-test-generation-02"
    )
    next_generation = launch_profile.replica_identity_summary()
    assert next_generation["publisher_generation_id"] != original[
        "publisher_generation_id"
    ]


@pytest.mark.parametrize(
    "value",
    [None, "short", " generation-with-spaces ", "<generation-id>"],
)
def test_production_requires_valid_nonsecret_generation_id(monkeypatch, value):
    _strict_env(monkeypatch)
    if value is None:
        monkeypatch.delenv("CATHEDRAL_PUBLISHER_GENERATION_ID")
    else:
        monkeypatch.setenv("CATHEDRAL_PUBLISHER_GENERATION_ID", value)

    errors = launch_profile.validate_env(signing_key_hex=SIGNING_KEY_HEX)

    assert any("CATHEDRAL_PUBLISHER_GENERATION_ID" in error for error in errors)


def test_effective_configuration_exposes_canonical_supply_and_burn_policy(monkeypatch):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "true")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2", "10")

    payload = launch_profile.effective_config_summary(
        database_path="publisher.db",
        service_role="all",
        storage_backend="postgres",
        signing_key_hex=SIGNING_KEY_HEX,
    )

    assert payload["economics"]["allocation_contract"] == "v2"
    assert payload["economics"]["validated_supply_enabled"] is True
    assert payload["economics"]["forced_burn_percentage"] == 10.0


def test_effective_configuration_uses_accepted_backend_not_url_presence(monkeypatch):
    _strict_env(monkeypatch)

    payload = launch_profile.effective_config_summary(
        database_path="publisher.db",
        service_role="all",
        storage_backend="sqlite",
        signing_key_hex=SIGNING_KEY_HEX,
    )

    assert payload["storage_backend"] == "sqlite"


def test_canonical_producer_vector_is_accepted_by_canonical_relay(
    tmp_path, monkeypatch
):
    _strict_env(monkeypatch)
    store = Store(
        str(tmp_path / "accepted.sqlite"),
        prefer_env_database_url=False,
    )

    vector = weights.build_signed_vector(
        store,
        signing_key_hex=SIGNING_KEY_HEX,
        now=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    assert vector["policy_metadata"]["validated_supply"] == {
        "contract_version": "v2",
        "intel_tdx_allocation": 0.9,
        "fixed_burn_allocation": 0.1,
        "burn_hotkey": SN39_BURN_HOTKEY,
    }
    assert validator_thin.vector_to_uid_weights(
        vector,
        {SN39_BURN_HOTKEY: 136},
        require_policy=validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
    ) == {136: 1.0}


def test_relay_rejects_producer_vector_when_supply_contract_is_disabled(
    tmp_path, monkeypatch
):
    _strict_env(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "false")
    store = Store(
        str(tmp_path / "rejected.sqlite"),
        prefer_env_database_url=False,
    )
    vector = weights.build_signed_vector(
        store,
        signing_key_hex=SIGNING_KEY_HEX,
        now=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    with pytest.raises(validator_thin.wire.VectorError, match="no validated_supply"):
        validator_thin.vector_to_uid_weights(
            vector,
            {SN39_BURN_HOTKEY: 136},
            require_policy=validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        )
