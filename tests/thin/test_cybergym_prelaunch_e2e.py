"""One disposable pre-launch CyberGym E2E: Distill -> intake -> preview.

This is intentionally process-level where the repository boundary matters. It
uses the real Distill operator commands, a real loopback HTTP socket serving the
canonical intake route, a restarted publisher Store, and the real validator
preview CLI. Every database and secret belongs to ``tmp_path``. No chain client,
wallet, deployment host, allocation change, or weight writer is involved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest

pytest.importorskip(
    "cathedral_distill.cybergym_score_report",
    reason="merge the Distill report producer before updating the immutable pin",
)
uvicorn = pytest.importorskip("uvicorn")

from fastapi import FastAPI  # noqa: E402

from cathedral_distill import operator_cli as distill_cli  # noqa: E402
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    CyberGymScoreStore,
)
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402
from cathedral_thin import cybergym_epoch_proof as epoch_proof  # noqa: E402
from cathedral_thin import integration_cli as validator_cli  # noqa: E402
from scaffold.publisher import cybergym_ingest as ingest  # noqa: E402
from scaffold.publisher.store import Store  # noqa: E402

NETWORK = "finney"
NETUID = 39
SOURCE_EPOCH = 11
PRODUCER = "5Producer"
TOKEN = "local-e2e-token"
SECRET = "local-e2e-hmac-secret"


@contextmanager
def _loopback_intake(store: Store):
    """Serve only the canonical intake router on an ephemeral loopback port."""
    app = FastAPI()
    app.include_router(ingest.router)
    app.dependency_overrides[ingest.get_publisher_store] = lambda: store

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            log_level="critical",
            access_log=False,
            lifespan="off",
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5.0
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("loopback CyberGym intake did not start")
    try:
        yield f"http://127.0.0.1:{port}/v1/cybergym/scores"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            raise RuntimeError("loopback CyberGym intake did not stop")


def _publisher_env(monkeypatch) -> None:
    monkeypatch.setenv(ingest.INGEST_ENABLED_ENV, "1")
    monkeypatch.setenv(ingest.AUTH_TOKEN_ENV, TOKEN)
    monkeypatch.setenv(ingest.HMAC_SECRET_ENV, SECRET)
    monkeypatch.setenv(ingest.PRODUCER_HOTKEY_ENV, PRODUCER)
    monkeypatch.setenv(ingest.NETWORK_ENV, NETWORK)
    monkeypatch.setenv(ingest.NETUID_ENV, str(NETUID))
    monkeypatch.setenv(epoch_proof.EPOCH_PROOF_SECRET_ENV, SECRET)


def _publish_command(report, proof, token, secret, url) -> list[str]:
    return [
        "publish-scores",
        "--report",
        str(report),
        "--url",
        url,
        "--token-file",
        str(token),
        "--hmac-secret-file",
        str(secret),
        "--proof-out",
        str(proof),
    ]


def _bundle(fx, receipt, proof, tmp_path) -> dict:
    public_key = base64.b64encode(fx.key.public_key().public_bytes_raw()).decode()
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "source_epoch": SOURCE_EPOCH,
        "now": "2026-07-25T12:30:00Z",
        "now_iso": "2026-07-25T12:30:00.000000Z",
        "burn_config": json.loads(fx.burn_config().decode()),
        "allocation_config": json.loads(
            fx.allocation_config(
                [
                    {
                        "lane": "cathedral_cybergym",
                        "allocation": "0.90",
                        "enabled": True,
                    }
                ]
            ).decode()
        ),
        "keys": {
            "compute-1": public_key,
            "distill-1": public_key,
            "config-1": public_key,
            "cybergym-1": public_key,
        },
        "receipts": [{"kind": "cybergym", "receipt": receipt}],
        "allowed_measurements": [fx.tdx_measurement],
        "allowed_tcb_statuses": ["UpToDate"],
        "allowed_advisories": [],
        "current_block": 200,
        "ledger_path": str(tmp_path / "consumption.sqlite"),
        "cybergym_epoch_proof": proof,
        "cybergym_expected_producer_hotkey": PRODUCER,
        "cybergym_expected_evidence_sha256": json.loads(proof["body"])[
            "evidence_sha256"
        ],
        "cybergym_epoch_state_path": str(tmp_path / "cybergym-epochs.sqlite"),
    }


def test_distill_commands_to_restarted_intake_to_stateful_validator_preview(
    tmp_path, monkeypatch, capsys
):
    _publisher_env(monkeypatch)
    fx = IntegrationFixtures(network=NETWORK, netuid=NETUID, source_epoch=SOURCE_EPOCH)
    receipt = fx.cybergym_receipt()

    score_db = tmp_path / "scores.sqlite"
    score_store = CyberGymScoreStore(str(score_db))
    score_store.record(receipt)
    score_store.mark_epoch(
        SOURCE_EPOCH,
        state=EPOCH_CLOSED,
        scored_miners=1,
        at=datetime.now(UTC).isoformat(),
    )
    score_store.close()

    report_path = tmp_path / "epoch-11.json"
    proof_path = tmp_path / "epoch-11.proof.json"
    assert (
        distill_cli.main(
            [
                "export-scores",
                "--score-db",
                str(score_db),
                "--epoch",
                str(SOURCE_EPOCH),
                "--network",
                NETWORK,
                "--netuid",
                str(NETUID),
                "--producer-hotkey",
                PRODUCER,
                "--out",
                str(report_path),
            ]
        )
        == 0
    )
    report_bytes = report_path.read_bytes()

    token_path = tmp_path / "intake-token"
    secret_path = tmp_path / "intake-hmac"
    token_path.write_text(TOKEN + "\n", encoding="utf-8")
    secret_path.write_text(SECRET + "\n", encoding="utf-8")
    token_path.chmod(0o600)
    secret_path.chmod(0o600)

    publisher_db = tmp_path / "publisher.sqlite"
    first_store = Store(str(publisher_db), prefer_env_database_url=False)
    with _loopback_intake(first_store) as url:
        assert (
            distill_cli.main(
                _publish_command(report_path, proof_path, token_path, secret_path, url)
            )
            == 0
        )
    first_store.close()
    first_proof_bytes = proof_path.read_bytes()
    first_result = json.loads(capsys.readouterr().out)
    assert first_result["accepted"] is True
    assert first_result["idempotent"] is False
    assert first_result["body_sha256"] == hashlib.sha256(report_bytes).hexdigest()

    # Restart the intake process/store, then retry exact bytes. The report and
    # proof remain byte-identical and the audience-scoped epoch fence says retry.
    restarted_store = Store(str(publisher_db), prefer_env_database_url=False)
    with _loopback_intake(restarted_store) as url:
        assert (
            distill_cli.main(
                _publish_command(report_path, proof_path, token_path, secret_path, url)
            )
            == 0
        )
    second_result = json.loads(capsys.readouterr().out)
    assert second_result["accepted"] is True
    assert second_result["idempotent"] is True
    assert proof_path.read_bytes() == first_proof_bytes
    assert len(restarted_store.query("SELECT * FROM cybergym_score_reports")) == 1
    assert len(restarted_store.query("SELECT * FROM cybergym_scores")) == 1
    restarted_store.close()

    proof = json.loads(proof_path.read_bytes())
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        json.dumps(_bundle(fx, receipt, proof, tmp_path)), encoding="utf-8"
    )

    inspection_path = tmp_path / "inspection.json"
    assert (
        validator_cli.main(
            ["--bundle", str(bundle_path), "--out", str(inspection_path)]
        )
        == 0
    )
    inspection = json.loads(inspection_path.read_bytes())
    assert inspection["gates"]["replay_mode"] == "inspection"
    assert inspection["gates"]["cybergym_epoch_proof"]["verified"] is True
    assert inspection["gates"]["cybergym_epoch_proof"]["bound"] is True
    assert inspection["audit"]["receipts"][0]["verdict"] == "PASS"
    assert {row["miner_hotkey"] for row in inspection["feed"]["weights"]} == {
        "5CyberMiner"
    }

    stateful_path = tmp_path / "stateful.json"
    assert (
        validator_cli.main(
            [
                "--bundle",
                str(bundle_path),
                "--out",
                str(stateful_path),
                "--consume-receipts",
            ]
        )
        == 0
    )
    stateful = json.loads(stateful_path.read_bytes())
    assert stateful["gates"]["replay_mode"] == "authoritative"
    assert stateful["gates"]["cybergym_epoch_proof"]["epoch_state"] == "admitted"
    assert stateful["feed"] == inspection["feed"]

    # A second stateful pass cannot claim or consume the same test epoch again.
    assert validator_cli.main(["--bundle", str(bundle_path), "--consume-receipts"]) == 2
