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
import subprocess
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uvicorn

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI  # noqa: E402

from cathedral_distill import cybergym_score_report  # noqa: E402
from cathedral_distill import operator_cli as distill_cli  # noqa: E402
from cathedral_distill import cybergym_http as cybergym_http  # noqa: E402
from cathedral_distill.cybergym_holdout import Holdout  # noqa: E402
from cathedral_distill.cybergym_private_artifacts import (  # noqa: E402
    PrivateChallengeArtifactStore,
    PrivateReferencePoCStore,
)
from cathedral_distill.cybergym_protocol import (  # noqa: E402
    CyberGymCorpusStore,
)
from cathedral_distill.cybergym_repro import ReproTaskSource  # noqa: E402
from cathedral_distill.cybergym_repro_manifest import (  # noqa: E402
    load_private_repro_manifest,
)
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    CyberGymScoreStore,
    CyberGymSolveStore,
)
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402
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
PRIVATE_EPOCH = 21
PRIVATE_MINER = "5PrivateE2EMiner"
PRIVATE_TASK = "arvo:368"
PRIVATE_POC = b"private-v2-e2e-poc"
PRIVATE_ARTIFACT = b"int parse(const unsigned char *input, unsigned long length);\n"
PRIVATE_MODEL = "sha256:" + hashlib.sha256(b"private-v2-e2e-model").hexdigest()


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


def _post_json(base: str, path: str, document: dict, *, miner: str | None = None):
    headers = {"Content-Type": "application/json"}
    if miner is not None:
        headers["X-Miner"] = miner
    request = urllib.request.Request(
        base + path,
        data=json.dumps(document).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _private_trace(task_id: str, poc: bytes) -> dict:
    thought = (
        "I inspect src/parser.c:42 to identify the length field, then follow the "
        "copy into the fixed buffer at src/parser.c:77. The vulnerable branch "
        "accepts an input length past that capacity, while the patched branch "
        "checks the same boundary before copying. I build the smallest input that "
        "crosses the copy boundary and independently verify the crash only occurs "
        "on the vulnerable image before submitting the exact bytes."
    )
    return {
        "task_id": task_id,
        "poc_sha256": poc_digest(poc),
        "model_id": "cathedral/private-v2-e2e",
        "licence": "cathedral-corpus-v1",
        "model_seal": "sha256:" + hashlib.sha256(b"private-v2-e2e-seal").hexdigest(),
        "steps": [
            {"step": 1, "action": "read_file", "thought": thought},
            {"step": 2, "action": "read_file", "thought": thought},
            {"step": 3, "action": "reason", "thought": thought},
            {"step": 4, "action": "write_poc", "thought": thought},
            {"step": 5, "action": "verify", "thought": thought},
        ],
    }


def _private_v2_service(tmp_path):
    artifact_digest = "sha256:" + hashlib.sha256(PRIVATE_ARTIFACT).hexdigest()
    poc_digest_value = "sha256:" + hashlib.sha256(PRIVATE_POC).hexdigest()
    manifest = load_private_repro_manifest(
        {
            "schema": "cathedral_cybergym_private_repro_manifest_v2",
            "source_epoch": PRIVATE_EPOCH,
            "tasks": [
                {
                    "task_id": PRIVATE_TASK,
                    "level": 2,
                    "disclosed_at": "2026-08-01T00:00:00Z",
                    "vulnerable_image": "registry.test/arvo-368-vul@sha256:"
                    + "ab" * 32,
                    "fixed_image": "registry.test/arvo-368-fix@sha256:" + "cd" * 32,
                    "context": {
                        "description": "private parser boundary task",
                        "sanitizer_trace": "AddressSanitizer: heap-use-after-free",
                    },
                    "challenge_artifact_digest": artifact_digest,
                    "reference_poc_digest": poc_digest_value,
                }
            ],
        }
    )
    artifacts = PrivateChallengeArtifactStore(
        manifest, {PRIVATE_TASK: PRIVATE_ARTIFACT}
    )
    references = PrivateReferencePoCStore(manifest, {PRIVATE_TASK: PRIVATE_POC})

    def docker(argv, capture_output=False, timeout=None):
        mount = next(value for value in argv if value.endswith(":/tmp/poc:ro"))
        submitted = Path(mount.split(":", 1)[0]).read_bytes()
        image = argv[argv.index(mount) + 1]
        crashed = (
            image == manifest.task(PRIVATE_TASK).vulnerable_image
            and submitted == PRIVATE_POC
        )
        return subprocess.CompletedProcess(
            argv,
            1 if crashed else 0,
            stdout=(
                b"==1==ERROR: AddressSanitizer: heap-use-after-free\n"
                if crashed
                else b"clean patched run\n"
            ),
            stderr=b"",
        )

    source = ReproTaskSource(
        manifest,
        challenge_artifacts=artifacts,
        reference_pocs=references,
        backend=docker,
    )
    key = Ed25519PrivateKey.generate()
    service = CyberGymService(
        Holdout(pool=source, _context={}),
        ChainContext(
            block=100,
            block_hash="0x" + "cd" * 32,
            network=NETWORK,
            netuid=NETUID,
            source_epoch=PRIVATE_EPOCH,
            valid_from_block=100,
            valid_until_block=460,
        ),
        backend=source.backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "private-corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "private-scores.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "private-solves.sqlite")),
        validator_hotkey="5PrivateE2EValidator",
        private_key=key,
        signing_key_id="cybergym-1",
        batch_size=1,
        cutoff=None,
        as_of=datetime.now(UTC),
        attestation_required=False,
        gates_required=False,
    )
    return service, key


def _private_bundle(fx, receipt, proof, tmp_path, cybergym_key) -> dict:
    config_key = base64.b64encode(fx.key.public_key().public_bytes_raw()).decode()
    now = datetime.now(UTC)
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "source_epoch": PRIVATE_EPOCH,
        "now": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "now_iso": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "burn_config": json.loads(fx.burn_config().decode()),
        "allocation_config": json.loads(
            fx.allocation_config(
                [{"lane": "cathedral_cybergym", "allocation": "0.90", "enabled": True}]
            ).decode()
        ),
        "keys": {
            "compute-1": config_key,
            "distill-1": config_key,
            "config-1": config_key,
            "cybergym-1": base64.b64encode(cybergym_key).decode(),
        },
        "receipts": [{"kind": "cybergym", "receipt": receipt}],
        "allowed_measurements": [fx.tdx_measurement],
        "allowed_tcb_statuses": ["UpToDate"],
        "allowed_advisories": [],
        "current_block": 200,
        "ledger_path": str(tmp_path / "private-consumption.sqlite"),
        "cybergym_epoch_proof": proof,
        "cybergym_expected_producer_hotkey": PRODUCER,
        "cybergym_expected_evidence_sha256": json.loads(proof["body"])[
            "evidence_sha256"
        ],
        "cybergym_epoch_state_path": str(tmp_path / "private-epochs.sqlite"),
    }


def test_distill_commands_to_restarted_intake_to_stateful_validator_preview(
    tmp_path, monkeypatch, capsys
):
    # A missing report producer is a broken immutable contract, not a skipped
    # E2E. The direct import above and this assertion keep that requirement
    # visible in the process-level path.
    assert callable(cybergym_score_report.build_score_report)
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


def test_private_v2_miner_to_verifier_to_validator_preview(
    tmp_path, monkeypatch, capsys
):
    """Prove the joined private path without Docker, chain access, or live secrets.

    The fake Docker runner is only the final process seam: it reads the real
    temporary PoC mount and emits the same target sanitizer signal a real private
    verifier consumes. Every protocol and durable boundary around it is real.
    """
    _publisher_env(monkeypatch)
    service, signing_key = _private_v2_service(tmp_path)
    server = cybergym_http.make_threaded_server(
        service,
        host="127.0.0.1",
        port=0,
        authenticator=lambda headers, _body: headers.get("X-Miner"),
        require_authentication=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, dispatched = _post_json(
            base,
            cybergym_http.DISPATCH_PATH,
            {"miner_hotkey": PRIVATE_MINER, "model_commitment": PRIVATE_MODEL},
            miner=PRIVATE_MINER,
        )
        assert status == 200
        task = dispatched["tasks"][0]
        assert task["task_id"] == PRIVATE_TASK
        assert task["artifact_digest"]

        request = {"task_id": PRIVATE_TASK, "batch_id": dispatched["batch_id"]}
        status, rejected = _post_json(
            base, cybergym_http.ARTIFACT_PATH, request, miner="5OtherMiner"
        )
        assert status == 400 and "active sealed batch" in rejected["error"]
        status, artifact = _post_json(
            base, cybergym_http.ARTIFACT_PATH, request, miner=PRIVATE_MINER
        )
        assert status == 200
        assert base64.b64decode(artifact["artifact_base64"]) == PRIVATE_ARTIFACT
        assert artifact["artifact_digest"] == task["artifact_digest"]
        assert PRIVATE_POC not in base64.b64decode(artifact["artifact_base64"])
        assert "vulnerable_image" not in artifact and "fixed_image" not in artifact

        status, verdict = _post_json(
            base,
            cybergym_http.SUBMIT_PATH,
            {
                "schema": "cathedral_cybergym_submission_envelope_v1",
                "batch_id": dispatched["batch_id"],
                "task_id": PRIVATE_TASK,
                "miner_hotkey": PRIVATE_MINER,
                "artifact_digest": task["artifact_digest"],
                "poc_base64": base64.b64encode(PRIVATE_POC).decode(),
                "trace": _private_trace(PRIVATE_TASK, PRIVATE_POC),
            },
            miner=PRIVATE_MINER,
        )
        assert status == 200
        assert verdict["accepted"] and verdict["solved"] and verdict["trainable"]
        assert verdict["work_units"] == "2"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    issued_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    results = service.score_epoch(issued_at=issued_at)
    assert len(results) == 1
    receipt = results[0].receipt
    assert receipt["miner_hotkey"] == PRIVATE_MINER
    assert receipt["score"]["work_units"] == "2"

    score_db = tmp_path / "private-scores.sqlite"
    report_path = tmp_path / "private-epoch-21.json"
    proof_path = tmp_path / "private-epoch-21.proof.json"
    assert (
        distill_cli.main(
            [
                "export-scores",
                "--score-db",
                str(score_db),
                "--epoch",
                str(PRIVATE_EPOCH),
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
    report = json.loads(report_path.read_bytes())
    assert report["scores"] == {PRIVATE_MINER: 2.0}

    token_path = tmp_path / "private-intake-token"
    secret_path = tmp_path / "private-intake-hmac"
    token_path.write_text(TOKEN + "\n", encoding="utf-8")
    secret_path.write_text(SECRET + "\n", encoding="utf-8")
    token_path.chmod(0o600)
    secret_path.chmod(0o600)
    publisher = Store(
        str(tmp_path / "private-publisher.sqlite"), prefer_env_database_url=False
    )
    with _loopback_intake(publisher) as url:
        assert (
            distill_cli.main(
                _publish_command(report_path, proof_path, token_path, secret_path, url)
            )
            == 0
        )
    published = json.loads(capsys.readouterr().out)
    assert published["accepted"] and not published["idempotent"]
    publisher.close()

    proof = json.loads(proof_path.read_bytes())
    config_now = datetime.now(UTC)
    fx = IntegrationFixtures(
        network=NETWORK,
        netuid=NETUID,
        source_epoch=PRIVATE_EPOCH,
        config_generated_at=config_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        config_valid_from=(config_now - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        config_valid_until=(config_now + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    bundle_path = tmp_path / "private-bundle.json"
    bundle_path.write_text(
        json.dumps(
            _private_bundle(
                fx,
                receipt,
                proof,
                tmp_path,
                signing_key.public_key().public_bytes_raw(),
            )
        ),
        encoding="utf-8",
    )
    inspection_path = tmp_path / "private-inspection.json"
    assert (
        validator_cli.main(
            ["--bundle", str(bundle_path), "--out", str(inspection_path)]
        )
        == 0
    )
    inspection = json.loads(inspection_path.read_bytes())
    assert inspection["gates"]["cybergym_epoch_proof"]["verified"] is True
    assert inspection["gates"]["cybergym_epoch_proof"]["bound"] is True
    assert inspection["audit"]["receipts"][0]["verdict"] == "PASS"
    assert {row["miner_hotkey"] for row in inspection["feed"]["weights"]} == {
        PRIVATE_MINER
    }

    stateful_path = tmp_path / "private-stateful.json"
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
    assert stateful["gates"]["cybergym_epoch_proof"]["epoch_state"] == "admitted"
    assert stateful["feed"] == inspection["feed"]
