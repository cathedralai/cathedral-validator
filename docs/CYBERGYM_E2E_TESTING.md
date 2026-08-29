# CyberGym pre-launch E2E testing

**Scope (2026-08-03): local/default-off end-to-end testing only.** This procedure
does not deploy a validator, change an allocation, connect a wallet, submit
weights, or authorize CyberGym rewards. The existing validator remains the sole
weight authority.

## One thin path

```text
cathedral-distill
  verified receipts + durable closed score epoch
    -> canonical frozen score report
    -> bearer + exact-body HMAC
    -> POST /v1/cybergym/scores

cathedral-validator
  accepted {body, signature} proof + signed receipts
    -> audience / producer / freshness / completeness checks
    -> exact score and evidence-manifest binding
    -> replay and monotonic-epoch gates
    -> non-writing composed preview
```

Distill owns CyberGym task dispatch, verification, receipt issuance, scoring,
durable epoch close, and report production. This repository independently
verifies that evidence. Live weight integration is outside this E2E scope.

## What is proven in source

| Boundary | State |
|---|---|
| Closed Distill epoch to canonical report | Implemented. Export refuses open/incomplete epochs and freezes the first close time. Closed epochs reject new or replacement scores. |
| Producer to score intake | Implemented. The exact canonical bytes are bearer- and HMAC-authenticated; HTTPS is mandatory except on loopback; an accepted response must return the same semantic digest. |
| Durable proof handoff | Implemented. The publish command freezes the accepted `{body, signature}` sidecar consumed here. |
| Independent validator checks | Implemented. The validator rechecks the HMAC, audience, producer pin, freshness, units, complete scored set, evidence manifest, signed receipts, replay ledger, and monotonic epoch state. |
| CLI stateful E2E pass | Implemented and non-writing. `cybergym_epoch_state_path` now reaches the library gate instead of being dropped by the CLI. |
| Chain access | Excluded from this test. The preview opens no chain client and never calls `set_weights`. |

## Local E2E setup

Run the publisher intake in an isolated test process with a temporary SQLite
database and owner-only temporary secrets. Do not use live credentials or a live
publisher host. The intake uses these test-process settings:

- `CATHEDRAL_CYBERGYM_INGEST_ENABLED=1`
- `CATHEDRAL_CYBERGYM_SCORES_TOKEN`
- `CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET`
- `CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY`
- `CATHEDRAL_WEIGHT_POLICY_NETWORK`
- `CATHEDRAL_WEIGHT_POLICY_NETUID`

For a process-level E2E test, use a loopback URL such as
`http://127.0.0.1:<port>/v1/cybergym/scores`; cleartext HTTP is accepted only on
loopback. Run `cathedral-cybergym export-scores` against the temporary durable
score database, then `cathedral-cybergym publish-scores`. The latter writes an
accepted proof sidecar. Put that exact object under
`cybergym_epoch_proof` in the integration bundle and pin:

- `cybergym_expected_producer_hotkey`;
- `cybergym_expected_evidence_sha256` when an independently reviewed digest is
  available;
- `cybergym_epoch_state_path` to a durable SQLite path for the authoritative
  receipt-consumption pass.

From a validator source checkout with the integration extra installed, run
`python -m cathedral_thin.integration_cli` first without
`--consume-receipts`. Review the feed, audit, and gates. A second stateful E2E
pass may add `--consume-receipts` against temporary ledger and epoch-state files
to prove once-only behavior. The runtime labels this mode `authoritative`, but in
this procedure it is authoritative only over disposable test state; it still
opens no chain client and never calls `set_weights`.

## Durable progress record

Archive these non-secret artifacts per E2E run:

1. the frozen canonical score report and its SHA-256;
2. the intake acceptance response, including `report_sha256`, `body_sha256`,
   epoch, producer, audience, and idempotence state;
3. the frozen `{body, signature}` proof sidecar;
4. the exact preview bundle with secrets excluded;
5. the preview `{feed, audit, gates}` output;
6. source commits under test for both repositories; and
7. test results for the Distill CyberGym suite, validator CyberGym integration,
   intake, and single-writer checks.

These artifacts demonstrate durable E2E progress. They are not evidence of miner
incentive, emission, deployment readiness, or a live validator.

## E2E acceptance criteria

The pre-launch E2E test passes only when:

1. a contract-valid signed CyberGym receipt is recorded in the durable score store;
2. closing the epoch produces one deterministic canonical report;
3. the authenticated loopback intake accepts the exact bytes and returns matching
   semantic and body digests;
4. the accepted proof and signed receipt independently verify and bind in the
   validator preview;
5. a byte-identical retry is idempotent after process/database restart;
6. incomplete, stale, tampered, conflicting, and rollback inputs fail closed; and
7. chain clients and weight-writing functions are never reached.

Allocation design, production deployment, real wallet testing, and live-chain
evidence are separate later tasks and are not part of this procedure.

## Automated process-level test

Run the complete disposable path with:

```bash
PYTHONPATH=. python -m pytest -vv tests/thin/test_cybergym_prelaunch_e2e.py
```

The test invokes both Distill operator commands, serves the canonical intake on
an ephemeral loopback socket, restarts its SQLite-backed store, proves the retry
is idempotent, and then runs both inspection and once-only stateful validator
previews. All artifacts, credentials, ledgers, and epoch state are temporary.
