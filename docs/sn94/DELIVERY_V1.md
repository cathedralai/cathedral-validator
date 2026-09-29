# SN94 delivered-resource mode

This source adds a separate, opt-in SN94 mechanism. The default remains the
existing SAT machine-count mechanism. Delivered-resource mode has a real route
from receipt consumer through durable accounting to the existing chain writer
and recovery journal. It is disabled unless all three delivery paths are given.

This is source and local test evidence. It is **not a published signed release**
and has not been qualified on TDX hardware or the chain. Do not use the existing
SN39 signed channel as evidence that this SN94 mechanism is installed.

## Inputs and trust

Each `cathedral_delivery_receipt_v1` envelope contains a terminal delivered
interval, allocation attempt, sandbox ID, miner hotkey, TDX hardware identity,
approved measurement, quote digest, fresh admission nonce and lease, resource
reservations, two signatures, and `retention_until` at least 14 days after issue.
No commands, environment values, file contents, or customer payloads belong in
these receipts. The standalone `cathedral-delivery` package is pinned by Git
commit in `pyproject.toml`; it shares source with the executor contract.

The executor signature binds the entire body. The authority countersignature
asserts it matched a durable allocation, observed start/end, and a fresh quote
admission. Validators independently verify both signatures, the raw quote,
REPORT_DATA nonce/hotkey/executor-key binding, approved measurement, stable
hardware identity, and the pinned vendor verifier result. A JSON `verified`
flag or an operator seed is insufficient. The authority's trusted clock and
allocation accounting remain part of the trust boundary; TDX alone does not
prove the amount of useful work done.

**The customer lifecycle producer and authority allocation bridge are not
connected on main.** Standard and operator-verified seed sandboxes cannot be
converted to eligible work by filling in this schema. The existing capacity
challenge receipt proves a probe, not delivered customer resource seconds.

## Units, windows, and weights

An eligible interval contributes:

```text
reserved vCPU × elapsed integer seconds + reserved GiB × elapsed integer seconds
```

These are reserved resource seconds, not measured CPU utilization. A lost
sandbox or unattested execution contributes zero. There is no machine-count or
unattested fallback. Invalid signatures or incomplete attestation refuse the
whole window. A missing or unreadable feed does not become an empty feed.

The authority must split a long allocation at UTC accounting-window boundaries:
keep one `attempt_id` and `sandbox_id`, assign a different `receipt_id` per
window, and sign exact non-overlapping intervals. Adjacent intervals are allowed;
overlapping intervals and repeated attempt/window or receipt identities are
refused. The first consumed interval pins that attempt's miner, sandbox,
hardware, and executor key across later windows.

`burn_bps` reserves a fraction of the 65,535 integer weight units. The remainder
is apportioned to eligible miners by largest remainder with a deterministic
tie-break. No eligible work sends the complete vector to the configured sink.
The sink is an explicit UID **and hotkey**, checked against finalized identities.
It must currently appear as a serving non-validator miner in the existing
snapshot contract. Sending weights to this sink is not itself proof of an
on-chain token burn; the operator must qualify the sink's economic behavior.

## Operator preparation

Use Python 3.12 on Linux/amd64. For source-only local checks, from this checkout:

```bash
python3.12 -m venv .venv
.venv/bin/pip install '.[test,snp-production]'
.venv/bin/python scripts/test_sn94_delivery_cli.py
.venv/bin/python scripts/test_sn94_probe_cli.py
.venv/bin/python -m pytest tests/thin/test_delivery_plan.py tests/thin/test_delivery_runtime.py tests/thin/test_delivery_probe.py
```

These checks do not open a wallet or contact the chain. Synthetic admission and
fake-chain tests are explicitly marked; they are not hardware or live evidence.

The operator supplies a policy JSON with these exact fields:

```json
{
  "schema": "cathedral_sn94_delivery_policy_v1",
  "netuid": 94,
  "mode": "plan_only",
  "window_seconds": 3600,
  "burn_bps": 1000,
  "burn_uid": 0,
  "burn_hotkey": "REPLACE_WITH_QUALIFIED_SINK_HOTKEY",
  "allowed_measurements": ["REPLACE_WITH_REVIEWED_TDX_MEASUREMENT"],
  "verifier_path": "/absolute/release/verifier",
  "verifier_sha256": "REPLACE_WITH_RELEASE_PIN",
  "control_plane_keys": {"central-1": "REPLACE_WITH_PUBLIC_ED25519_HEX"}
}
```

Placeholders deliberately fail validation. The verifier path must identify an
absolute, regular, non-symlink file, not group/world writable, with the exact
pinned hash. Writing mode additionally requires the release QVL pin. Public
keys are not credentials; never place private keys in policy or feed files.

A feed has exactly `window_start`, `uid_hotkeys`, and `entries`. Each entry has
exactly `receipt`, `executor_public_key` (raw Ed25519 hex), and `quote_hex`.
The closed window must align with the policy. Maximum 1,000 entries and 8 MiB
per bundle. For writing, feed-provided miner identities are replaced with the
finalized metagraph; an external feed cannot choose who receives weights.

```bash
cathedral-validator delivery-plan --policy /absolute/policy.json \
  --bundle /absolute/bundle.json --ledger /absolute/private/delivery.sqlite
cathedral-validator delivery-plan --policy /absolute/policy.json \
  --recover-window 1790640000 --ledger /absolute/private/delivery.sqlite
```

This command only prepares/retrieves a plan and always reports
`chain_write: false`. For a production writer, the signed release and bootstrap
must first carry this code, the lifecycle producer must be qualified, and the
operator must deliberately choose `mode: write`. The existing validator process
then receives these additional flags:

```text
--netuid 94
--delivery-policy /absolute/policy.json
--delivery-bundle /absolute/bundle.json
--delivery-ledger /absolute/private/delivery.sqlite
```

The normal validator hotkey, permit, release verification, chain compatibility,
SNP policy startup checks, and journal protections still apply. SAT telemetry
cannot be combined with delivery mode. This change does not add commit/reveal
support to the writer; a chain that requires it remains a separate release gate.
Do not enable a service from this branch or bypass signed setup.

## Recovery

Receipt reservation and plan construction commit atomically in SQLite. Before
calling the signer, the delivery ledger persists `STARTED`. The existing writer
persists and recovers the exact signed extrinsic. The next cycle reconciles that
same plan and hash without signing again. A crash after `STARTED` but before a
writer journal exists returns `NOT_PROVEN`; it never assumes nothing happened.
A changed policy cannot reinterpret a reserved window or pending journal.

Never delete either ledger to clear uncertainty. Even finalized failed writes
need the existing operator recovery procedure. A settled window never submits
again automatically. Keep receipt evidence for its declared retention period;
accounting tombstones and unresolved journals must survive payload/log cleanup.
No retention cleaner is introduced by this patch.

## Ordinary-key probes

The `delivery-probe` CLI uses the same sandbox API as a customer. Load the API
key into `CATHEDRAL_API_KEY` through the operator's secret manager; it is not a
command argument, policy field, or log value.

```bash
cathedral-validator delivery-probe --api-url https://YOUR_CONTROL_PLANE \
  --image alpine:3.22 --max-spend-usd "$APPROVED_PROBE_CEILING" \
  --hold-seconds 30 --create-timeout 60
```

Set `APPROVED_PROBE_CEILING` to an explicitly approved per-sandbox dollar cap.
The command requires that cap and opts into the `sn94.v1` profile.
It submits one labelled, idempotent create, observes running, executes `true`
once, observes the sandbox during the hold, and requests deletion.
Exec and delete carry stable derived idempotency keys. A 202/deleting response
is reported as cleanup requested, not as confirmed deletion. It records create
and exec latency plus observed mid-life loss. Transport uncertainty is
`NOT_PROVEN`, not a fabricated loss or success. Neither create nor exec is
replayed after an ambiguous response; TTL is the cleanup backstop. Redirects
are refused so bearer credentials cannot cross origins.

These observations do not prove fleet capacity or the 24-hour loss SLO. They do
not grant admission and are not yet automatically scheduled each tempo or used
to discount weights. Publish sample count, observation duration, region and
hardware class alongside aggregates. Qualification still requires Affine's
500-trial, 100-in-flight acceptance test and the declared fleet quota.
