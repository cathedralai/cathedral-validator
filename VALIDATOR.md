# Run a Cathedral SN39 validator

Cathedral's validator turns a signed, evidence-backed compute report into a
UID-aligned Bittensor weight decision. It supports two concurrent paths:

- a **thin path** that verifies Cathedral's signed vector; and
- an **independent provenance audit** that re-checks the public artifacts and,
  when configured with controlled evidence, can recompute the vector itself.

> [!CAUTION]
> `cathedral-validator serve` is **non-writing by default** in the launch
> candidate. Only an explicit `--broadcast` permits a chain-write attempt, and
> Finney SN39 still requires the signed release and transition gates. Until
> Cathedral publishes the supported tag, immutable pin bundle, and launch
> notice, use only `--offline --once` and `--dry-run --once`.

## Status

| Component | Current state |
|---|---|
| Signed vector, JWKS, and public evidence index | Deployed |
| Validator thin-path checks | Implemented |
| Concurrent shadow provenance audit | Implemented; default mode |
| Full-provenance authority mode | Implemented; requires `FULL` evidence and every independent pin |
| Current deployed vector vs independent verifier | `FAIL`: public v1/GPU-allocation contract does not match the v2/fixed-burn/body-binding verifier |
| General validator launch | Pending tagged release and final acceptance |

The current public contract mismatch is a launch blocker. Shadow mode reports
it but does not veto an otherwise valid thin vector, which is why operators
must remain in non-writing preview modes until the supported release
converges.

## What happens on each tick

```text
signed vector ── verify signature, scope, policy, expiry, rollback
      │
      ├── thin path ── map public hotkeys to fresh metagraph UIDs
      │
      └── provenance audit ── verify artifacts and recompute when possible
                                      │
                                      v
                            PASS / FAIL / NOT_PROVEN
      │
      v
local weight decision ── dry-run preview or authorized set_weights
```

The validator checks:

- Ed25519 signature and pinned `key_id`;
- `network = finney` and `netuid = 39`;
- the required reward-policy version;
- expiry and a durable monotonic rollback fence;
- burn contract and complete finite, non-negative weights;
- current hotkey-to-UID mapping immediately before a write; and
- the configured provenance mode's acceptance requirements.

A failed gate belonging to the active submission authority fails closed.
Default shadow provenance is observational: its `FAIL` or `NOT_PROVEN` result
does not block a thin submission whose own signed-vector gates pass.
Registration, uptime, attestation, and self-reported work never create positive
weight by themselves.

## Provenance modes

| Mode | Submission authority | Behavior |
|---|---|---|
| `shadow` | Thin path | Default. Independently audits evidence in the background without delaying the thin tick. |
| `authority` | Full-provenance recomputation | Refuses unless the epoch reaches `FULL` assurance and the recomputed vector passes every gate. |
| `off` | Thin path | Disables the independent audit. This is an explicit reduction in assurance. |

`receipts_only` is reported as `NOT_PROVEN`; it is not accepted as `FULL`.
Authority mode requires controlled raw evidence, a pinned static verifier,
independently pinned keys and digests, an immutable source revision, and an
independently queried historical candidate set. Read
[the full provenance contract](docs/PROVENANCE.md) before selecting it.

## Prerequisites

For the default thin + shadow mode:

- Linux or macOS with Python 3.11 or newer;
- a stable network connection;
- for metagraph-backed checks, a Bittensor-compatible Finney RPC endpoint; and
- for any future write, a registered SN39 validator hotkey with the required
  chain permissions.

Thin mode does not need TDX or GPU hardware. Full-provenance authority
additionally needs a Linux x86-64 host for the pinned static TDX verifier and
access to the controlled-disclosure package for the epoch being replayed.

Never place wallet seeds or private keys in TOML, environment files committed
to Git, logs, issues, or provenance bundles.

## Install a reviewed build

Do not install a moving branch for chain use. When a supported release is
published, verify the tag, commit, package digest, and release notes before
installation.

For source review and non-writing testing only:

```bash
git clone https://github.com/cathedralai/cathedral.git
cd cathedral

python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[provenance]'

cp config/validator.toml my-validator.toml
```

The project distribution is currently built from this repository; there is no
published `cathedralsubnet` PyPI package. A copied sample config is suitable
for review and previews only. Public launch operators must use the immutable
release configuration and installation named by the launch notice.

## Configure

Edit your copy, not the repository sample:

```toml
[network]
name = "finney"
netuid = 39
wallet_name = "<your-wallet-name>"
validator_hotkey = "<your-validator-hotkey-name>"

[publisher]
url = "https://api.cathedral.computer"

[weight_policy]
key_id = "cathedral-weight-policy"
public_key_hex = "<independently verified key from the supported release>"
require_policy = "validated_supply_v1"

[provenance]
mode = "shadow"
mechanism = "validated_supply_v1"
```

Create a private user-owned runtime directory, then set the state and log paths
through environment variables:

```bash
install -d -m 700 "$HOME/.cathedral"
export CATHEDRAL_VALIDATOR_STATE="$HOME/.cathedral/validator-state.json"
export CATHEDRAL_VALIDATOR_JSONL="$HOME/.cathedral/validator-events.jsonl"
```

Do not accept the key merely because it appears in the same checkout or
payload you are verifying. Compare the supported release's pin with the live
[JWKS](https://api.cathedral.computer/.well-known/cathedral-jwks.json) through
an independent channel.

For authority mode, add every pin documented in
[`docs/PROVENANCE.md`](docs/PROVENANCE.md). A missing pin is not inferred from
the manifest or public evidence server.

### Optional RPC endpoint

```bash
export CATHEDRAL_CHAIN_ENDPOINT="wss://your-finney-node.example:443"
```

The endpoint must serve the same Finney chain and historical state required by
the evidence anchor. Changing the RPC connection does not change the signed
`network` label.

## Non-writing acceptance

Run these in order.

### 1. Synthetic-map tick

This fetches the signed vector and shadow evidence over HTTPS, uses a synthetic
UID map, opens no chain connection, and cannot broadcast:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --offline \
  --once
```

Confirm:

- signature and policy checks pass;
- the vector is fresh and scoped to Finney SN39;
- burn and weights are finite and normalized;
- the provenance result is clearly `PASS`, `FAIL`, or `NOT_PROVEN`; and
- no wallet or chain client is initialized, and no broadcast is attempted.

### 2. Metagraph-backed dry run

This resolves hotkeys and computes the exact UID vector without writing:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --dry-run \
  --once
```

Confirm the current metagraph, burn destination, candidate mapping, normalized
weight sum, rollback state, and explicit “no chain writes” banner.

If there are no eligible miners, a burn-only outcome is expected fail-closed
behavior—not a reason to preserve an old positive vector.

## Observe the validator

TTY output is designed for a human operator. JSONL is the stable integration
surface:

```bash
tail -f "$CATHEDRAL_VALIDATOR_JSONL" | jq .
```

Useful lifecycle stages include `FEED`, `SIGNATURE`, `FRESHNESS`, `ROLLBACK`,
`PROVENANCE`, `VECTOR`, `PREFLIGHT`, `MAP`, `WEIGHTS`, and `CHAIN`. Records
include the active mode and a `PASS`, `FAIL`, `NOT_PROVEN`, or `INFO` status.
Credential-shaped values are redacted, but logs should still be protected as
operational data.

The lane state file stores rollback fences, provenance reservations, and
durable pending/finalized attempt records. The release-managed runtime root
also holds the cross-mode lock and ambiguity journal used to prevent a retry
after an uncertain submission. Keep both on durable owner-only storage; never
delete, roll back, or replace them to clear a refused attempt. Follow the
release runbook for recovery.

## Chain-writing launch gate

Do not add `--broadcast` until all of the following are true:

- [ ] Cathedral has published a supported immutable tag and launch notice.
- [ ] You verified the source/package digest and all signing-key pins.
- [ ] Synthetic-map and metagraph-backed dry runs passed on your machine.
- [ ] The current vector, evidence index, and provenance outcome match your
      intended assurance level; the known public contract mismatch is resolved.
- [ ] Your validator hotkey, permit, wallet isolation, RPC, and rollback-state
      backup are confirmed.
- [ ] You have explicit operator authorization for a mainnet transaction.
- [ ] You understand that only `--broadcast` permits a chain attempt, and the
      SN39 release and authorization state can still refuse it.

Only an authorized operator should then start the continuous service:

```bash
# MAINNET WRITE: calls set_weights when all gates pass.
cathedral-validator serve \
  --config <immutable-release-config> \
  --broadcast
```

Stop the service on any unexpected key, policy, candidate, provenance, burn,
rollback, or chain result. Do not “fix” a failed gate by disabling it during a
live launch.

## Updating or rotating keys

Treat a release or signing-key change as a new trust decision:

1. stop the chain-writing service;
2. fetch the new immutable release and pin bundle;
3. verify the change through an independent channel;
4. install into a new environment;
5. preserve and migrate the rollback state deliberately;
6. repeat synthetic-map and metagraph-backed dry runs; and
7. resume only after explicit operator authorization.

Never accept a replacement key from a weight payload signed only by the old or
new key itself.

## Compute + Distill integration (preview, default OFF)

`cathedral-validator` can independently verify **both** Compute (Intel TDX CPU and
confidential-GPU) and Distill receipts and compose one auditable weight vector, per
[cathedral-validator#1](https://github.com/cathedralai/cathedral-validator/issues/1).
The receipt/lane/config contract is shared with, and shipped by,
[`cathedral-distill`](https://github.com/cathedralai/cathedral-distill); this repo's
`cathedral_thin.integration` module drives it through the validator's own event
pipeline (`INTEGRATION_CONFIG`, `INTEGRATION_RECEIPT`, `INTEGRATION_LANE`,
`INTEGRATION_VECTOR`, each `PASS` / `FAIL` / `NOT_PROVEN`).

> [!IMPORTANT]
> This lane is **default OFF and non-writing**. It never touches the live
> `validated_supply_v2` thin path and never calls `set_weights`; it composes and
> audits a *preview* vector only. Enabling it as a live reward lane — and choosing
> the allocation — is a separate owner decision.

Enable the optional dependency, then verify + preview from a signed burn/allocation
config and a set of receipts:

```bash
python -m pip install -e '.[integration]'
```

```python
from cathedral_thin.integration import preview_integrated_vector, LaneReceipt

out = preview_integrated_vector(
    burn_config=burn_bytes, allocation_config=alloc_bytes,   # Cathedral-signed
    key_registry=registry, receipts=[LaneReceipt(kind, lane, receipt), ...],
    network="finney", netuid=39, source_epoch=epoch,
    now=now_dt, now_iso=now_iso, gpu_attestation_verifier=verify_gpu, events=events,
    # admission policy: required for any lane with a nonzero allocation
    allowed_measurements=frozenset({...}), allowed_tcb_statuses=frozenset({"UpToDate"}),
    allowed_advisories=frozenset(), current_block=finalized_block,
    consumption_ledger=ConsumptionLedger("/var/lib/cathedral/consumption.sqlite"),
    # consume_receipts=True only for the epoch's one authoritative pass; the
    # default reads the ledger, so this call can be repeated safely
)
out["feed"]   # one deterministic pre-burn vector; a missing/invalid lane -> burn
out["audit"]  # receipt -> verdict -> contribution -> allocation -> final weight
out["gates"]  # per lane: which admission gates were actually applied
```

What is verified before any weight: the burn/allocation config's signer,
network/subnet target, freshness, rollback fence, and burn destination; and each
receipt's anchored signing key, canonical `receipt_id`, replay/epoch binding,
freshness, strict TDX/TCB, and, for a GPU receipt, the composite binding to a
valid TDX CPU quote (a GPU attestation alone never admits). See the
[shared contract](https://github.com/cathedralai/cathedral-distill/blob/main/docs/INTEGRATION_CONTRACT.md).

### The preview fails closed on a missing policy

A lane with a **nonzero allocation is a reward lane**, so every gate in
`integration.REQUIRED_REWARD_GATES` must be supplied for it:
`allowed_measurements`, `allowed_tcb_statuses`, `allowed_advisories`,
`current_block`, `consumption_ledger`. Omit any one and the preview raises
`IntegrationPolicyError` before verifying a single receipt, because a preview that
could not apply the launch policy is not evidence that a receipt would be admitted
under it.

An **empty** allow-list is not an omission, it is a policy. `None` (bundle key
absent) means no policy was ever expressed, and that is what gets refused. What an
empty list *admits* is per list, so it is worth stating exactly:

| Empty list | Effect |
|------------|--------|
| `allowed_measurements=frozenset()` | admits nothing: every receipt carries exactly one measurement, and it is not in the list |
| `allowed_tcb_statuses=frozenset()` | admits nothing: same reasoning for `tcb.status` |
| `allowed_advisories=frozenset()` | admits only receipts that carry **no** advisory. The check is a subset test, so an advisory-free receipt passes and any receipt reporting an advisory is refused until the advisory is named |

A launch policy therefore looks like a real measurement list, a real TCB-status
list, and usually an *empty* advisory list, which is the strict setting rather than
a vacuous one.

Shadow and exploratory previews stay usable through one explicit opt-out,
`allow_unpoliced_preview=True` (CLI: `--allow-unpoliced-preview`). It must be the
boolean `True`: any other value, including the string `"false"` that a config
round-trip can produce, is refused with `IntegrationPolicyError` rather than
interpreted, because every non-empty string is truthy in Python and a truthiness
test would turn a deserialization mistake into an authorization. The omission is
recorded in `out["gates"]` and announced on stderr, so an unpoliced run can never
be mistaken for a policed one. An unfunded lane (allocation `0`) needs no policy,
because it cannot pay anyone.

### Inspection is repeatable; consumption is an explicit pass

The replay gate has two modes, because a preview and an epoch's authoritative pass
want opposite things from the same ledger.

| Mode | How | Ledger | Repeatable |
|------|-----|--------|------------|
| Inspection (default) | `preview_integrated_vector(...)`, CLI as-is | read only | yes: N runs return an identical vector |
| Authoritative | `consume_receipts=True`, CLI `--consume-receipts` | records each credited receipt | run at most once per epoch |

Inspection still refuses a receipt whose token is already on record, so replay
protection holds in both modes. What inspection does not do is spend the tokens:
a preview that consumed its own evidence composed a 100% burn vector the second
time it was run, which is the wrong property for a read-only document whose whole
purpose is to be examined before activation. `out["gates"]["replay_mode"]` and the
CLI status line say which mode ran.

### The replay ledger must actually record

`consumption_ledger` is checked by behaviour, not presence. It must implement
`consume` and `is_consumed`, and in the authoritative pass every consumption is
read back before the receipt is credited. A ledger that reports a consume it did
not record, cannot be queried, or is unavailable raises `IntegrationLedgerError`, a
preview-level failure: an outage reported as one `FAIL` per receipt would compose a
100% burn vector and still call the run a success, denying every legitimate miner.
The shared contract's `NO_REPLAY_LEDGER` marker counts as *no* ledger, so a funded
lane still refuses unless the operator also takes the unpoliced opt-out.

The gate runs only after selection is final, so a receipt that will not be credited
never spends its replay token, and the composed vector does not depend on the order
in which receipts were submitted.

### Reading the gate report and the audit trail

`out["gates"]` separates configuration from effect:

* `supplied`: what the operator passed;
* per lane, one boolean per gate: what the receipts **in that lane** actually had
  applied;
* per lane, `kinds`: the same per receipt kind.

They differ, and the difference is the point. `current_block` gates nothing for a
compute or distill receipt (only a CyberGym receipt carries a block window), and
the measurement/TCB/advisory policy gates nothing for a CyberGym receipt (it
carries no TEE evidence of its own). A report that echoed the arguments would say
`block_window=yes` for a compute lane, and a `current_block=0` typo would look like
an applied gate.

`out["audit"]["receipts"]` has one row per submission, in submission order, and
every row carries the same keys, including the seam-built refusals for lanes the
signed config does not fund. A consumer can read `row["credited"]` on every row.

### Lane boundary guarantees

* one malformed contribution forfeits only its own lane share; it can never abort
  the complete vector, including an unknown kind, an unfunded lane, an exception
  from an injected verifier, or a ledger failure;
* one receipt earns at most once across the whole preview, even with no ledger;
* a miner with two credited receipts in one lane keeps exactly one, chosen by
  lowest `receipt_id` so the outcome does not depend on submission order;
* the configured burn hotkey is never a reward subject, and a receipt claiming it
  is refused before it can consume a replay token.

### CyberGym lane

Each receipt kind has a canonical lane id
(`integration.DEFAULT_LANE_FOR_KIND`), so a preview bundle may name the lane or
take the default: `compute_cpu` -> `cathedral_confidential_tdx`, `compute_gpu` ->
`cathedral_confidential_gpu`, `distill` -> `cathedral_distill`, `cybergym` ->
`cathedral_cybergym`. A CyberGym receipt is authorized for a bounded
`[valid_from_block, valid_until_block)` window, so `current_block` is what
distinguishes an authorized receipt from an expired one. The CLI prints, per lane,
whether the measurement/TCB/advisory policy, the block window and the ledger were
applied.

## Further reading

- [SN39 Intel TDX CPU mainnet release boundary](docs/SN39_MAINNET_RELEASE_20260724.md)
- [Full-provenance verification](docs/PROVENANCE.md)
- [Score-class contract](docs/THIN_SCORE_CLASSES.md)
- [Threat model](docs/THIN_SUBNET_DESIGN.md)
- [Evidence record](docs/THIN_SUBNET_EVIDENCE.md)
- [Operator runbook for the experimental owner-independent path](docs/THIN_SUBNET_RUNBOOK.md)
