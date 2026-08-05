# Run a Cathedral SN39 validator

Cathedral's validator turns a signed, evidence-backed compute report into a
UID-aligned Bittensor weight decision. It supports two concurrent paths:

- a **thin path** that verifies Cathedral's signed vector; and
- an **independent provenance audit** that re-checks the public artifacts and,
  when configured with controlled evidence, can recompute the vector itself.

> [!IMPORTANT]
> **Install and first run live in one place: [README's
> quickstart](README.md#quickstart).** This runbook does not restate those
> commands — it explains what each step proves, what to watch afterwards, and
> what must be true before anyone adds `--broadcast`. Run the quickstart
> first; every command below assumes the `my-validator.toml` and the
> owner-only `$HOME/.cathedral` it produces.

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
| Full-provenance authority mode | Deprecated; no shipped config profile selects it (removal tracked in #40) |
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
| `shadow` | Thin path | The mode. Independently audits evidence in the background without delaying the thin tick. |
| `authority` | Full-provenance recomputation | **Deprecated.** Loses the chain-finality race; no shipped config profile selects it. The code path remains until the excision tracked in #40. |

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

The validator does not need TDX or GPU hardware; the background provenance
audit uses the pinned static TDX verifier binary only when the controlled
raw-evidence path is provisioned.

Never place wallet seeds or private keys in TOML, environment files committed
to Git, logs, issues, or provenance bundles.

## Install

Follow [README's quickstart](README.md#quickstart). It is the only install
procedure in this repository: clone, venv, `pip install -e '.[provenance]'`,
copy `config/validator-thin-sn39-relay.toml` to `my-validator.toml`, then the
two non-writing runs.

Do not install a moving branch for chain use. When a supported release is
published, verify the tag, commit, package digest, and release notes before
installation. The project distribution is built from this repository; there is
no published `cathedralsubnet` PyPI package. A copied profile is suitable for
review and previews only — public launch operators must use the immutable
release configuration and installation named by the launch notice.

Do not accept the signing key merely because it appears in the same checkout or
payload you are verifying. Compare the supported release's pin with the live
[JWKS](https://api.cathedral.computer/.well-known/cathedral-jwks.json) through
an independent channel.

Every provenance pin is documented in
[`docs/PROVENANCE.md`](docs/PROVENANCE.md). A missing pin is not inferred from
the manifest or public evidence server.

### Configuration comes from the file, not the environment

> [!WARNING]
> `CATHEDRAL_*` environment variables override the config file. That is a trap
> worth stating plainly, because the failure it causes names no cause: a
> leftover `export CATHEDRAL_VALIDATOR_STATE=$HOME/...` in a shell profile
> replaces the pinned state file, and every later broadcast attempt fails with
> `SN39 mainnet broadcast differs from the immutable trust profile:
> state_file`. The same applies to `CATHEDRAL_VALIDATOR_JSONL`,
> `CATHEDRAL_WEIGHT_POLICY_*`, `CATHEDRAL_EVIDENCE_URL`, and the
> `CATHEDRAL_PROVENANCE_*` pins.
>
> Configure a preview with the `--runtime-root`, `--state-file` and `--jsonl`
> flags from the quickstart, which are scoped to the one command that runs.
> Configure a service with its shipped config. If a broadcast is refused for a
> value you believe your config sets, check `env | grep CATHEDRAL_` first.

### Optional RPC endpoint

```bash
export CATHEDRAL_CHAIN_ENDPOINT="wss://your-finney-node.example:443"
```

This one is a connection override, not a trust value: it must serve the same
Finney chain and historical state required by the evidence anchor, and it does
not change the signed `network` label. `--chain-endpoint` does the same thing
per command.

## Non-writing acceptance

The two runs are quickstart steps 1 and 2. What to confirm in each:

### 1. Synthetic-map tick (`--offline --once`)

Fetches the signed vector and shadow evidence over HTTPS, uses a synthetic UID
map, opens no chain connection, and cannot broadcast. Confirm:

- signature and policy checks pass;
- the vector is fresh and scoped to Finney SN39;
- burn and weights are finite and normalized;
- the provenance result is clearly `PASS`, `FAIL`, or `NOT_PROVEN` — and not a
  transport or file error. A relay without controlled raw evidence reports
  `PROVENANCE_AUDIT_NOT_PROVEN` with `assurance receipts_only`, which is the
  expected outcome; a `FileNotFoundError` naming a key bundle means the audit
  never ran at all; and
- no wallet or chain client is initialized, and no broadcast is attempted.

A `--once` run exits non-zero unless the shadow audit reached the configured
minimum assurance in the same run, so a relay's healthy preview exits 1 and
records `PROVENANCE_HEALTH_GATE_FAILED`. That gate is deliberate — a one-shot
current-health run is not launch-ready evidence — and it exists only on the
`--once` path. Judge these two steps from the journal, not the exit status.

### 2. Metagraph-backed dry run (`--dry-run --once`)

Resolves hotkeys and computes the exact UID vector without writing. Confirm
the current metagraph, burn destination, candidate mapping, normalized weight
sum, rollback state, and explicit “no chain writes” banner.

If there are no eligible miners, a burn-only outcome is expected fail-closed
behavior—not a reason to preserve an old positive vector.

## Observe the validator

TTY output is designed for a human operator. JSONL is the stable integration
surface — the path is whatever `--jsonl` or `[logs].jsonl` set, so for a
quickstart preview:

```bash
tail -f "$HOME/.cathedral/validator-events.jsonl" | jq .
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

### Shadow-audit mismatch alert (systemd)

`deploy/sn39/cathedral-mismatch-check` turns two shadow-audit conditions in
the event journal into a failing oneshot service — the unit failing IS the
alert; there is no separate notification channel:

1. any `PROVENANCE_VECTOR_MISMATCH` in the last 30 minutes — the audit
   disagreed with a vector that was already accepted for submission, and
   could not re-verify that vector against the epoch it names either; and
2. persistent audit failure (#64) — at least one `PROVENANCE_AUDIT_FAIL` and
   zero `PROVENANCE_AUDIT_PASS` in the last 90 minutes (about three audit
   cycles). A transient `FAIL` followed by a `PASS` does not alert; an empty
   window does not alert.

`PROVENANCE_VECTOR_STALE_EPOCH` deliberately does NOT alert. The publisher
signs and caches a vector for up to a minute while the evidence index flips to
the next epoch, so an audit can hold last epoch's vector beside this epoch's
evidence. The audit then re-verifies that vector IN FULL against the epoch it
names — that epoch's signed manifest, its report body digest, and its
recomputed shares — and emits this `NOT_PROVEN` event instead. It is still a
disagreement (nothing is submitted on its strength), just not the tamper
alarm. A vector that cannot be re-verified against a signed, digest-matched
epoch is never reclassified: it stays `PROVENANCE_VECTOR_MISMATCH` and alerts.

The script reads `/var/log/cathedral-validator/validator-events.jsonl` by
default; pass a different journal path as its only argument. Install from the
reviewed release and enable the timer, which runs the check every 10 minutes:

```bash
install -D -o root -g root -m 0755 \
  "$release/deploy/sn39/cathedral-mismatch-check" \
  /usr/local/bin/cathedral-mismatch-check
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-mismatch-alert.service" \
  /etc/systemd/system/cathedral-mismatch-alert.service
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-mismatch-alert.timer" \
  /etc/systemd/system/cathedral-mismatch-alert.timer
systemctl daemon-reload
systemctl enable --now cathedral-mismatch-alert.timer
```

Watch `systemctl status cathedral-mismatch-alert.service` (a failed unit is
the alert) and `journalctl -u cathedral-mismatch-alert` for the reason line.
A healthy run prints `no recent mismatch; shadow audit not persistently
failing` and exits 0.

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
- [ ] `env | grep CATHEDRAL_` is empty of trust values, so the pinned config is
      what actually runs (see the environment warning above).
- [ ] The `[launch]` settings match what this runtime actually is — see [the
      two `[launch]` settings a relay depends
      on](README.md#the-two-launch-settings-a-relay-depends-on). A relay clears
      the completed-launch gate; a runtime that originates weights does not get
      to clear it by editing a config file.

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
`INTEGRATION_EPOCH_CLAIM`, `INTEGRATION_VECTOR`, each `PASS` / `FAIL` /
`NOT_PROVEN` as applicable).

> [!IMPORTANT]
> This lane is **default OFF and non-writing**. It never touches the live
> `validated_supply_v2` thin path and never calls `set_weights`; it composes and
> audits a *preview* vector only. Enabling it as a live reward lane — and choosing
> the allocation — is a separate owner decision.

What "non-writing" means precisely, so the guarantee is not read wider than it is:
the seam neither imports nor calls any chain writer in this repo. That is pinned by
tests, in three parts: a fresh interpreter importing the seam or its CLI loads no
`scaffold` module; an AST pass shows no import of `scaffold`, `bittensor` or a
substrate client; and a full preview composes its vector with every writer entry
point in this repo (`mechanism_weightset.set_weights`, `publish_next`,
`ChainClient.set_weights`, `ChainClient.map_weights`,
`validator_thin.set_weights_on_chain`, `_submit_exact_sn39_extrinsic`,
`BittensorRuntime.submit_weights`) replaced by a trap that raises if touched. Each
of those writers also refuses SN39 and finney on its own.

It is not a sandbox. The GPU/CPU verifiers and the event logger are supplied by the
caller and are run by the preview, with the caller's privileges; those callables are
the operator's own code.

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
    # consume_receipts=True atomically claims this epoch before consuming the
    # selected receipts; the default reads the ledger and is safely repeatable
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
| Authoritative | `consume_receipts=True`, CLI `--consume-receipts` | atomically claims the epoch, then records each credited receipt | exactly one winner; overlap/repeat is refused |

Inspection still refuses a receipt whose token is already on record, so replay
protection holds in both modes. What inspection does not do is spend the tokens:
a preview that consumed its own evidence composed a 100% burn vector the second
time it was run, which is the wrong property for a read-only document whose whole
purpose is to be examined before activation. `out["gates"]["replay_mode"]`, the
`authoritative_epoch_claim` field, and the CLI status line say which mode ran.

The authoritative guarantee is deliberately narrow and fail-closed. Before any
receipt token is mutated, the pass atomically consumes one claim token derived
from `(network, netuid, source_epoch)`. Concurrent processes can both perform
non-mutating verification, but exactly one can claim the epoch and proceed to
receipt consumption; every other process raises `IntegrationLedgerError`.

The epoch claim and the selected receipt tokens are not one database batch. If
the winning process crashes after the claim, the claim remains durable and the
epoch must be inspected and recovered by an operator. The software does not
silently retry that epoch, because a retry could split the credited set between
two competing vectors. This chooses a visibly withheld epoch over double credit
or ambiguous authoritative output.

### The replay ledger must actually record

`consumption_ledger` is checked by behaviour, not presence. It must implement
`consume` and `is_consumed`, and in the authoritative pass every consumption is read
back against the audit the pass produced. A ledger that reports a consume it did not
record, cannot be queried, or is unavailable raises `IntegrationLedgerError`, a
preview-level failure: an outage reported as one `FAIL` per receipt would compose a
100% burn vector and still call the run a success, denying every legitimate miner.
The shared contract's `NO_REPLAY_LEDGER` marker counts as *no* ledger, so a funded
lane still refuses unless the operator also takes the unpoliced opt-out.

### Where the token is actually spent

An uncredited receipt keeps its one-time token, and that has to hold for *every*
reason it might not be credited. `compose_integrated` refuses a contribution on five
grounds: an unknown lane, a lane funded with zero, a duplicate `receipt_id`, a miner
already credited in that lane, and the burn hotkey as subject. It is the only place
that knows all five, so it is the only safe place to burn a token, and that is where
the authoritative pass burns it: the verifier is called with
`defer_consumption=True`, which marks the decision `REPLAY_PENDING` without touching
the ledger, and the ledger is handed to the composer.

An earlier revision spent the token in the seam, before composition, having
pre-refused four of those five grounds. The fifth is reachable from a valid signed
config: an allocation is any decimal in `0..1`, so a lane can be *enabled and funded
with zero*. A receipt aimed at one was credited by the seam, had its token burned,
and was then dropped by the composer as "allocated zero and cannot pay". It earned
nothing and could never be credited again in any later epoch. Deferring removes the
whole class rather than adding a fifth check to a list that has to stay in sync.

Two things are checked afterwards, by state rather than by reading any message:

* every receipt the composer's own rules would have credited must actually be
  credited. The seam re-composes the same decisions with no ledger, which skips the
  consume step entirely, so the composer is its own oracle: a receipt that falls out
  of the real pass lost its credit to the ledger, not to a rule. Without this, a
  ledger whose writes fail becomes one dropped contribution per receipt and the pass
  still returns a burn vector and calls itself a success.
* a receipt credited anywhere must have its token on record, and a receipt credited
  nowhere must not.

Deduplication is the composer's, not the seam's. What the seam owes it is a
canonical ORDER, because the composer's rules are first-wins and the caller's
submission order must not decide who earns: decisions are composed sorted by
`(receipt_id, lane, kind)`, and the audit trail is restored to submission order
afterwards. Re-deriving those rules in the seam from a precomputed winner map got
one case wrong that the composer gets right, because the composer claims a lane's
per-miner slot only at the moment it credits: one receipt tagged into two lanes took
the second lane's slot, was refused there as already credited elsewhere, and the
miner's own second valid receipt in that lane was then refused citing a receipt that
lane never credited.

### Reading the gate report and the audit trail

`out["gates"]` separates configuration from effect:

* `supplied`: what the operator passed;
* `applied`: which gates actually ran against at least one receipt in the preview;
* per lane, one boolean per gate: what the receipts **in that lane** had applied;
* per lane, `kinds`: the same per receipt kind.

`supplied` and `applied` differ, and the difference is the point. `current_block`
gates nothing for a compute or distill receipt (only a CyberGym receipt carries a
block window), and the measurement/TCB/advisory policy gates nothing for a CyberGym
receipt (it carries no TEE evidence of its own). A compute-only preview with
`current_block` passed therefore reports `block_window` supplied and **not**
applied. A report that echoed the arguments would say `block_window=yes` for a
compute lane, and a `current_block=0` typo would look like an applied gate.

`out["audit"]["receipts"]` has one row per submission, in submission order, and
every row carries the same keys, including rows for lanes the signed config does not
fund. A consumer can read `row["credited"]` on every row.

Read `credited`, not `verdict`, to see who earned. `verdict` is the *verification*
outcome, so a miner's second valid receipt in one lane is `PASS`: it verified, and it
was simply not the one credited. `drop_reason` says why, and
`replay_token_consumed` says whether its one-time token was spent.

### Lane boundary guarantees

* one malformed contribution forfeits only its own lane share; it can never abort
  the complete vector, including an unknown kind, an unfunded lane, an exception
  from an injected verifier, or a ledger failure;
* one receipt earns at most once across the whole preview, even with no ledger;
* a miner with two credited receipts in one lane keeps exactly one, the lowest
  `receipt_id`, so the outcome does not depend on submission order;
* a receipt that is not credited keeps its replay token, for every one of the five
  reasons it might not be credited;
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

- [2026-07-24 SN39 Intel TDX CPU release record](docs/SN39_MAINNET_RELEASE_20260724.md)
- [Full-provenance verification](docs/PROVENANCE.md)
- [Score-class contract](docs/THIN_SCORE_CLASSES.md)
- [Threat model](docs/THIN_SUBNET_DESIGN.md)
- [Evidence record](docs/THIN_SUBNET_EVIDENCE.md)
- [Operator runbook for the experimental owner-independent path](docs/THIN_SUBNET_RUNBOOK.md)
