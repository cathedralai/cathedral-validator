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
> Cathedral publishes a reviewed commit and launch
> notice, use only `--offline --once` and `--dry-run --once`.

## Status

| Component | Current state |
|---|---|
| Signed vector, JWKS, and public evidence index | Deployed |
| Validator thin-path checks | Implemented |
| Concurrent shadow provenance audit | Implemented; default mode |
| Full-provenance authority mode | Deprecated; no shipped config profile selects it (removal tracked in #40) |
| Current deployed vector vs independent verifier | Re-derive before relying on it — this status moves with each deploy. An earlier release recorded `FAIL` (public v1/GPU-allocation shape vs the v2/fixed-burn/body-binding verifier); the 2026-07-28 redeploy converged production and `cathedral-compute`'s `BUILD_STATUS.md` reported `AGREE` (2026-08-07). Confirm against the live signed vector before broadcasting. |
| General validator launch | Pending a scoreable corpus and final acceptance |

Any residual public-contract mismatch is a launch blocker, and shadow mode
reports it but does not veto an otherwise valid thin vector — so confirm the
live signed vector reproduces against the pinned verifier before broadcasting,
and stay in non-writing preview until it does. Do not rely on a static verdict
here or in `BUILD_STATUS.md`; both are dated and must be re-derived against the
live vector.

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
- a host clock disciplined by NTP (`chronyd`, `systemd-timesyncd`, or `ntpd`):
  the signed vector's freshness is judged against this host's clock, so a drift
  of a couple of minutes refuses every tick and writes nothing;
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

A preview runs `main`; that is the distribution. A validator that will
broadcast should not run a moving branch — pin the exact commit you reviewed
(`git checkout --detach <sha>`, which is what the systemd install's
`$release_sha` does), so an upstream merge cannot change what a chain-writing
process runs between one tick and the next. There are no tags: `git rev-parse
origin/main` is the normal way to name a reviewed commit. The distribution is
built from this repository; there is no published `cathedralsubnet` PyPI
package. See [Upgrade and rollback](#upgrade-and-rollback) for moving between
commits without disturbing durable state.

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

### Is it working right now? (`status`)

```bash
cathedral-validator status --config my-validator.toml
```

One screen, one exit code. `status` reads the event journal and only the
journal — no chain call, no wallet, no publisher fetch, no lock — so it is
safe to run beside a live validator as often as you like, and it still answers
when the thing that broke is the network. It prints the journal it read, when
the last tick completed, the last weight write, the last accepted vector, the
last shadow-audit verdict, and when the next tick is due.

It exits `0` when healthy, `1` when it is not — naming the reason — and `2`
when there is no journal configured to read at all. It applies the same five
rules as the systemd alert below, and `tests/thin/test_liveness_alert.py` runs
both against the same journals so they cannot drift apart. Pass `--jsonl PATH`
to point it at a preview journal — a preview wrote under `$HOME`, and without
the flag `status` reads the service path from the config and correctly reports
that it cannot see anything — and `--interval-secs` if the running validator's
tick interval is not the one in the config you gave it.

A start with no completed tick yet is reported as healthy and says so — the
footer reads `starting up`, not `ticks are completing`. That grace is given
once, dated from the first restart since the last completed tick, so a process
that keeps crashing and restarting runs out of it and turns `UNHEALTHY` with
`The validator is not writing weights.`

TTY output is designed for a human operator. JSONL is the stable integration
surface — the path is whatever `--jsonl` or `[logs].jsonl` set, so for a
quickstart preview:

```bash
tail -f "$HOME/.cathedral/validator-events.jsonl"    # pipe through `jq .` if you have it
```

**Filter on `event`.** It is the stable key: one code per outcome, and the
table below says which ones need a person. Every record also carries `ts`,
`stage`, `mode`, a `PASS`/`FAIL`/`NOT_PROVEN`/`INFO` `status`, and a `detail`.
`stage` is a coarse grouping — `startup`, `verify`, `map`, `safety`,
`provenance`, `launch`, `submit`, `result` (plus `INTEGRATION` for the
default-off preview lane) — and it is not a filter that will find you a
specific failure.

The field to read when something went wrong is `remediation`. Every refusal
recorded as `FAIL` or `NOT_PROVEN` carries one, and it says what is actually
true about that failure — whether anything was signed, whether a chain call had
begun, and what a person has to do:

```bash
python3 -c 'import json,sys,textwrap
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r.get("status") in ("FAIL", "NOT_PROVEN"):
        print(r["ts"], r["event"])
        for lead, key in (("  ", "detail"), ("  -> ", "remediation")):
            print(textwrap.fill(r.get(key, ""), 78,
                                initial_indent=lead, subsequent_indent="     "))' \
  "$HOME/.cathedral/validator-events.jsonl"
```

On the wallet-less box from quickstart step 2 that prints three blocks — the
two the relay always ends on, then the wallet failure. Abridged to the last:

```
2026-08-05T22:18:18.523Z TICK_FAILED
  Generic error: Failed to get hotkey: FileNotFound("Keyfile at: <path> does
     not exist.")
  -> The tick failed closed before any chain call, so nothing was signed,
     submitted, or finalized and there is no ambiguous write to inspect. The
     detail above names the cause; the next tick rebuilds every proof from a
     fresh finalized head.
```

Credential-shaped values, absolute paths and usernames are redacted — a path
in a message appears as the literal `<path>` — but journals should still be
protected as operational data.

The lane state file stores rollback fences, provenance reservations, and
durable pending/finalized attempt records. The runtime root also holds the
cross-mode lock and the ambiguity journal that prevents a retry after an
uncertain submission. Keep both on durable owner-only storage, and never
delete, roll back, or replace them to clear a refused attempt — that is the
one action that can turn a fenced write into a double write. What to do
instead is [below](#recovering-from-a-refused-or-fenced-write).

### When a tick does not write, alert on these

A tick that submits nothing is not one condition. Some of them clear by
themselves within a block or two and need nobody; others mean this validator
is writing no weights at all and will keep not writing until a person acts.
Each has its own event code so a filter does not have to choose between paging
on the routine ones and muting the serious ones.

| Event | Status | Page a human? | What it means |
| --- | --- | --- | --- |
| `WEIGHT_COOLDOWN_SKIPPED` | `INFO` | No | The subnet's own `weights_rate_limit` has not elapsed. The detail names the block at which the next write becomes possible. |
| `EPOCH_ROOM_SKIPPED` | `NOT_PROVEN` | No | Too few blocks were left in the epoch to prove mortal inclusion. Nothing was reserved or signed; the detail names the block at which it clears. |
| `WAITING_FOR_JOB` | `NOT_PROVEN` | No | Nothing was independently proven this epoch, so there is nothing to score. |
| `PRE_SIGN_HEAD_DRIFT_RETRY` | `NOT_PROVEN` | No | The chain moved while the tick was preparing; it rebuilds from a fresh head. |
| `PRE_SIGN_HEAD_DRIFT_RETRY_EXHAUSTED` | `FAIL` | Only if it repeats | The retry budget ran out. Nothing was signed and the loop re-arms on a short delay. |
| `CONTINUOUS_LAUNCH_LOCKED` | `FAIL` | **Yes** | Recurring writes are locked. This unit is up, ticking, and writing nothing, and will not start on its own: run `cathedral-validator reconcile-launch`, then restart the loop. |
| `SUBMISSION_FENCE_REFUSED` | `FAIL` | **Yes** | The local durable attempt fence would not reserve, before any chain call. Nothing was signed or submitted, and the cause — an unresolved pending attempt, a second writer, an unwritable runtime root — does not clear by itself. |
| `PENDING_RECEIPT_NOT_PROVEN` | `NOT_PROVEN` | **Yes** | A signed attempt is fenced awaiting finalized archive proof. Never submit a replacement. |
| `PENDING_RECEIPT_CONTRADICTION` | `FAIL` | **Yes** | A signed attempt has a positive contradiction. Stop every writer. |
| `TICK_FAILED` | `FAIL` | **Yes** | The residual: everything answerable without a person has been given its own code above, so this one means a person has to look. Read its `remediation` first — it says whether a chain call had begun. |

The two skip codes exist because they were the overwhelming majority of what
`TICK_FAILED` used to carry. Alerting on `TICK_FAILED`/`FAIL` is only worth
switching on if it does not fire for the chain's own schedule.

Every row there is the **terminal** outcome of a tick that wrote nothing. Four
more codes are worth recognizing precisely because they are not that:

- `VECTOR_REJECTED` (`FAIL`) and `PROVENANCE_RESERVATION_REFUSED` (`FAIL`)
  **accompany** a `TICK_FAILED` rather than replacing it. They name the cause —
  a signed vector that failed UID mapping, an authority reservation that a
  newer one or an unwritable state file refused — and both say "nothing was
  submitted". If you page on `TICK_FAILED`, these are what you read next.
- `UNSAFE_TARGETS_EXCLUDED` (`NOT_PROVEN`) is emitted by a tick that **did**
  write. One or more rewarded hotkeys had a UID mapping this validator could
  not prove stable, so their mass was **burned, not redistributed**; the detail
  names the excluded UIDs and the forfeited share. They rejoin automatically
  once their mapping is provable for a full mortal era. Nothing is broken, but
  the vector you submitted is not the vector the publisher signed shares for,
  and this is the only record of that.
- `PENDING_RECEIPT_RECOVERED` (`PASS`) is the resolution of the two
  pending-receipt rows above: the fenced attempt was re-proven against a
  finalized block, and the fence has cleared.

`PROVENANCE_STATE_STALE_SKIPPED` and `PROVENANCE_STATE_WRITE_FAILED`
(`NOT_PROVEN`) belong to the shadow audit's own bookkeeping. The second one is
worth fixing — its `remediation` is "fix the state file path/permissions" — but
neither touches the thin submission, which does not depend on the audit either
way.

### Recovering from a refused or fenced write

Four of the five **Yes** rows name a specific unresolved condition —
`CONTINUOUS_LAUNCH_LOCKED`, `SUBMISSION_FENCE_REFUSED`,
`PENDING_RECEIPT_NOT_PROVEN`, `PENDING_RECEIPT_CONTRADICTION` — and the
validator will not leave any of them on its own. Each has one correct
response, and they are not interchangeable. (`TICK_FAILED`, the fifth, is the
residual and has no single procedure: its `remediation` field says whether a
chain call had begun, and its `detail` names the cause.)

One rule governs all of them: **never delete, edit, restore or roll back the
state file or the runtime root to clear a refusal.** Those files are the only
record that an attempt was signed. Clearing one turns "one write, unconfirmed"
into two writes, and no later check can undo that.

**`CONTINUOUS_LAUNCH_LOCKED`.** Nothing was signed. Run:

```bash
cathedral-validator reconcile-launch --config /etc/cathedral-validator/validator-thin-sn39-relay.toml
```

It re-verifies the finalized rewarded-set-gated launch against the chain and
your durable state and submits nothing; on success it unlocks recurring writes
and names the block and extrinsic it proved. Restart the service afterwards.
Otherwise it exits 1 with `launch reconciliation failed closed:` and a cause,
and the lock is correct until that cause is not true. Note that the shipped
relay profile sets `require_completed_launch_for_broadcast = false`, so this
gate never runs for a pure relay — seeing this code means the runtime is not
one.

**`SUBMISSION_FENCE_REFUSED`.** Nothing was signed, submitted or finalized: the
reservation is taken immediately before the chain call precisely so a refusal
here leaves no ambiguous write. The cause is local and does not clear itself.
Check, in this order:

1. **a second writer.** `systemctl list-units 'cathedral-validator*'` and
   `pgrep -af cathedral-validator`. The relay unit declares `Conflicts=` and an
   `ExecStartPre=` guard, but neither can stop a process someone started by
   hand in a shell;
2. **the runtime root.** Is it writable by the account the service runs as, is
   the filesystem full or read-only, and is it the path the config names? A
3. **an unresolved pending attempt** in the state file — which is the next
   entry, not this one.

**`PENDING_RECEIPT_NOT_PROVEN`.** Read the record's `remediation` first,
because this code covers two situations that want opposite responses:

- *"The exact signed attempt remains fenced"* — a transaction was signed and
  its outcome is not yet provable from a finalized block. There is nothing to
  do but let it re-prove: a broadcasting validator re-runs the recovery before
  every tick, so leaving the service running, or restarting it, retries.
  Success is a `PENDING_RECEIPT_RECOVERED` record. **Never submit a
  replacement** — not with a second config, not by hand.
- *"No signed attempt was recorded before this failure"* — nothing is fenced
  and nothing is owed. The detail names the failing preflight step: an
  unregistered hotkey, a missing validator permit, an RPC that would not serve
  the metagraph at the finalized head, or the 180s deadline. Fix that and
  restart.

**`PENDING_RECEIPT_CONTRADICTION`.** A signed attempt has a positive
contradiction: the chain and this validator's journal disagree about what
happened. Stop every writer for this hotkey on every host, and leave the state
file and runtime root byte-for-byte as they are. Establish what the named
extrinsic actually did from an independent chain view before anything writes
again. This is the one state where a guess costs more than the downtime.

### Liveness and shadow-audit alert (systemd)

`deploy/sn39/cathedral-mismatch-check` turns five conditions in the event
journal into a failing oneshot service — the unit failing IS the alert; there
is no separate notification channel:

1. the journal is missing, is not a regular file, is unreadable, is empty with
   no rotated generation beside it, or holds no parseable record. **This check
   fails closed**: a monitor that cannot see the validator must never report
   that the validator is fine;
2. the newest record is older than 3 tick intervals — the validator is
   stopped, wedged, or writing to a different path;
3. no tick has COMPLETED in the last 4 tick intervals — no
   `WEIGHTS_SUBMITTED`, `WEIGHTS_DRY_RUN`, `WEIGHT_COOLDOWN_SKIPPED` or
   `WAITING_FOR_JOB`. That is what a validator which has silently stopped
   writing weights looks like. A tick declined by the subnet's
   `weights_rate_limit`, and a tick that found nothing to score, both count as
   alive. A process that restarted inside the window is given until the end of
   it to finish its first tick — dated from the **first** restart since the
   last completed tick, not the newest, so a crash-restart loop cannot renew
   its own grace. It used to: every crash wrote a `STARTUP` and kept the
   journal growing, so six hours of writing nothing read as "starting up" and
   exited 0 in both halves of this alert;
4. any `PROVENANCE_VECTOR_MISMATCH` in the last 30 minutes — the audit
   disagreed with a vector that was already accepted for submission, and
   could not re-verify that vector against the epoch it names either; and
5. persistent audit failure (#64) — the audit's **two most recent completed
   outcomes** inside the last 90 minutes (about three audit cycles) are both
   `PROVENANCE_AUDIT_FAIL`. A single `FAIL` never alerts; an empty window does
   not alert; and any completed audit after the failures — `PASS` **or**
   `NOT_PROVEN` — clears it.

Rule 3 also fires when the process is perfectly healthy but the signed feed
has been unreachable for the whole window, because the fail-closed idle state
writes nothing and the operator is losing emission either way. The `ALERT:`
line says "the validator is not writing weights", which is what is true; the
journal and `cathedral-validator status` say which of the two it is.

Rules 1-3 exist because rules 4 and 5 alone were green for a dead validator:
both greps returned zero matches for a journal that no longer existed, and
zero matches read as "nothing is wrong". The expensive SN39 failure is not a
bad vector, it is no vector at all.

The two liveness windows are tick multiples, so a validator configured to tick
faster is declared dead sooner rather than later. They are measured against
the shipped `[weights].interval_secs` of 1500s; if you changed it, set
`CATHEDRAL_TICK_SECS` in the unit to match (`Environment=CATHEDRAL_TICK_SECS=…`).

#### A relay's steady state is `NOT_PROVEN` on every tick, and that is correct

Recovery in rule 2 is "the next audit completed with some outcome other than
`FAIL`", not "a `PASS`", because on a third-party relay a `PASS` never comes.

`PROVENANCE_AUDIT_PASS` is emitted only when the audit reaches the configured
`min_assurance` (default `rewarded_set_proven`, meaning every rewarded hotkey
was replayed from raw evidence). A relay has no controlled raw-evidence
package — `config/validator-thin-sn39-relay.toml` sets no `controlled_dir` or
`verifier_binary`, and `cathedral-validator-sn39-relay.service` deliberately
omits the `cathedral-validator-evidence` group — so its audit is
`receipts_only`, below that bar, and it logs `PROVENANCE_AUDIT_NOT_PROVEN`
every ~25 minutes. **That is the permanent, expected, correct steady state of
a relay, not a fault to chase.** It means the audit ran and verified what a
relay can verify; the thin submission never depended on it either way. The
only relay journal worth acting on is one with no `PROVENANCE_*` records at
all, or the two alert conditions above.

Keying recovery on `PASS` would therefore have reduced rule 2 on every relay
to "one `PROVENANCE_AUDIT_FAIL` in 90 minutes alerts". Since any exception
inside the audit is recorded as `FAIL`, and the ones seen in practice are
publisher-side and self-clearing (`evidence index is stale`, `score report is
stale`), a 60-second hiccup upstream would have failed the alert unit for 90
minutes while claiming a sustained outage. Two consecutive failures are
required precisely so the timer stays trustworthy enough to leave enabled —
rule 1 is the alarm that matters, and it is only ever seen through this unit.

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
default; pass a different journal path as its only argument.

#### Log rotation, and why it does not blind the alert

`deploy/sn39/cathedral-validator.logrotate`, installed as
`/etc/logrotate.d/cathedral-validator`, bounds `/var/log/cathedral-validator`
at 14 daily generations or 64 MB, whichever comes first. Nothing rotated it
before, and both streams there are append-only.

It rotates with `copytruncate` because it has to: `scaffold/events.py` opens
each stream once, `O_APPEND`, and holds the descriptor for the life of the
process, so a rename-and-create rotation would leave the validator writing into
the renamed inode until its next restart while the live path sat at zero bytes.
`copytruncate` keeps the inode, so the descriptor, its owner and its
`0600`/`0640` mode all survive, and the next append lands at offset 0.

The consequence is that for up to one tick interval after a rotation the live
journal is legitimately empty. Both readers handle that the same way: the
alert and `scaffold/health.py` (behind `cathedral-validator status`) also read
the single most recent rotated generation, which `delaycompress` keeps
uncompressed as `validator-events.jsonl.1`. Removing `delaycompress`, or
switching to `create`, would put a healthy validator's newest record out of
reach of both — a red liveness alert on a working validator, or a blind one.

The durable submission state under `/var/lib/cathedral-validator` — the
monotonic fences, the anti-rollback watermarks and the signed-attempt journal —
is deliberately not covered by any rotation rule and must never be added to
one.

**Installing it is a step of the supported install, not an extra.** The three
files below are installed and the timer enabled by README's
[Supported systemd install (relay)](README.md#supported-systemd-install-relay)
block, and `--relay` binds all three in the release manifest — so install them
*before* building the manifest, or the build fails with `required release file
is unavailable`. Do not install them by hand out of that order; the table below
records only which reviewed bytes land where:

| Reviewed file | Installed path |
|---|---|
| `deploy/sn39/cathedral-mismatch-check` | `/usr/local/bin/cathedral-mismatch-check` (0755) |
| `deploy/sn39/cathedral-mismatch-alert.service` | `/etc/systemd/system/cathedral-mismatch-alert.service` (0644) |
| `deploy/sn39/cathedral-mismatch-alert.timer` | `/etc/systemd/system/cathedral-mismatch-alert.timer` (0644) |

The timer runs the check every 10 minutes.
Watch `systemctl status cathedral-mismatch-alert.service` (a failed unit is
the alert) and `journalctl -u cathedral-mismatch-alert` for the reason line.
A healthy run names the tick it saw and exits 0:

```
validator alive (last completed tick at 2026-08-05T18:26:03.228Z); no recent
mismatch; shadow audit not persistently failing
```

An unhealthy run exits 1 with one `ALERT:` line naming the condition and what
to do about it, for example:

```
ALERT: event journal has not grown since 2026-08-05T15:06:03.228Z, more than 3
tick intervals (75m) — the validator is stopped, wedged, or writing to a
different path. Check: systemctl status cathedral-validator-sn39
```

Verify the alert can actually see your journal after installing it — the one
failure this design cannot detect for you is a timer running as a user that
cannot read an owner-only `0600` journal. That now alerts rather than passing
silently, but only if you run it once and look:

```bash
sudo /usr/local/bin/cathedral-mismatch-check
```

## Chain-writing launch gate

Do not add `--broadcast` until all of the following are true:

- [ ] Cathedral has published a reviewed commit and a launch notice. There are
      no tags in this repository; `git rev-parse origin/main` names the commit.
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

## Upgrade and rollback

The quickstart installs an **editable** checkout (`pip install -e
'.[provenance]'`), so the running validator executes the files in that clone.
The first consequence is the one to internalize:

> [!WARNING]
> `git pull` in the checkout changes the code a running service will execute
> from its next import — there is no version pin and no restart barrier between
> the two. A tick that is mid-flight when the tree changes underneath it is not
> a state anything here reasons about. **Stop the service before you pull.**

Upgrading, from a stopped service:

```bash
cd /path/to/cathedral-validator
git fetch origin
git rev-parse HEAD > ~/cathedral-rollback-sha    # where you are now
git log --oneline HEAD..origin/main              # what you are about to run
git checkout --detach origin/main                # or a specific reviewed sha
.venv/bin/python -m pip install -e '.[provenance]'
```

`--detach` on purpose: it names the exact commit this host runs, works whether
you were on a branch or already pinned, and cannot be moved later by a stray
`git pull`.

Reinstall even when only `.py` files changed: an editable install picks those
up on its own, but entry points, dependency pins and package metadata do not
move until pip runs. Then repeat quickstart steps 1 and 2 before restarting the
service with `--broadcast`, and check
[`status`](#is-it-working-right-now-status) after the first tick.

Rolling the **software** back is the same shape:

```bash
git checkout --detach "$(cat ~/cathedral-rollback-sha)"
.venv/bin/python -m pip install -e '.[provenance]'
```

Rolling the **durable state** back is different, and it is forbidden: the state
file and runtime root carry the monotonic fences that make a replayed
submission impossible. Restoring either from a snapshot rewinds a fence that
the chain has not rewound — the validator prints this as the `caveat` line on
every start. Keep them across an upgrade or a rollback, untouched. If a
rollback is being attempted *because* of a refused or fenced write, that is
[the previous
section](#recovering-from-a-refused-or-fenced-write), not this one.

`my-validator.toml` is your file, not the repository's, so a fast-forward pull
leaves it alone. Re-diff it against
`config/validator-thin-sn39-relay.toml` after an upgrade: the shipped profile
carries the trust pins, and the validator refuses a broadcast whose config
differs from the release constants rather than silently honoring it.

### Rolling back a staged (side-by-side) install

Everything above describes the **editable checkout** the quickstart installs,
where the running code is the clone and rolling back is `git checkout --detach`.
A host built the other way — each version unpacked under its own
`/opt/cathedral-validator-staging-<version>` with its own venv, and a systemd
drop-in naming the one that runs — rolls back by repointing that drop-in
instead. `deploy/sn39/cathedral-sn39-rollback` is that sequence:

```bash
cathedral-sn39-rollback list             # staged versions, marking the running one
cathedral-sn39-rollback to <version> --dry-run
cathedral-sn39-rollback to <version>     # repoint, reload, restart
cathedral-sn39-rollback previous         # undo the last move it made
```

It refuses rather than guesses: a version that is not staged, one whose venv has
no interpreter, the version already running, anything that is not a plain
directory name, and — the one worth knowing about — a drop-in that already names
**two** versions, which is the hand-edit that leaves `ExecStart` on a new tree
while `WorkingDirectory` still points at the old one. It backs the drop-in up
before touching it and restores that backup if the rewrite does not come out
clean.

It does not install, fetch or build: a version it cannot already see staged is a
version it will not select, so a rollback can never be the thing that first
introduces a tree to the host.

The rule above still holds and the script obeys it — **it moves code and never
state**. There is no flag that makes it touch the state file, the runtime root or
the journal.

### Rotating a signing key

Treat a signing-key change as a new trust decision, not an upgrade:

1. stop the chain-writing service;
2. take the new pin bundle from the reviewed commit you are moving to, and
   verify the change through an independent channel — compare the pin against
   the live
   [JWKS](https://api.cathedral.computer/.well-known/cathedral-jwks.json), not
   against the checkout that carries it;
3. install as above;
4. preserve the rollback state deliberately (see the paragraph above);
5. repeat the synthetic-map and metagraph-backed dry runs; and
6. resume only after explicit operator authorization.

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

- [2026-07-24 SN39 Intel TDX CPU release record](docs/history/SN39_MAINNET_RELEASE_20260724.md)
- [Full-provenance verification](docs/PROVENANCE.md)
- [Score-class contract](docs/THIN_SCORE_CLASSES.md)
- [Threat model](docs/THIN_SUBNET_DESIGN.md)
- [Evidence record](docs/history/THIN_SUBNET_EVIDENCE.md)
- [Operator runbook for the experimental owner-independent path](docs/THIN_SUBNET_RUNBOOK.md)
  — a **different binary** (`cathedral-thin-validator`) with its own flags and
  its own state file. Nothing in it applies to `cathedral-validator serve`.
