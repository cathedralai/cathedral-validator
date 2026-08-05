# Cathedral Validator

Cathedral Validator is the canonical operator repository for Cathedral SN39.
It fetches the signed weight vector, enforces the weight-policy signature,
freshness, the rollback fence, UID-replacement safety, and the burn pin, and
broadcasts exactly what it verified — while a full-provenance verifier
re-checks the published evidence chain concurrently and never delays the
write. One mode, one command.

Do not run a validator from another Cathedral repository. This repository owns
the validator command, release bundle, systemd units, runtime policy, dry-run
path, and broadcast gates.

## Quickstart

**This section is the canonical operator path.** Follow it top to bottom and
nothing else — [VALIDATOR.md](VALIDATOR.md) and
[VALIDATOR-ONBOARDING.md](VALIDATOR-ONBOARDING.md) both start by pointing back
here, and pick up where this leaves off.

Everything below runs as an ordinary user. No root, no systemd, no chain
write. Use Python 3.11 or 3.12 on Linux x86-64.

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[provenance]'
cp config/validator-thin-sn39-relay.toml my-validator.toml
```

`config/validator-thin-sn39-relay.toml` is the **third-party relay profile**:
it follows Cathedral's remote signed feed, carries the trust pins verbatim,
and is the profile a validator that is not Cathedral should run. Copy it to
the repository root as shown — the copy's relative provenance key pins resolve
against the directory it sits in.

Edit `my-validator.toml` and set your wallet under `[network]`:
`wallet_name` and `validator_hotkey` are your local bittensor wallet labels.
Change nothing else in the file; the rest is the pinned trust profile and the
validator re-checks it before any broadcast.

### 1. Verify offline

No chain connection, no wallet, no directory to create beforehand:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --state-file "$HOME/.cathedral/thin-state.json" \
  --jsonl "$HOME/.cathedral/validator-events.jsonl" \
  --offline --once
```

The three path flags are the whole reason a preview needs them: the shipped
profile pins the **service-owned** runtime root, state file, and journal under
`/var/lib/cathedral-validator` and `/var/log/cathedral-validator`, which the
release install provisions as root and an ordinary user cannot write. The
flags redirect all three into one owner-only directory the validator creates
for you at mode 0700. A production install keeps the shipped paths and does
not pass these flags.

You should see the signed vector fetched, its signature, freshness and
rollback fence pass, a synthetic UID map, and `dry run, nothing written`.

**Expect exit status 1, and read the journal rather than the status.** A
`--once` run reports success only if the concurrent shadow audit *also*
reached the configured minimum assurance in that same run. A relay has no
controlled raw-evidence package, so its audit is `receipts_only` and cannot,
and the run ends with `PROVENANCE_AUDIT_NOT_PROVEN` and
`PROVENANCE_HEALTH_GATE_FAILED` in `$HOME/.cathedral/validator-events.jsonl`.
That is the expected relay outcome, not a misconfiguration — what it tells you
is that the audit ran. A `FileNotFoundError` naming a key bundle, or no
`PROVENANCE_*` record at all, would mean it did not. The exit status is
computed only on the `--once` path; the continuous service does not gate on
it.

### 2. One metagraph-backed dry cycle

Same command with `--dry-run` instead of `--offline`. This one reads live
chain state and writes nothing:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --state-file "$HOME/.cathedral/thin-state.json" \
  --jsonl "$HOME/.cathedral/validator-events.jsonl" \
  --dry-run --once
```

This step needs a local bittensor wallet matching the labels you set, and that
hotkey must be registered on SN39. If it is not, the tick fails closed with
`validator hotkey is not registered on this subnet` — which still tells you
the feed, the pins, the metagraph connection, and the UID mapping all worked.
Register the hotkey and run it again.

### 3. Stop here

`--broadcast` is a mainnet write and is **not** the next step. Until Cathedral
publishes a supported tag, immutable pin bundle, and launch notice, `--offline
--once` and `--dry-run --once` are the supported modes. The full checklist that
must be true before anyone adds `--broadcast` is in
[VALIDATOR.md](VALIDATOR.md#chain-writing-launch-gate).

> [!WARNING]
> Do not set `CATHEDRAL_*` environment variables to configure paths.
> Environment beats the config file, so a leftover
> `export CATHEDRAL_VALIDATOR_STATE=...` in a shell profile silently replaces
> the pinned state file and every later broadcast fails with `differs from the
> immutable trust profile: state_file`, naming no cause. Use the flags above
> for a preview and the shipped config for a service.

A validator that will broadcast must start from a **clean journal**: never
hand-edit live submission state. To migrate a host that ran an older release,
archive the previous state file and start fresh
(`deploy/publisher/init-clean-journal.sh` provisions a clean runtime root —
see `deploy/publisher/README.md`).

### The two `[launch]` settings a relay depends on

SN39's launch was a one-shot, subnet-level event. A relay cannot perform one,
so an unconditional per-validator launch gate would lock every operator except
Cathedral off the subnet. Two settings in the relay profile handle that, and
they are not interchangeable:

| Setting | Who it is for | What happens without it |
|---|---|---|
| `require_completed_launch_for_broadcast = false` | Every third-party relay. | Defaults to `true`, so broadcast is refused pending a completed launch this validator can never have. |
| `beta_skip_launch_ceremony = true` | A runtime that **does** owe a launch: `provenance = "authority"`, or a host holding the controlled launch material at the release-pinned paths. | The line above is ignored for such a runtime and the ceremony is still required. |

For a pure relay the second setting changes nothing — the obligation it waives
is one the relay does not have. The shipped profile sets it anyway so the
profile stays runnable on a host that once held launch material.

The waiver is narrow. It clears the one-shot ceremony and the recurring-write
authorization derived from it — process controls that make a single mainnet
launch auditable. Every gate that keeps a submission *correct* still runs on
every tick and is not reachable from either setting: feed signature and key
pin, freshness and expiry, the monotonic rollback fence, the
`validated_supply` contract check, burn destination and floor, UID-replacement
safety, and the single-writer guard.

## What it does

On every cycle the validator:

1. fetches the signed weight vector from the publisher feed;
2. enforces the weight-policy signature, freshness, the monotonic
   policy-version fence, and the pinned policy contract;
3. resolves eligible hotkeys against the current SN39 metagraph and refuses
   any UID whose mapping cannot be proven stable;
4. enforces the pinned burn destination and floor;
5. prints and records the exact UID vector it will submit;
6. submits before chain finality advances — the concurrent full-provenance
   audit (TDX attestation and signed score reports re-checked against the
   published evidence chain) runs in the background and never blocks the
   write; its verdicts land in the event journal as `PROVENANCE_AUDIT_*`;
7. stops at dry-run unless the operator explicitly enables broadcast.

If the signed feed is unreachable there is nothing to verify, so there is
nothing to submit: the validator idles and retries rather than inventing a
vector. Alert on `PROVENANCE_VECTOR_MISMATCH` in the event stream — it means
the audit disagreed with a vector that was already accepted for submission;
the write is not blocked, so the alert is the response path.

Do not alert on `PROVENANCE_VECTOR_STALE_EPOCH`. The publisher signs and
caches a vector for up to a minute while the evidence index flips to the next
epoch, so a consumer can hold last epoch's vector beside this epoch's
evidence. When that happens the audit re-verifies the vector IN FULL against
the epoch it names — that epoch's signed manifest, its report body digest,
and its recomputed shares — and reports this event instead. A vector that
cannot be re-verified that way is never reclassified: it stays
`PROVENANCE_VECTOR_MISMATCH`.

## Self-composing (advanced)

The profile above follows the remote Cathedral publisher feed. A self-composing
validator runs the publisher role on the same host and follows its own local
feed instead: use `config/validator-selfcompose-sn39.toml` (its `[publisher]`
url points at the local `cathedral-publisher.service`) and the units in
`deploy/publisher/`. Everything else — verification, fences, broadcast gates —
is identical.

For a pinned production install (immutable reviewed release, systemd, single
writer), see [VALIDATOR.md](VALIDATOR.md) and `deploy/sn39/`.

## How it verifies

The write path enforces, on every cycle: the ed25519 weight-policy signature
over the canonical vector bytes; vector freshness and network/netuid identity;
the monotonic policy-version fence (no rollback); UID-replacement safety for
every rewarded hotkey; and the pinned burn destination. A vector failing any
check is refused — the validator fails closed and writes nothing.

The full-provenance verifier runs concurrently in the background and re-checks
the published evidence chain (TDX attestation, signed score reports, signed
evidence index) against what was submitted. It labels each epoch `PASS`,
`FAIL`, or `NOT_PROVEN` in the event journal without delaying the write.

Compute workers need Intel TDX when their policy requires TDX evidence; the
validator host itself does not.

## Operator documents

The quickstart above is the one path to a running preview. These pick up from
it; none of them restates it.

- [Validator runbook](VALIDATOR.md) — what each gate proves, how to read the
  event journal, the checklist that must be true before `--broadcast`, and key
  rotation.
- [Review gates](VALIDATOR-ONBOARDING.md) — what a reviewer must prove from one
  cycle before a write.
- [Provenance contract](docs/PROVENANCE.md) — every pin the shadow audit uses.
- [CyberGym pre-launch E2E testing](docs/CYBERGYM_E2E_TESTING.md)
- [Miner error contract](docs/MINER_ERROR_CONTRACT.md)

## Repository boundary

This repository contains validator-owned code and release assets. Compute
worker software lives in
[`cathedral-compute`](https://github.com/cathedralai/cathedral-compute).
Distill receipt and lane contracts live in
[`cathedral-distill`](https://github.com/cathedralai/cathedral-distill).
The optional dependencies are pinned to immutable reviewed commits.

[BOUNDARY.md](BOUNDARY.md) records the ownership and security boundary. There
is no upstream validator sync. Changes to validator behavior start and finish
in this repository.

## Security

Keep wallet seeds, private keys, bearer tokens, cloud credentials, internal
addresses, and controlled evidence out of Git, issues, and public logs.

Treat `PASS`, `FAIL`, and `NOT_PROVEN` as different outcomes. A local test, a
past receipt, or a historical chain row does not prove current eligibility.
