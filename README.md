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

Use Python 3.11 or 3.12 on Linux x86-64.

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[provenance]'
cp config/validator-thin-sn39-relay.toml my-validator.toml
```

Edit `my-validator.toml` and set your wallet under `[network]`:
`wallet_name` and `validator_hotkey` are your local bittensor wallet labels.

Verify offline first — no chain connection is opened:

```bash
cathedral-validator serve --config my-validator.toml --offline --once
```

Then run one metagraph-backed dry cycle — reads chain state, writes nothing:

```bash
cathedral-validator serve --config my-validator.toml --dry-run --once
```

When the dry-run candidate is fresh, nonempty, policy-correct, and mapped to
the UIDs you expect, run the validator:

```bash
cathedral-validator serve --config my-validator.toml --broadcast
```

That is the whole loop. The validator must start from a **clean journal**:
never hand-edit live submission state. To migrate a host that ran an older
release, archive the previous state file and start fresh
(`deploy/publisher/init-clean-journal.sh` provisions a clean runtime root —
see `deploy/publisher/README.md`).

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

- [Validator runbook](VALIDATOR.md)
- [Provenance contract](docs/PROVENANCE.md)
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
