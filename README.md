# Cathedral Validator

Cathedral Validator is the canonical operator repository for Cathedral SN39.
It verifies signed work evidence, resolves eligible miner hotkeys to current
UIDs, applies the owner-controlled allocation and burn policy, and produces the
only candidate weight vector an operator should consider for broadcast.

Do not run a validator from another Cathedral repository. This repository owns
the validator command, release bundle, systemd units, runtime policy, dry-run
path, and broadcast gates.

## What it does

On every cycle the validator:

1. fetches the signed Cathedral weight candidate;
2. verifies its signature, audience, freshness, rollback fence, and policy;
3. checks the configured Compute and Distill evidence boundary;
4. resolves hotkeys against the current SN39 metagraph;
5. applies the fixed burn contract and owner-controlled allocations;
6. prints and records the exact UID vector; and
7. stops at dry-run unless the operator explicitly enables broadcast.

A registered miner, an online worker, or a self-reported score does not earn
weight. Evidence must pass the active validator policy.

## Install for review and dry-run

Use Python 3.11 or 3.12.

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test,provenance,integration]'
```

The installed command belongs to this repository:

```bash
cathedral-validator --help
```

For chain use, install an immutable reviewed release. Do not operate from a
moving branch or editable checkout. The full installation and release process
is in [VALIDATOR.md](VALIDATOR.md).

## Run safely

Copy the sample before editing it:

```bash
cp config/validator.toml my-validator.toml
```

Run an offline verification first. It opens no chain connection:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral-validator" \
  --offline \
  --once
```

Then run a metagraph-backed dry cycle. It reads chain state but does not write:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral-validator" \
  --dry-run \
  --once
```

Do not add `--broadcast` unless the dry-run candidate is fresh, nonempty,
policy-correct, mapped to the intended UIDs, and identical to the reviewed
candidate. Broadcast also requires the immutable Linux release, the registered
validator hotkey, one-writer protection, and explicit operator authorization.

## Evidence modes

| Mode | Weight authority | Host requirements |
|---|---|---|
| `shadow` | Signed thin vector | Python runtime and chain access for dry-run |
| `authority` | Independent replay from controlled evidence | Linux x86-64, pinned verifier, controlled evidence tree |
| `off` | Signed thin vector | Independent provenance audit disabled |

The validator host does not need Intel TDX for the signed-vector path. Compute
workers need TDX when their policy requires TDX evidence. Authority replay needs
the pinned Linux verifier and the controlled evidence package.

## Operator documents

- [Validator runbook](VALIDATOR.md)
- [Provenance contract](docs/PROVENANCE.md)
- [Thin validator operations](docs/THIN_SUBNET_RUNBOOK.md)
- [Design and trust boundaries](docs/THIN_SUBNET_DESIGN.md)
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
