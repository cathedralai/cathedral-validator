# cathedral-validator

> **Status: derived copy, not a source of truth.**
>
> This repository is extracted from
> [`cathedralai/cathedral`](https://github.com/cathedralai/cathedral) at commit
> **`fd02392dc969bbea09e3107febb64f1f5f748391`**.
>
> - **Sync is one-way**, upstream to here. Nothing in this repo feeds back into
>   `cathedralai/cathedral`, and no change should be made here first.
> - **This is not yet the authoritative validator source.** `cathedralai/cathedral`
>   remains authoritative. The reproduction locks, release manifests, and public
>   reproduction paths all pin upstream paths, and they still resolve there.
> - **Do not deploy from this repo** without an explicit cutover decision. The
>   running SN39 validator is built from upstream, not from here.
>
> Treat this as an extraction exercise that proves the validator's boundary is
> real and separable. `BOUNDARY.md` records exactly what was taken, what was
> left, and why.

## What is here

The Cathedral SN39 validator: the code that decides what goes on chain and
verifies what does.

| | |
|---|---|
| `scaffold/validator_thin.py`, `scaffold/cli.py` | Thin validator and its CLI |
| `scaffold/provenance_audit.py` | Independent provenance audit path |
| `scaffold/publisher/` | Publisher service and its test suite |
| `cathedral_thin/` | Thin subnet protocol, scoring, receipts, policy |
| `config/provenance/` | Pinned signing-key bundles |
| `deploy/sn39/`, `deploy/thin/` | systemd units |

`VALIDATOR.md` is the operator guide. `docs/PROVENANCE.md`,
`docs/THIN_SUBNET_RUNBOOK.md`, and `docs/THIN_SUBNET_DESIGN.md` cover the
evidence chain, day-to-day operation, and the design.

## What is not here

`game/` (the SAT lane), `hunt-board/`, the arena tooling, the lane verify
scripts, and the lane planning docs. The full list, with a reason for each entry,
is in `BOUNDARY.md`.

The one subtlety worth knowing up front: `scaffold/publisher/app.py` contains two
`from game.arena import ...` statements. Both are function-local and sit behind a
default-off feature flag, so they never execute on any validator path. The file
is carried byte-identical and `game/` is not shipped.
`tests/boundary/test_no_game_dependency.py` proves this rather than asserting it.

## Install

Python 3.11 or 3.12.

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[test,publisher]"
```

The `provenance` extra pulls the sha256-locked `cathedralconfidential` package
that the full-provenance audit path needs:

```sh
python -m pip install -e ".[provenance]"
```

## Test

```sh
pytest tests/thin        # thin validator
pytest tests/boundary    # the SAT lane stays out
pytest scaffold/publisher/tests
```

The publisher suite carries pre-existing failures in a plain environment with no
PostgreSQL and no outbound network. They are inherited from upstream, not
introduced by the extraction, and the same tests fail identically in an upstream
checkout. `BOUNDARY.md` describes how to re-verify that after a sync.

## Entry points

| Command | Does |
|---|---|
| `cathedral-validator` | Serve, audit, and (with `--broadcast`) set weights |
| `cathedral-candidate-snapshot` | Snapshot registration candidates |
| `cathedral-thin-validator` | Thin path validator |
| `cathedral-thin-preflight` | Pre-run environment checks |
| `cathedral-thin-e2e` | End-to-end self test |
| `cathedral-thin-score-report` | Score-class report tooling |
| `cathedral-verified-policy` | Signed policy registry tooling |

`cathedral-validator serve` is non-writing by default. Only an explicit
`--broadcast` permits a chain-write attempt. See `VALIDATOR.md` before running
anything against Finney.

## Re-syncing from upstream

```sh
git clone https://github.com/cathedralai/cathedral.git /tmp/cathedral-upstream
./tools/sync-from-upstream.sh /tmp/cathedral-upstream . tools/upstream-manifest.txt
```

Read the re-sync section of `BOUNDARY.md` first. `pyproject.toml` is deliberately
outside the manifest and has to be reconciled by hand.
