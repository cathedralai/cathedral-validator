# cathedral-validator

> **Status: derived extraction. Not the authoritative source, not a deploy
> source.**
>
> This repository is extracted from
> [`cathedralai/cathedral`](https://github.com/cathedralai/cathedral) at commit
> **`7657adcae82644a3af4b211ed2396749bd057fa2`**. `MANIFEST.origin.tsv` records
> that SHA and CI clones upstream at it, so the two cannot drift apart silently.
> If they ever disagree, the manifest is right; it is the one a machine checks.
>
> - **`cathedralai/cathedral` remains authoritative.** The reproduction locks,
>   release manifests, and public reproduction paths all pin upstream paths, and
>   they still resolve there.
> - **The running SN39 validator is built from upstream, not from here.** No
>   cutover has happened. Do not deploy from this repository, and do not treat
>   anything here as a production runbook.
> - **Sync is one-way**, upstream to here. No change should be made here first.
>
> Treat this as an extraction exercise that proves the validator's boundary is
> real and separable. [`BOUNDARY.md`](BOUNDARY.md) records exactly what was
> taken, what was left, what deliberately diverges, and why.

## Who this is for

Reviewers and auditors who want to read the validator's decision path in
isolation, without the mechanism and game lanes around it. If you want to
**operate** a validator, use
[`VALIDATOR.md` upstream](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md)
instead.

## What the validator decides, and what it cannot

For each decision the validator reads the configured feed and evidence, verifies
signature, scope, policy, freshness, rollback state, and the burn contract,
resolves hotkeys against the current metagraph, runs the configured provenance
or integration checks, and then either records one UID-aligned vector or refuses
the input.

Five boundaries are worth stating explicitly, because they are what the
extraction is meant to make legible:

- **Verification.** Every stage reports `PASS`, `FAIL`, `NOT_PROVEN`, or `INFO`.
  A failed gate on the active submission path leaves the relevant weight at zero
  or stops the decision. Shadow provenance results are observational and do not
  veto an otherwise valid thin vector. `NOT_PROVEN` is not success.
- **Composition.** The validator derives work units from the committed task, not
  from any score a miner or worker reports. Class allocation is a policy input
  the validator verifies, not a field a miner controls.
- **Burn.** The burn contract is signed and verified alongside the vector. A
  vector with zero positive miners is a valid outcome; eligible mass routes to
  the configured burn destination rather than preserving stale credit.
- **Allocation.** The publisher composes verified mechanism output into a
  per-hotkey vector and signs it. The default thin validator verifies that vector
  rather than independently replaying all underlying work. Full-provenance
  authority mode recomputes from the controlled evidence package.
- **Chain authority.** The validator wallet alone authorizes a weight
  transaction. A publisher, feed, receipt, miner, or CLI cannot bypass the
  validator's local policy or sign with its wallet.

The validator host does not need Intel TDX for the signed-feed path. TDX belongs
to the worker being measured. Full raw-evidence replay additionally needs a
Linux x86-64 host, the pinned verifier, and the controlled evidence package
described in [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

## What is here

| | |
|---|---|
| `scaffold/validator_thin.py`, `scaffold/cli.py` | Thin validator and its CLI |
| `scaffold/provenance_audit.py` | Independent provenance audit path |
| `scaffold/publisher/` | Publisher service and its test suite |
| `cathedral_thin/` | Thin subnet protocol, scoring, receipts, policy |
| `config/provenance/` | Pinned signing-key bundles |
| `deploy/sn39/`, `deploy/thin/` | systemd units, carried for review, not a deploy source |

`VALIDATOR.md`, `docs/PROVENANCE.md`, `docs/THIN_SUBNET_RUNBOOK.md`, and
`docs/THIN_SUBNET_DESIGN.md` are carried from upstream and describe the evidence
chain, operation, and design.

## What is not here

`game/` (the SAT lane), `hunt-board/`, the arena tooling, the lane verify
scripts, and the lane planning docs. The full list, with a reason for each entry,
is in [`BOUNDARY.md`](BOUNDARY.md).

The one subtlety worth knowing up front: `scaffold/publisher/app.py` contains two
`from game.arena import ...` statements. Both are function-local and sit behind a
default-off feature flag, so they never execute on any validator path. The file
is carried byte-identical and `game/` is not shipped.
`tests/boundary/test_no_game_dependency.py` proves this rather than asserting it.

## Read it locally

Python 3.11 or 3.12.

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[test,publisher,integration]"
python -m pytest tests/thin tests/boundary
```

**Include `integration`.** Without it, nine `tests/thin` modules cannot import
the shared `cathedral-distill` contract and skip at import time, taking roughly
40% of the thin suite with them. They are whole-module skips, one line each, so
the count looks unremarkable while most of the lane never ran. Run with `-rs` and
each skip names the extra to install. The extra is public and installs
unauthenticated. CI installs it on the gating job too, so those tests gate rather
than quietly skipping
([#19](https://github.com/cathedralai/cathedral-validator/issues/19)).

The `provenance` extra pulls the commit-pinned `cathedral-compute` package that
the full-provenance audit path needs:

```sh
python -m pip install -e ".[provenance]"
```

Current CI gates the thin and boundary suites. The publisher suite remains
advisory and carries known extraction-related failures. Read
[`BOUNDARY.md`](BOUNDARY.md) for the current baseline and re-verification method,
and inspect skip summaries rather than trusting a passing total alone.

## Entry points

| Command | Does |
|---|---|
| `cathedral-validator` | Serve, audit, and (with `--broadcast`) attempt to set weights |
| `cathedral-validator-integration-preview` | Non-writing Compute and Distill preview (needs `.[integration]`) |
| `cathedral-candidate-snapshot` | Snapshot registration candidates |
| `cathedral-thin-validator` | Thin path validator |
| `cathedral-thin-preflight` | Pre-run environment checks |
| `cathedral-thin-e2e` | End-to-end self test |
| `cathedral-thin-score-report` | Score-class report tooling |
| `cathedral-verified-policy` | Signed policy registry tooling |

`cathedral-validator serve` is non-writing by default; only an explicit
`--broadcast` permits a chain-write attempt. Do not broadcast from this
repository. Operate from upstream, at a reviewed immutable release.

## Re-syncing from upstream

```sh
git clone https://github.com/cathedralai/cathedral.git /tmp/cathedral-upstream
./tools/sync-from-upstream.sh /tmp/cathedral-upstream . tools/upstream-manifest.txt
```

Read the re-sync section of [`BOUNDARY.md`](BOUNDARY.md) first. `pyproject.toml`
is deliberately outside the manifest and has to be reconciled by hand.

## Security

- Keep wallet seeds, private keys, bearer tokens, cloud credentials, internal
  addresses, and controlled evidence out of Git, issues, and public logs.
- Treat `PASS`, `FAIL`, and `NOT_PROVEN` as different outcomes.
- Do not infer current eligibility from a past receipt, a historical chain row,
  or a local test.

## License

This repository does not publish a license file. Do not assume redistribution
rights. Contact the maintainers before reuse beyond rights granted by applicable
law.
