# cathedral-validator

> **Status: derived copy, not a source of truth.**
>
> This repository is extracted from
> [`cathedralai/cathedral`](https://github.com/cathedralai/cathedral) at commit
> **`7657adcae82644a3af4b211ed2396749bd057fa2`**.
>
> `MANIFEST.origin.tsv` records the same SHA and CI clones upstream at it, so the
> two cannot drift apart silently. If they ever disagree, the manifest is right —
> it is the one a machine checks.
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
python -m pip install -e ".[test,publisher,integration]"
```

**Include `integration`.** Without it, nine `tests/thin` modules cannot import the
shared `cathedral-distill` contract and skip at import time, so `pytest tests/thin`
reports **241 passed, 9 skipped** instead of **409 passed, 4 skipped** — 168 tests
that never ran. They are whole-module skips, one line each, so the count looks
unremarkable while roughly 40% of the thin suite is missing. The extra is public
and installs unauthenticated.

The `provenance` extra pulls the commit-pinned `cathedral-compute` package that the
full-provenance audit path needs:

```sh
python -m pip install -e ".[provenance]"
```

> This extra used to fail to install ([#16](https://github.com/cathedralai/cathedral-validator/issues/16), fixed
> in [#22](https://github.com/cathedralai/cathedral-validator/pull/22)). Its pin was a
> GitHub auto-generated tarball with a sha256, and those archives embed the repository
> name as their top-level directory — so renaming `cathedralconfidential` to
> `cathedral-compute` changed the bytes and invalidated the digest while nothing inside
> the repository changed. It surfaced as a hash mismatch, which reads like tampering
> rather than like a moved URL, and it broke asymmetrically: `pip` refused, `uv`
> installed it anyway. It is pinned by commit SHA now, which a rename cannot invalidate.

## Test

```sh
pytest tests/thin        # thin validator — 409 passed, 4 skipped with [integration]
pytest tests/boundary    # the SAT lane stays out, the derived-from SHA agrees — 12 passed
pytest scaffold/publisher/tests
```

If `tests/thin` reports **241 passed, 9 skipped**, the `integration` extra is
missing and the integration lane did not run. See Install above. Run with `-rs`
and each of the nine skips says so and names the extra to install.

CI installs `integration` on the gating job too, so those 168 tests gate rather
than quietly skipping ([#19](https://github.com/cathedralai/cathedral-validator/issues/19)).

The publisher suite carries pre-existing failures. They are not caused by the
extraction, and — despite what this file said for a long time — **none of them
needs PostgreSQL or outbound network.** A run produces *zero* psycopg2 or
connection errors.

What they actually are depends only on which extras you installed:

| Install | Result | Cause |
|---|---|---|
| `.[test,publisher,provenance]` | **26 failed**, 1366 passed, 0 skipped | all 26 the render divergence |
| `.[test,publisher,integration]` | **21 failed**, 1349 passed, 22 skipped | 20 render divergence + 1 needing `provenance` |
| upstream, same machine | **1393 passed, 0 failed** | — |

The render divergence: `scaffold/render.py` is a local addition, and upstream's
tests assert the plain-text journal (`FEED fetch source=...`) while this repo
emits the rendered one. It is confined to three files —
`test_validator_two_mode.py`, `test_validator_thin_validated_supply.py`,
`test_validator_lifecycle.py`. The twenty-first is
`test_snapshot_candidates.py`, which raises `ModuleNotFoundError: No module
named 'cathedral'` without the `provenance` extra and passes with it.

**So a failure outside those four files is new.** Two things have proved that rule
already: a forged-token test that only forged ~94% of the time (`cathedral#424`),
and a cross-*suite* order dependency — `test_client_ip_mode.py` used
`asyncio.get_event_loop()`, which `asyncio.run()` unsets, so it passed alone and
failed after `tests/thin` (`cathedral#425`). Running all three suites in one
process now gives the **same failure set** as the publisher suite alone. That rule earned its keep
immediately: the first CI run after it was written reported 22, and the extra one
was a real defect — a test whose forgery only forged ~94% of the time, because it
edited the last base64 character of an HMAC whose final character carries just 4
significant bits. Fixed upstream in `cathedral#424`; see `BOUNDARY.md`.

> **How the environment story died.** It never fitted: a missing database does
> not care how a run is split across processes, yet roughly half the failures
> vanished when each file ran in its own process
> ([#17](https://github.com/cathedralai/cathedral-validator/issues/17),
> [#20](https://github.com/cathedralai/cathedral-validator/issues/20)). The cause
> was one process-wide rate limiter keyed on client IP — the same `testclient`
> for every request — so ~1300 tests shared a single 120-request, 60-second
> budget against a suite that runs in about 60 seconds. The count moved with
> *machine speed*, which is why three machines measured the same bug as 69, 64
> and 62.
>
> Five separate causes have since come out of that number: the rate limiter
> (`cathedral#420`), a test coupling the relay profile to the operator's
> `provenance` (`#422`), a canary that could not import its own dependencies
> inside a virtualenv at all (`#423`), three tests predating the thin-admit split
> (`#423`), and one pin that could not install (#16 / #22). `BOUNDARY.md` has the
> detail and the re-verification method.

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
