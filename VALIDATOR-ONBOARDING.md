# Review Cathedral Validator

This repository is the sole source for Cathedral Validator software and
operator releases. The default path is read-only. A broadcast needs a reviewed
commit and a candidate that passes every gate in the same cycle.

> [!IMPORTANT]
> **The one install-and-run path is [README's
> quickstart](README.md#quickstart).** This document adds only what a reviewer
> needs on top of it. Do not follow a second procedure from here.

## Local review

Run the quickstart through step 1 (`--offline --once`), then install the extras
CI uses — the quickstart's `.[provenance]` alone is not enough for a review —
and run the suite:

```bash
.venv/bin/pip install -e ".[test,publisher,provenance,integration]"
.venv/bin/python -m pytest -q tests/thin tests/boundary
```

`tests/thin` needs the shared cathedral-distill contract that the `integration`
extra brings in. Without it 215 of 830 tests (26%) do not run. Nine modules
`importorskip` the contract and skip quietly; `test_cybergym_prelaunch_e2e.py`
imports it at module scope, so the run ends in a collection error and a
non-zero exit rather than a quiet green — that loud import is the only thing
that makes the shortfall visible, so leave it as it is.

The suite checks source; the quickstart's offline run prints a synthetic
dry-run vector. Neither connects to a wallet or writes to a chain.

## Before a broadcast

The gates that must be proven in one cycle are listed once, in
[`REVIEW.md`](REVIEW.md#broadcast-review). The operator-side checklist that must
be true before anyone adds `--broadcast` is in
[`VALIDATOR.md`](VALIDATOR.md#chain-writing-launch-gate). Do not turn a review
command into a broadcast command by adding a flag, and record the commit,
candidate, dry run, operator authorization, transaction, inclusion block,
events, and resulting weights.

See [`README.md`](README.md) for orientation and the canonical install-and-run
path, [`VALIDATOR.md`](VALIDATOR.md) for operation, upgrade and recovery,
[`REVIEW.md`](REVIEW.md) for the review order, and [`BOUNDARY.md`](BOUNDARY.md)
for ownership and trust boundaries.
