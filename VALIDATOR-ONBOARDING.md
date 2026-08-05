# Review Cathedral Validator

This repository is the sole source for Cathedral Validator software and
operator releases. The default path is read-only. A broadcast needs a reviewed
immutable release and a candidate that passes every gate in the same cycle.

> [!IMPORTANT]
> **The one install-and-run path is [README's
> quickstart](README.md#quickstart).** This document adds only the review
> gates. Do not follow a second procedure from here.

## Local review

Run the quickstart through step 1 (`--offline --once`), then add the suite:

```bash
.venv/bin/python -m pytest -q tests/thin tests/boundary
```

The suite checks source; the quickstart's offline run prints a synthetic
dry-run vector. Neither connects to a wallet or writes to a chain.

`tests/thin` needs the shared cathedral-distill contract, so install with the
extras CI uses rather than the quickstart's `.[provenance]` alone:

```bash
.venv/bin/pip install -e ".[test,publisher,provenance,integration]"
```

## Production path

Use the immutable Linux release process in `VALIDATOR.md`. Before a write,
prove all of these from one cycle:

- one active writer
- a registered validator hotkey with a permit
- fresh admitted miner evidence
- a signed, nonempty vector
- the owner-controlled allocation and burn destination
- complete hotkey-to-UID mapping
- the same vector in dry-run and submission preflight
- durable rollback and attempt state

Do not turn a review command into a broadcast command by adding a flag. Record
the release, candidate, dry run, operator authorization, transaction, inclusion
block, events, and resulting weights.

See [`README.md`](README.md) for orientation and the canonical install-and-run
path, [`VALIDATOR.md`](VALIDATOR.md) for operation, [`REVIEW.md`](REVIEW.md)
for review gates, and [`BOUNDARY.md`](BOUNDARY.md) for ownership and trust
boundaries.
