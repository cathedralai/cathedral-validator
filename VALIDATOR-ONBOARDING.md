# Review Cathedral Validator

This repository is the sole source for Cathedral Validator software and
operator releases. The default path is read-only. A broadcast needs a reviewed
immutable release and a candidate that passes every gate in the same cycle.

## Local review

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3 -m venv .venv
.venv/bin/pip install -e ".[test,provenance,integration]"
.venv/bin/python -m pytest -q tests/thin tests/boundary
.venv/bin/cathedral-validator serve \
  --config config/validator.toml \
  --mode thin \
  --offline \
  --once
```

This checks source and prints a synthetic dry-run vector. It does not connect
to a wallet or write to a chain.

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

See `README.md` for orientation, `VALIDATOR.md` for operation, `REVIEW.md` for
review gates, and `BOUNDARY.md` for ownership and trust boundaries.
