# Reviewing Cathedral Validator

Review this repository as the canonical validator source. Do not compare or
sync validator behavior from another Cathedral repository.

Third-party validators run `main` directly: they clone it, install it, and run
it. Nothing stands between a merge and an operator, so `main` is the shipped
artifact and this review is the last gate in front of it.

## Required review order

1. Confirm the branch is based on current `cathedral-validator` main.
2. Inspect the complete diff and list every changed trust boundary.
3. Confirm Compute and Distill pins are immutable and current for the change.
4. Confirm the Compute dependency does not export `cathedral-validator`.
5. Run the thin, boundary, and validator-facing publisher suites.
6. Run `git diff --check`, ruff, and compile every tracked Python file.
7. Run offline verification, then one metagraph-backed dry cycle.
8. Compare the exact dry-run UID vector with the intended signed candidate.
9. Permit broadcast only after every required gate passes.

### Steps 5 and 6: what CI gates on

```bash
python -m pytest -q tests/thin tests/boundary
python -m pytest -q \
  scaffold/publisher/tests/test_validator_thin_validated_supply.py \
  scaffold/publisher/tests/test_validator_lifecycle.py
ruff check cathedral_thin tests/thin
ruff format --check cathedral_thin tests/thin
git diff --check
git ls-files '*.py' | xargs python -m py_compile
```

The integration and release-install tests are files inside `tests/thin`, not
separate suites; the command above runs them. They only run *for real* with the
`integration` extra installed. Without it, 215 of 830 tests (26%) do not run:
nine modules `importorskip` the shared cathedral-distill contract and skip
quietly, and `test_cybergym_prelaunch_e2e.py` imports it at module scope, so the
run ends in a collection error and a non-zero exit rather than a quiet green.
Keep that loud import as it is — it is the only thing that makes the shortfall
visible. A skipped contract is a failure, not a pass. Install the extras CI
uses, listed under "Local review" in
[`VALIDATOR-ONBOARDING.md`](VALIDATOR-ONBOARDING.md); the operator install
itself is README's quickstart and is not restated anywhere.

The two publisher files above are required because they cover the validator's
own weight mapping, UID-replacement safety, the tick lifecycle, the durable
attempt fence, and the chain weight-cooldown stand-down. The rest of
`scaffold/publisher/tests` is advisory legacy fixtures.

### Step 4: the console-script owner

An operator's environment holds this project *and* the pinned Cathedral Compute
distribution, so the installed `cathedral-validator` entry point must resolve to
`scaffold.cli:main` there. If the Compute distribution also declares
`cathedral-validator`, the operator's command silently becomes another program.
A competing owner is a blocker.

### Steps 7 and 8: the dry cycle

These are steps 1 and 2 of README's quickstart. Read the event journal rather
than the exit status — README explains which non-zero outcome is the expected
relay result and which one means the audit never ran. The vector compared in
step 8 must be byte-identical to the candidate that would be submitted; an
unchanged candidate between dry run and submission is a broadcast gate, not a
formality.

## Review findings

Report each finding with a file and line number. Separate:

- implemented
- locally tested
- merged
- installed on the Linux host
- live evidence proven
- dry-run proven
- broadcast and on-chain inclusion proven

Do not convert `NOT_PROVEN` into `PASS`. Do not use a test fixture as evidence
of a live miner, validator, hardware quote, or chain write.

## Dependency review

The provenance extra installs a pinned Cathedral Compute archive. Review the
dependency commit and archive digest together with
`requirements/sn39-reproduction.lock` and
`scripts/build_sn39_release_manifest.py`. The pin is asserted at every one of
those sites plus the shipped configs and the validator's own constants, so a
half-moved pin fails the boundary suite rather than reaching an operator.

The integration extra pins Cathedral Distill. Review the imported contract
modules and confirm replay, receipt, lane, and composition behavior before
moving the pin.

## Broadcast review

Broadcast is blocked unless all of the following are proven in the same cycle:

- one active writer
- registered validator hotkey and permit
- fresh, signed, nonempty candidate
- admitted current miner evidence
- intended owner-controlled allocation and burn
- complete hotkey to UID mapping
- unchanged candidate between dry-run and submission
- durable rollback and attempt state
- explicit operator authorization

Retain the extrinsic hash, inclusion block, events, and resulting on-chain
weights. Without those records, a broadcast is not proven.

## Hardened install path only

The following applies **only** to the pinned systemd install described under
"Supported systemd install (relay)" in [README.md](README.md). It does not
apply to a validator running `main`, and its absence is not a review finding
against one.

Build the locked environment on Linux before approving that install. The
release source must be pristine and immutable, and the Linux manifest builder
must validate the exact source commit, locked environment, installed configs,
launcher, services, verifier, and interpreter.

In that layout the production launcher invokes `scaffold.cli` from the release
directory instead of installing the validator project into the locked
dependency environment. The console-script rule in step 4 still holds: the
pinned Cathedral Compute distribution must not declare the
`cathedral-validator` command in either layout.
