# Reviewing Cathedral Validator

Review this repository as the canonical validator source. Do not compare or
sync validator behavior from another Cathedral repository.

## Required review order

1. Confirm the branch is based on current `cathedral-validator` main.
2. Inspect the complete diff and list every changed trust boundary.
3. Confirm Compute and Distill pins are immutable and current for the change.
4. Confirm the Compute dependency does not export `cathedral-validator`.
5. Run thin, boundary, integration, release, and affected publisher tests.
6. Run `git diff --check` and compile every tracked Python file.
7. Build the locked environment on Linux before approving a release.
8. Run offline verification, then one metagraph-backed dry cycle.
9. Compare the exact dry-run UID vector with the intended signed candidate.
10. Permit broadcast only after every required gate passes.

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
`scripts/build_sn39_release_manifest.py`.

The integration extra pins Cathedral Distill. Review the imported contract
modules and confirm replay, receipt, lane, and composition behavior before
moving the pin.

## Release review

The release source must be pristine and immutable. The Linux manifest builder
must validate the exact source commit, locked environment, installed configs,
launcher, services, verifier, and interpreter.

In a combined developer environment, the installed `cathedral-validator`
entry point must resolve to `scaffold.cli:main`. The immutable production
launcher invokes `scaffold.cli` from the release directory instead of
installing the validator project into the locked dependency environment. In
both layouts, the pinned Cathedral Compute distribution must not declare the
`cathedral-validator` command. Any competing owner is a release blocker.

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
