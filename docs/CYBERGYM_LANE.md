# CyberGym lane: what the code does, what is on

Generated from the 2026-08 audit of the shipped composer, not from the
design we wished we had shipped. If this page and a flag default disagree,
the flag is the product.

## Hard rule

**Do not set `CATHEDRAL_ALLOCATION_CONTRACT=v3` until cathedral-distill
refuses public-catalog `task_id`s (`arvo:<n>`, `oss-fuzz:<n>`).**

Those ids map 1:1 to public images (`n132/arvo:<n>-vul`). A miner who sees
the id can `docker run --rm --entrypoint cat n132/arvo:<id>-vul /tmp/poc`.
Admission today fingerprints disclosed *context*, not the catalog id
(distill #127 / #131). v3 is the only path that puts weight and money
through that hole. Leave v3 off until that refuse ships and is deployed.

Everything else in the audit is survivable. That flip is not.

## What the composer actually does

Pipeline, when someone turns the flags on:

1. Distill grades PoCs and HMAC-posts a score report.
2. Validator publisher authenticates the HMAC (this part works).
3. Only if the allocation contract is v3, the publisher puts those scores
   in a 30% CyberGym lane.
4. The validator never calls `verify_poc`. It does not re-run the crash.

The tournament is deterministic. Two validators with the same reports
agree. The HMAC path authenticates. v3 fails closed if the lane cannot
compose. Those bits are done. Do not one-shot-rewrite the validator to
"fix the docs."

## The four switches (all off in what we ship)

| Switch | Shipped default | On means |
|---|---|---|
| `require_policy` in `config/validator-selfcompose-sn39.toml` | `validated_supply_v1` | Validator accepts a v3 vector |
| `CATHEDRAL_ALLOCATION_CONTRACT` | unset / v2 | Publisher composes 70/30 |
| `CATHEDRAL_CYBERGYM_MECHANISM_ENABLED` | false | Lane is allowed to contribute |
| `CATHEDRAL_CYBERGYM_WEIGHT_FRACTION` | 0.0 | Lane share (v3 uses 0.30) |

v3 without a posting producer, or without the mechanism flags, fails the
**entire** weight vector. That is worse than CyberGym off. Do not flip
`require_policy` or `CATHEDRAL_ALLOCATION_CONTRACT` from a repo PR alone.

## What the CyberGym "DCAP" check actually is

`scaffold/publisher/cybergym_attestation.py` verifies Cathedral's Ed25519
signature on a `cathedral_customer_receipt_v1`. It does not verify an Intel
quote. `CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT` is off: failure is
recorded and the lane still pays.

Do not write "every validator independently DCAP-verifies CyberGym." That
sentence is how the pitch collapses in public.

Real Intel DCAP quote verification is its own piece of work. Build it
deliberately. Do not pretend this module is it.

## Distill issues that block a honest v3 (note, do not flip past them)

These live in cathedral-distill. This repo cannot close them.

- **Public catalog `task_id` leak (the one that would actually hurt).**
  Dispatched `arvo:<n>` / `oss-fuzz:<n>` names the public image. Distill
  #131 is the seal-time genericisation; the smallest close is refuse those
  ids at admission. Until that ships, v3 stays off.
- **Unauthenticated task/dispatch HTTP (live now).**
  Distill #33: `require_authentication` defaults false on
  `cybergym_http.make_handler`. Anyone on the internet can ask the task
  endpoint for task ids. Timeouts and the `authenticated_caller` seam exist;
  the default is still open. This is more exposed than the leak because it
  is on today and needs no subnet registration.
- **Trace bonus computed, never paid.** Distill #116.
- **Commit-then-draw is decorative.** Distill #136.
- **Crash differential not always deterministic.** Distill #153.

Miners for CyberGym come after the task-id fix, auth default-on, and a
coordinated v3 cutover. Not before.

## How to turn the lane on later

Only after distill refuses public catalog ids **and** a producer is posting
HMAC reports:

1. Deploy that distill revision.
2. Set `CATHEDRAL_CYBERGYM_MECHANISM_ENABLED=1`
3. Set `CATHEDRAL_CYBERGYM_WEIGHT_FRACTION=0.30`
4. Set `CATHEDRAL_ALLOCATION_CONTRACT=v3` on the publisher
5. Set `require_policy = "validated_supply_v3"` on the validator
6. Flip publisher and validator in one window. See
   [SN39_V3_PUBLISHER_CUTOVER.md](SN39_V3_PUBLISHER_CUTOVER.md).

Optional, still not DCAP: `CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT=1`
makes the Cathedral-signature check fail closed.
