# What a miner and a validator run on SN39

This page describes what the shipped validator and publisher **actually do**.
If a sentence here disagrees with a flag default, the flag default is the
product. See [docs/CYBERGYM_LANE.md](docs/CYBERGYM_LANE.md) for the CyberGym
switches and the v3 gate.

## What is live today

SN39 currently pays **one lane**: attested Intel TDX compute, composed as
`validated_supply_v1` (v2 vector: 90% TDX / 10% burn). CyberGym is implemented
in the publisher, and it is **switched off** in what we ship. Four flags are
all off. No CyberGym weight and no CyberGym money move today.

That is intentional until cathedral-distill refuses public-catalog `task_id`s
(`arvo:<n>`, `oss-fuzz:<n>`). Do not set `CATHEDRAL_ALLOCATION_CONTRACT=v3`
before that fix is deployed. Flipping v3 first is the one non-survivable
move: a miner who sees those ids can pull `n132/arvo:<n>-vul` and read
`/tmp/poc`.

## A miner

One neuron, one live lane:

```
register a hotkey on SN39
   └─ run the approved Intel TDX workload
   └─ Cathedral issues a customer receipt over that work
   └─ the producer exports a signed score-class report + public evidence
```

CyberGym solving is not a paying lane on the shipped defaults. Miners for
that lane come after the task-id fix and a coordinated v3 cutover.

## A validator

One neuron, `cathedral-validator serve`. Each tempo:

```
1. COMPUTE lane   — ingest Cathedral's signed compute feed (not a per-validator
                    Intel DCAP replay of every miner). The public evidence
                    chain is independently verifiable. Validator-self-scored
                    compute is still building (see Status).
2. CYBERGYM lane  — only if v3 is selected AND the mechanism is enabled.
                    Ingest the corpus holder's HMAC-authenticated score report.
                    Optional spot-check: verify Cathedral's Ed25519 signature
                    on one carried receipt. Default: record failure, pay anyway.
3. COMPOSE        — v2: 90% compute / 10% burn.
                    v3 (not shipped): 70% compute / 30% CyberGym; an
                    unfilled CyberGym share burns. A v3 compose that cannot
                    build the CyberGym lane fails the whole vector.
4. SET WEIGHTS    — one path: smooth, normalize, chain limits, commit-reveal.
```

### What "attestation" means on this path

- Offline verifier success on a Cathedral receipt proves Cathedral signed
  those exact assertions with the pinned Ed25519 key.
- It does **not** independently replay vendor evidence.
- It does **not** prove AMD SEV host attestation.
- It is **not** "every validator independently DCAP-verifies CyberGym."
  That sentence was wrong. The code checks Cathedral's signature.

`CATHEDRAL_CYBERGYM_REQUIRE_ATTESTATION_RECEIPT` is off by default. When off,
a missing or invalid carried receipt is recorded and the lane still pays.
Once an audience has ingested a receipt-bearing report, a later report
without one is refused by the ingest ratchet even while this flag stays
off. Real Intel DCAP quote verification is separate work.

## Why the two lanes are scored differently (design, not today's defaults)

| Lane | Who scores it today | Why |
|---|---|---|
| **Compute / TDX** | Cathedral producer, relayed. Each validator checks the signed vector + public evidence, not a local DCAP loop over miners. | An Intel TDX receipt is publicly verifiable; the live path still uses the signed feed. |
| **CyberGym** | Corpus holder, HMAC-relayed, then optional Cathedral-signature spot-check | The holdout is a sealed private corpus. If every validator held it, so could miners. |

## Getting started

- **Run a validator:** [deploy/sn39/docker/](deploy/sn39/docker/) or the native
  quickstart in the [README](README.md#quickstart). Register + stake a hotkey
  first.
- **Run a miner:** register a hotkey and run the compute/`cathedral-miner`
  attestation flow.

## Status (shipped vs building)

- **Shipped:** compose + set weights; CyberGym ingest + tournament + Cathedral
  Ed25519 spot-check (default advisory, mechanism default off); SN39 onboarding.
- **Shipped defaults:** `require_policy = validated_supply_v1`;
  `CATHEDRAL_ALLOCATION_CONTRACT` unset/v2; `CATHEDRAL_CYBERGYM_MECHANISM_ENABLED`
  false; `CATHEDRAL_CYBERGYM_WEIGHT_FRACTION` 0.0.
- **Building:** validator-self-scored compute (local DCAP of miner receipts);
  miner commit-reveal; real Intel DCAP verification of CyberGym receipts;
  distill public-catalog `task_id` refusal (blocks any v3 flip).
