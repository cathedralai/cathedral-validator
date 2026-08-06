# What a miner and a validator run on SN39

SN39 (Cathedral) rewards **two lanes of verified work**, composed into one weight vector
each tempo — **70% Intel-TDX compute** / **30% CyberGym vulnerability solving**, with any
unfilled share burned. This page is the whole mental model. The deeper contracts are in
[VALIDATOR.md](VALIDATOR.md), [deploy/MECHANISM_ROUTER_CONTRACT.md](deploy/MECHANISM_ROUTER_CONTRACT.md),
and the reward-path docs.

## A miner

One neuron, one lane at a time:

```
register a hotkey on SN39 (btcli subnet register --netuid 39 …)
   └─ do verified work in a lane:
        • compute  : run the approved Intel-TDX workload      → a Cathedral attestation receipt
        • cybergym : solve the dispatched sealed PoC          → a proof-of-crash + trace
   └─ submit it: an on-chain COMMIT of  H(work_hash ‖ your_hotkey)  + an off-chain pointer
   └─ the artifact is graded after a short reveal delay
```

- The receipt / PoC lives **off-chain**; only the hotkey-bound hash + pointer go on-chain,
  so a copier who points at your artifact commits a hash that will not validate under their
  hotkey.
- You earn **proportional to verified work** (not a fixed slot): more verified solves / more
  attested compute → more of your lane's share.

## A validator

One neuron, `cathedral-validator serve`. Each tempo it does exactly this:

```
1. COMPUTE lane   — for each miner, fetch its Intel-TDX receipt and DCAP-verify it
                    *itself*, then score. (Publicly verifiable → every validator agrees.)
2. CYBERGYM lane  — ingest the corpus holder's signed score report and independently
                    verify its attestation receipt (the spot-check), then score.
3. COMPOSE        — 70% compute / 30% cybergym; a lane that fails to verify BURNS its
                    share rather than handing it to the other lane.
4. SET WEIGHTS    — one path: smooth, normalize, apply the chain limits + commit-reveal,
                    zero any replaced hotkey, and confirm the extrinsic landed.
```

It **verifies before it trusts**: it never relays a score it has not checked. Run it in
**shadow** first (`--dry-run`, composes but writes nothing), then broadcast for real from
the staged install (`deploy/sn39`).

## Why the two lanes are scored differently

| Lane | Scored by | Because |
|---|---|---|
| **Compute / TDX** | **each validator, independently** | an Intel-TDX (DCAP) receipt is publicly verifiable — no secret needed, so it is fully decentralized. |
| **CyberGym** | the **corpus holder**, centrally, then relayed | the vulnerability holdout is a **sealed private corpus** — if every validator held it, so could miners, and the "solve an unseen bug" mechanism collapses. It stays central, but **provably honest**: the signed report carries one Intel-signed attestation receipt that every validator verifies binds to *this epoch's chain-named miner*. |

That single asymmetry — decentralize what is verifiable, attest what cannot be — is the
design. A validator on this network is never a rubber stamp: the compute lane it computes,
and the CyberGym lane it *proves*.

## Getting started

- **Run a validator:** [deploy/sn39/docker/](deploy/sn39/docker/) (Docker, 3 commands) or
  the native quickstart in the [README](README.md#quickstart). Register + stake a hotkey
  first (an unstaked validator's weights are ignored by consensus).
- **Run a miner:** register a hotkey, pick a lane, submit. (Miner tooling: `cathedral-miner`.)

## Status (what's shipped vs. building)

This page is the **launch design**. Some of it ships today; some is the refactor that gets us
there (tracked in the launch refactor plan):

- **Shipped:** the validator that composes lanes + sets weights (`scaffold/publisher/mechanism_router.py`,
  `scaffold/validator_thin.py`); the CyberGym lane ingest + tournament + **attestation spot-check**
  (`mechanism_cybergym_adapter.py`, `cybergym_attestation.py`); onboarding (`deploy/sn39`).
- **Building:** moving the **compute lane from relayed to validator-self-scored** (DCAP-verified in
  the validator), and the **miner commit-reveal** submission path. Until then the compute lane is
  relayed from Cathedral's signed feed, and the miner path is the compute/`cathedral-miner` attestation
  flow. The end state is one validator + two lane modules + one miner — no separate relay.
</content>
