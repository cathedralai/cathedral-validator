# Customer execution and subnet boundary

Status: contract boundary only. No reward-policy, wallet, or chain behavior changes.

## Purpose

Cathedral customer execution must remain available without Bittensor. The customer request path
selects capacity, runs the job, verifies evidence, confirms cleanup, settles the invoice, and signs
the customer receipt before any subnet component receives a fact.

```text
customer request
    -> Cathedral capacity broker
    -> seed or miner provider
    -> verified result and cleanup
    -> settled customer receipt

settled verified-work fact
    -> score-class producer
    -> validator-owned assignment
    -> optional Bittensor weight transaction
```

The second path is asynchronous. A stopped publisher, validator, chain, or epoch loop must not block
customer admission, execution, result retrieval, cleanup, refund, or receipt retrieval.

## Provider identities

The customer plane recognizes two provider identity kinds:

- `cathedral_seed`. Cathedral-managed bootstrap capacity. It has no subnet hotkey and earns no
  subnet reward.
- `subnet_hotkey`. Admitted external capacity with an explicit hotkey binding. The binding makes the
  provider eligible for later scoring. It does not grant a reward by itself.

Provider enrollment, uptime, claimed capacity, self-reported speed, and a successful boot quote are
not payable work.

## Reward-eligible fact

A future adapter may convert completed provider attempts into the existing
`cathedral_score_class_report_v2` contract. It must admit a fact only when all of these conditions
hold:

1. The provider identity kind is `subnet_hotkey` and the hotkey appears in the finalized candidate
   snapshot for the report epoch.
2. The logical job and terminal attempt are unique under the producer's durable high-water state,
   and each consuming validator independently rejects a repeated `(job_id, attempt_id)` against its
   own replay state. Producer-side deduplication is a first filter, not the authority. The validator
   contract below never falls back to provider self-reporting, and a producer high-water mark is a
   producer assertion.
3. The attempt reached `SUCCEEDED` through `EVIDENCE_VERIFIED` and
   `SUCCESS_CLEANUP_PENDING`, and the slot reconciler recorded confirmed
   provider-resource absence for that attempt.

   Terminal state alone is not sufficient. An attempt also reaches a terminal
   state when the cleanup deadline expires without confirmed absence. Admitting
   that case would pay a provider that never tore down its resource, which
   inverts the incentive on the one behavior the customer plane most needs to
   enforce. A deadline-expired attempt settles the customer normally and
   produces no reward-eligible fact.
4. The result, policy, workload, assignment, and receipt digests match the accepted customer record.
5. The customer invoice decision is terminal and carries no charge above the reserved cap.
6. The receipt and evidence kinds required by the validator's local policy are present.
7. The exported metric is exactly `verified_work_units`: a non-negative integer count of attempts
   satisfying conditions 1 through 6, carrying no latency, uptime, or capacity component. Adding a
   metric or changing this definition is a versioned reward-policy change under step 5 of the
   activation order, not an implementation detail. The producer does not assign weights.

`cathedral_seed` attempts may contribute operational benchmark data. They must produce zero subnet
reward entries because no miner hotkey performed the work.

Seed capacity is Cathedral-operated. Using its measurements as a comparative baseline that scores
miner capacity would let the operator set the bar it grades competitors against. Seed benchmark data
is therefore limited to operational monitoring until a versioned reward-policy decision states
otherwise under step 5 of the activation order.

## Private and public data

The score-class report must not contain customer IDs, account IDs, idempotency keys, workload input,
output, artifacts, secrets, provider credentials, raw hardware evidence, internal endpoints, cloud
instance IDs, or stable hardware identifiers.

Allowed evidence references are bounded identifiers, digests, and approved credential-free HTTPS
locations already covered by the score-class policy. Receipt verification proves the signed
assertions. It does not replay provider deletion, billing rows, or vendor evidence by itself.

## Validator authority

The existing validator contract remains unchanged:

- The publisher authenticates and stores external score-class reports. It does not set weights.
- Each validator pins sources and keys, checks freshness and replay state, maps hotkeys to current
  UIDs, applies its own allocation, and signs its own transaction.
- A failed or missing class holds the configured decision. It never falls back to provider
  self-reporting.
- Broadcast remains an explicit validator operation behind release, evidence, wallet, and
  single-writer gates.

No customer control-plane service receives a validator wallet or permission to call `set_weights`.

## Activation order

1. Prove the seed-provider customer path with subnet export disabled.
2. Emit shadow verified-work facts for admitted miner attempts.
3. Reproduce deduplication, evidence admission, and aggregation off-chain.
4. Dark-score the proposed metric without changing the signed vector.
5. Review and version any reward-policy change separately.
6. Enable a bounded subnet class only after an explicit chain-activation decision.

This document does not activate any of those phases.
