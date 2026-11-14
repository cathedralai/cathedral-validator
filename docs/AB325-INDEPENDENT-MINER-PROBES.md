# AB#325: independent miner probes

Status: proposed implementation contract for peer review. This document changes no scoring or production setting. AB#325 remains Doing.

## Current behavior and gap

- `cathedral_thin/independent_runtime/direct_validator.py` challenges miner machines and builds the paid vector from positive machine rows in `_positive_machine_rows` and `build_direct_plan` (lines 581-737). It writes the plan in `run_direct_cycle` before any capacity shadow work (lines 958-1023).
- `cathedral_thin/independent_runtime/capacity_shadow.py` validates signed capacity receipts and can record attestation evidence, but its policy accepts only `shadow` (lines 64, 264-282). `CapacityShadow.record` fetches its own feed after the write. `direct_validator.py:_capacity_shadow_event` explicitly runs outside the cycle lock after the write (lines 1436-1465). Neither changes paid weight.
- A capacity receipt may reuse attestation evidence from admission or the last relaunch. Its age check is optional (`capacity_shadow.py`, lines 101-114). A passing shadow receipt therefore does not prove a fresh quote or a successful small sealed task in this cycle.
- `capacity_inventory.py` marks verified receipts healthy and missing receipts missing, but it has no binding from a box to a paid `machine_id` and no path into the paid plan (lines 1-30, 100-160).

The first code package must establish a signed, per-cycle result that can be matched to exactly one paid machine. It must not treat broker health or the existing shadow inventory as that result.

## Contract to agree before code

1. **Independent caller and trust root.** An operator-controlled prober, separate from the miner hotel and broker, obtains a fresh validator challenge for each finalized anchor. The validator pins its Ed25519 public key in a local policy. A miner or broker cannot submit a positive result merely by setting a status field. The deployed prober identity and feed URL are recorded with the policy digest.
2. **One machine, one cycle.** Each signed result binds netuid, finalized anchor block hash, validator challenge nonce, miner hotkey, UID, the paid `machine_id`, and the concrete endpoint or attested box identity used to reach it. The validator accepts at most one result for that tuple and refuses ambiguous duplicate or cross-hotkey identities. A result for a different anchor, nonce, network, or machine cannot be reused.
3. **Fresh attestation and task.** The prober verifies an SNP quote under the pinned SN94 measurement and TCB policy, debug off, with a nonce generated for this cycle. It then creates or uses a sealed task room and executes a small bounded command through the guest, checks the authenticated result and its signed receipt, and records both evidence digests. A successful TCP or broker health check alone cannot yield PASS. The task and quote must be for the same admitted machine and current cycle.
4. **Bounded failure.** A signed FAIL or timeout for a machine sets that machine's compute contribution to zero even if its broker health is green. A missing, stale, malformed, or unverifiable result never becomes PASS. If the prober or feed is unavailable as a whole, the compute lane burns for that cycle with an operator alert; the Escape lane keeps its own verified share. The validator still writes a fresh plan so previous on-chain compute weight is not left in force. No other miner receives a failed miner's share.
5. **Evidence-bound scoring.** Before `build_direct_plan` and `writer.submit`, the validator intersects existing positive machine rows with verified probe PASS rows. It includes the probe policy digest, challenge, per-machine verdict and evidence digest in the plan's evidence document so the written vector can be audited. The `shadow` deployment remains read-only; a separate explicit enforce setting controls the new gate and defaults off until a mainnet proof and owner decision.

## Work packages

1. **Pure contract, no payout change.** Add strict parser and signature verification for the probe result and a pure function that matches it to the current finalized snapshot and positive machine rows. Add bounded document size, row count, time and duplicate checks. A result cannot inherit the old capacity-shadow optional evidence-age rule. Keep this package off the paid path and record only a comparison event.
2. **Independent prober.** Implement the challenge, fresh SNP verification and sealed task in the owner-operated prober. Publish signed results through a feed that does not trust the broker's asserted success. Record the real deployment and key custody in the operator runbook. The prober must time out well within `FULL_CYCLE_RESPONSE_DEADLINE_SECONDS`.
3. **Paid gate.** Fetch and verify results inside the cycle deadline, before plan construction. Gate only positive machine rows; do not manufacture new positive rows from the feed. Bind the probe evidence into `DirectWeightPlan` identity and the writer journal. Preserve Escape share on compute failure. Provide a single reversible enforce switch with a shadow comparison period before activation.
4. **Mainnet proof.** On an approved SN94 miner hotel, capture a successful fresh quote plus task receipt and the resulting paid vector. Intentionally fail the sealed task while broker health remains green, then show that machine's compute contribution becomes zero on the signed on-chain vector. Repeat with stale/replayed evidence and a prober outage. Restore the good path and show recovery. Keep the card open until these readbacks are attached.

## Required regressions

- PASS with matching nonce, anchor, hotkey, machine, fresh SNP quote and signed task receipt.
- Broker healthy but task fails; good quote but task fails; good task but stale, wrong-TCB, debug-on, or wrong-machine quote. Each yields no positive compute for that machine.
- Missing result, duplicate result, replay from another anchor or hotkey, forged signature, and mismatched UID or endpoint. Each yields no positive compute.
- One failing miner cannot suppress an unrelated approved miner. Whole-feed outage burns the compute lane and still writes the Escape lane. The next good cycle can recover.
- Timeout and cancellation leave no running probe or held cycle lock. Plan identity and journal recovery bind the same probe digest used for the vector.

## Boundaries and unresolved inputs

- This card does not open compute mining to unapproved hotkeys, change the approved list, or change the compute/escape share.
- The owner must name the independently operated prober and approve its key custody, measurement/TCB policy and mainnet failure window before activation. No production switch is flipped by the parser package.
- The current capacity receipt `box_id` and paid `machine_id` are not proven to be the same identifier. Package 1 must define and test an attested, one-to-one mapping rather than joining them by similar strings.
- A feed that can only say what the broker says is not an independent probe. Package 2 must demonstrate an end-to-end guest command and verified receipt.
