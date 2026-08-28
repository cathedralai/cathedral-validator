# SN39 dedicated second-miner plan

## Outcome target

The intended future state is two independently identified Cathedral miners on
SN39. UID30 assigns equal semantic scores to both miners and assigns zero weight
to a burn destination.

The first miner remains pinned by hotkey, not by a permanent UID:

- Wallet hotkey label: `serge_sat_test`
- Public hotkey: `5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G`

The dedicated second miner is pinned separately:

- Wallet hotkey label: `serge_sat_test_2`
- Public hotkey: `5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq`

Never place a mnemonic, private key, or wallet password in this repository, a
pull request, a plan artifact, a VM startup script, or an operator log.

## What this repository change does

`cathedral-second-miner-plan preview` performs finalized public reads only. It:

1. Pins Finney, netuid 39, mechanism 0, Cathedral UID30, the Cathedral coldkey,
   and both miner public hotkeys.
2. Confirms UID30 still has its validator permit and the first miner still has
   the expected owner.
3. Reports whether the second hotkey is unregistered, lacks its finalized HTTPS
   axon, or has reached the point where fresh machine proofs are required.
4. Derives the exact complete two-miner row only after the second hotkey has a
   finalized UID.
5. Writes owner-only JSON plus a detached SHA-256 digest without overwriting an
   existing file.

The command does not load a wallet. It has no registration, axon announcement,
extrinsic composition, weight submission, daemon, or retry path. Every artifact
contains `authorized_for_chain_write: false`.

Example, after installing the reviewed revision:

```bash
install -d -m 0700 "$HOME/.cathedral/second-miner"
cathedral-second-miner-plan preview \
  --output "$HOME/.cathedral/second-miner/plan.json"
```

## Current boundary

The existing standby VM uses the first miner's UID124 public hotkey. It is a
second machine behind the same on-chain identity. It is not a second listed
miner and does not satisfy this plan's outcome target.

The dedicated `serge_sat_test_2` public hotkey was not registered at finalized
block 8,946,847 on 2026-08-28. The planner must therefore return
`BLOCKED_SECOND_MINER_UNREGISTERED` and omit a wire row for the present state.

Both previous one-shot launch tools are consumed artifacts. The UID124 axon
announcement tool is pinned to the first hotkey and exact endpoint. The UID30
launch tool is pinned to the completed one-miner vector. Neither tool is a safe
path for a second miner.

## Required live sequence

Each step below needs separate operator review and explicit authorization. This
change implements none of the write steps.

1. Bootstrap or restart the second machine with the dedicated second public
   hotkey. Keep the immutable miner image and its reviewed startup contract.
2. Prove the second machine has fresh QVL PASS, canonical SAT success, and a TLS
   SPKI different from the first machine.
3. Register `serge_sat_test_2` once. SN39 is full, so registration replaces an
   incumbent UID. Registration has no rollback and incurs the live chain fee or
   burn even though the future weight vector has zero burn allocation.
4. Confirm the second public hotkey, Cathedral coldkey ownership, and assigned
   UID at a finalized head. Repeat at a later finalized head.
5. Build and review a new one-shot axon announcement. Pin the second public
   hotkey, finalized UID, external IP, HTTPS port 8081, protocol 4, genesis,
   source revision, and one exact write.
6. Submit that announcement once, then confirm the exact axon at inclusion and
   at two later finalized heads.
7. Rerun the read-only planner. Require both hotkeys to resolve uniquely and
   require the complete intended row below.
8. Build and review a new one-shot UID30 successor. Bind it to fresh QVL and SAT
   proofs for both axons, distinct TLS SPKIs, the latest finalized identities,
   UID30's permit and cooldown, zero burn destination, and one exact write.
9. Submit once. Confirm the complete UID30 row at inclusion and at two later
   finalized heads.

## Weight semantics

UIDs are resolved from hotkeys at a finalized head. For example, if the first
miner remains UID124 and the second registers as UID200, equal input scores
`[1.0, 1.0]` encode through Bittensor 10.5 as:

```json
[[124, 65535], [200, 65535]]
```

This is max-normalized u16 encoding. It is not a 65,535 total split such as
32,768 plus 32,767. A mechanism-weight submission replaces UID30's complete
row, so omitting either miner removes it from the row. UID30 itself and the
subnet-owner burn hotkey must not appear as destinations.

Zero burn here refers only to weight allocation. It does not remove the
registration cost.

## Success gates

The second-miner launch is complete only after all gates pass:

- Two distinct miner hotkeys resolve to two distinct finalized SN39 UIDs owned
  by the Cathedral coldkey.
- Both finalized axons expose HTTPS port 8081 with protocol 4.
- Both machines pass fresh QVL and canonical SAT verification.
- Their TLS SPKI identities differ.
- The reviewed preview names exactly both current UIDs with raw weights 65,535
  and has no burn destination.
- One successful UID30 extrinsic replaces the complete row.
- Inclusion and two later finalized reads reproduce the same exact row.

Registration, an axon, or an assigned UID does not prove rewards. A UID30 weight
row proves allocation from that validator only. TAO earnings remain not proven
until subnet emission is positive and a reward or balance delta is observed.
