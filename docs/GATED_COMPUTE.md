# Gated compute (SN94)

Owner decision, 12 November 2026. Until then the validator weighted every
verified TDX or SEV-SNP machine with nothing burned, so anyone who rented
confidential VMs earned, whether or not the machines could host customer rooms.
Now only approved miners are paid for compute.

## The split

Every cycle the validator signs one vector of 65535 units:

| Share | Goes to | Divided by |
|---|---|---|
| 10 percent (6553) | Approved miner hotkeys with at least one verified machine | Count of distinct verified machines |
| 10 percent (6553) | Verified escape room breakers | Count of verified breaks |
| The rest (80 percent or more) | The subnet owner hotkey | Burned by the chain |

Rules:

- A verified machine on a hotkey that is not on the approved list gets zero
  compute weight. Verification is still required: an approved hotkey with no
  verified machine gets nothing either.
- If a lane has no recipient in a cycle, its share is burned. It is never moved
  to the other lane or to an unlisted miner. With no approved machine and no
  break the whole vector is burned.
- Each lane is rounded on its own, so rounding cannot reach a hotkey outside
  the lane.
- The two shares are the constants `COMPUTE_LANE_SHARE` and `ESCAPE_LANE_SHARE`
  in `cathedral_thin/independent_runtime/direct_contract.py`. No environment
  variable or host file changes them. The escape lane is switched on per host
  as before ([Escape payout rollout](ESCAPE-PAYOUT-ROLLOUT.md)); while it is
  off its 10 percent is burned.

## The burn destination

The burn goes to the subnet owner hotkey
`5FQsFkui1UvS7S7Sf3JAqN9FPCR7RmufSEZTGuVPPN5EDmsN` (UID 0 on netuid 94 when this
was written). The chain burns or recycles miner emission that lands on the
subnet owner hotkey. The validator pins the hotkey, not the UID, resolves the
UID at each cycle's anchor, and refuses to sign unless the chain's own
`SubnetOwnerHotkey` for the subnet still names that hotkey at the sign head. If
the owner hotkey ever changes, validators stop writing until a release pins the
new one.

A validator that signs as the subnet owner hotkey submits the same vector, with
the burn on its own UID. The chain accepts that entry and keeps the subnet
owner's weight on its own UID in the epoch. The owner should later move its
validator to a hotkey that is not the subnet owner hotkey; that is an
operations change, not part of this release.

## The approved list

The list is `config/compute/approved-miners.json`. It ships inside the signed
validator release: the same document is embedded in
`cathedral_thin/independent_runtime/approved_miners.py` and pinned by sha256, so
an edit to one without the others fails at import. Nothing on a validator host
can add or remove a hotkey.

Each entry has the hotkey, a label and a note. A listed hotkey that is not
registered on the subnet, or has no verified machine, receives nothing and
changes nothing in the vector.

On 12 November 2026 the list was seeded with the owner's three compute-miner
hotkeys (`sn94_mainnet_cherry46`, `sn94_mainnet_cherry48`,
`sn94_mainnet_contabo`). None was registered on netuid 94 at that time (Finney
block 9489224): their earlier UIDs had been recycled. Until one of them is
registered again and has a verified machine, the compute lane is burned every
cycle. The owner can register them without a new release.

## How a miner gets onto the list

By owner approval only. There is no application endpoint and no automatic
admission.

1. The miner registers a hotkey on netuid 94 and runs sealed machines that pass
   verification.
2. The owner approves the hotkey.
3. A reviewed pull request adds an entry (`hotkey`, `label`, `note`) to
   `config/compute/approved-miners.json` (compact JSON, sorted keys, entries
   sorted by hotkey, one trailing newline), makes the same change to
   `PINNED_APPROVED_MINERS_DOCUMENT` and updates `PINNED_APPROVED_MINERS_SHA256`.
   `tests/thin/test_gated_compute_weights.py` checks the three agree. The pull
   request should state how the hotkey was confirmed on chain.
4. The owner signs and publishes a release. Validators on the stable channel
   pick it up through the signed updater and pay the new hotkey from their next
   cycle.

Removing a hotkey is the same change in reverse.

## Locking out validators on older releases

Releases with the gated split stamp weight version key `10005001`
(`DIRECT_VERSION_KEY`); earlier releases used `10005000`. After every validator
has updated, the owner may set `weights_version` on netuid 94 to `10005001`.
Validators still on older releases then cannot set weights and drop out of
consensus after `activity_cutoff`. That is an owner transaction and is not part
of any release. Do it only when no validator has a commit from an older release
still waiting for its reveal: the chain checks the key when it reveals a
timelocked commit, and a commit that fails that check is dropped.
