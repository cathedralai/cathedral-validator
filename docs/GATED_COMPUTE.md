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
- The list gates the compute lane only. Unlisted hotkeys get zero compute
  weight; escape weight goes to verified breakers and is not gated by the
  list. A breaker is paid on the hotkey its signed receipt names, listed or
  not.
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

## A cycle always writes

Machine verification never stops the write. Before the split, a round with a
verifier `INFRA` verdict, a blocked round, or no serving miner refused the
whole cycle. That would now leave the previous on-chain row in force, and any
miner could cause it. So:

- No serving miner, or no verified machine: the vector is the burn, plus the
  escape share when there are verified breaks.
- An `INFRA` verdict on a hotkey that is not on the approved list is ignored.
  That hotkey earns no compute weight whatever its verdict.
- An `INFRA` verdict on an approved hotkey, or a blocked round, burns the
  compute lane for that cycle (the cycle event carries
  `compute_lane.status = BURNED_UNPROVEN`). No approved miner is paid another
  approved miner's share because of this validator's own verifier outage. With
  `CATHEDRAL_INFRA_HALT=scoped`, and a verifier that passed another machine of
  the same kind in the round, the proven machines are paid as before.

Chain rules still refuse a write (cooldown, permit, stake, commit-reveal
state, a changed subnet owner hotkey), as does a chain read that fails.

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
registered on the subnet, or has no verified machine, receives no compute
weight and changes nothing in the vector.

On 12 November 2026 the list was seeded with the owner's three compute-miner
hotkeys (`owner-miner-1`, `owner-miner-2`, `owner-miner-3`). None was
registered on netuid 94 when the list was built (Finney block 9489224): their
earlier UIDs had been recycled. The owner can register them without a new
release, and has started to: by Finney block 9489294 `owner-miner-1` was
registered as UID 19 (block 9489265) and `owner-miner-3` as UID 20 (block
9489293), while `owner-miner-2` was still unregistered. A registered hotkey is
paid from the compute lane only in cycles where it has a verified machine;
otherwise the compute lane is burned.

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

## Uptime rule (AB#327)

An approved miner's compute weight is multiplied by its uptime factor. The
cut goes to the burn, never to another miner. Code:
`cathedral_thin/independent_runtime/uptime_weight.py`.

- Source: the validator's own telemetry spool (`--telemetry-spool`), the same
  finalized rounds as the rolling availability (AB#326). A hotkey is up in a
  round when it had at least one verified machine.
- Window: one UTC day. Uptime is up rounds over counted rounds, in basis
  points.
- Factor: the latest settled window, which is the previous UTC day from
  01:00 UTC on (a commit-reveal round is spooled only after its reveal). At
  or above 9500 the factor is the uptime (97 percent keeps 97 percent of the
  weight). Below 9500 it is zero.
- Probation: three failing windows in the last seven settled windows pay
  zero until enough of them age out of the seven.
- Not held against a miner: rounds the validator did not finalize, rounds in
  which no hotkey verified a machine (this validator's verifier outage burns
  the compute lane and spools every miner at zero), rounds before the hotkey
  was first up, and windows with fewer than 12 counted rounds.
- Fails open: with no spool, or a spool that cannot be read or scored, the
  plan is unchanged. The cycle event's `uptime.status` says which:
  `APPLIED`, `FULL`, `NO_HISTORY` or `UNAVAILABLE`.
- A plan with a factor below full lists it in its identity (`uptime`) and
  binds it into the evidence digest; the writer refuses a factor that is not
  below full, names a UID outside the compute lane, or repeats a UID.

Known limits: a validator without a telemetry spool pays full factors, so two
validators can sign different vectors. The public telemetry status of an
approved miner cut to zero reads `not_approved`. The spool keeps 720 events
and 16 MiB; with many serving miners the byte cap shortens the lookback.

## Known limits

- **Recipients are checked at one finalized block.** The validator checks
  every recipient's UID and hotkey at the anchor and again at the sign head.
  The signed call, and the timelocked commit the chain reveals about one epoch
  later, carry UIDs, not hotkeys. A hotkey swap keeps the UID, so if the owner
  of an approved hotkey swaps it after that read, the weight stays on the UID
  under the new hotkey; reveal recovery records the change and does not undo
  it. Only the owner of an approved hotkey can do this, and today every
  approved hotkey is the subnet owner's own, so it is accepted for this
  release. It must be closed before any outside hotkey is put on the list.
- **The escape lane is per host.** A validator without the escape source
  configured burns the escape share, so validators can disagree on that lane.
- **Telemetry is not a payout ledger.** It lists serving miners only, so an
  escape breaker that serves no axon is not shown, and no event is published
  for a cycle with no serving miner or with a burned unproven compute lane.
- **Any serving miner can cost one cycle.** Before it signs, the writer
  requires the serving set to equal the set at the anchor. A finalized axon
  change by any miner, listed or not, inside that window makes the validator
  skip that cycle; it writes on the next one. This rule is older than the
  gated split. A miner would have to land a change inside every cycle's
  window, on every validator, to keep an older row in force.
- **`CATHEDRAL_INFRA_HALT=scoped` keeps its meaning.** With that opt-in, an
  approved miner whose machine ends in INFRA while the verifiers passed other
  machines of that kind does not burn the lane: the approved miners that
  passed share it. Without the opt-in the lane is burned.
- **Unlisted miners are still challenged.** Their evidence cannot change the
  vector, but they are verified every cycle and take cycle time.

## Locking out validators on older releases

Releases with the gated split stamp weight version key `10005001`
(`DIRECT_VERSION_KEY`); earlier releases used `10005000`. After every validator
has updated, the owner may set `weights_version` on netuid 94 to `10005001`.
Validators still on older releases then cannot set weights and drop out of
consensus after `activity_cutoff`. That is an owner transaction and is not part
of any release. Do it only when no validator has a commit from an older release
still waiting for its reveal: the chain checks the key when it reveals a
timelocked commit, and a commit that fails that check is dropped.
