# Cathedral Validator boundary

## Authority

`cathedralai/cathedral-validator` is the canonical source for Cathedral SN39
validator behavior and operations.

This repository owns:

- the `cathedral-validator` command
- signed-vector verification
- provenance replay and evidence gates
- miner hotkey to UID resolution
- allocation and burn enforcement
- one-writer and rollback protection
- dry-run and broadcast controls
- the immutable Linux release builder, launcher, configs, and systemd units

There is no upstream validator sync. No other Cathedral repository is a deploy
source for the validator.

### Allocation contracts

This repository is the sole owner of the signed allocation contracts, both the
v2 (90% Intel TDX / 10% fixed burn) contract and the v3 (70% Intel TDX / 30%
CyberGym / 0% fixed burn) contract. That ownership covers both halves of the
v3 CyberGym lane — the composition in `scaffold/publisher/weights.py` and the
admission in `scaffold/validator_thin.py`.

The two halves are a producer and an independent verifier, so they share
exactly one thing: `wire_vector.V3_CYBERGYM_LANE_FIELDS`, the lane's key set.
Shape is a wire contract and is stated once; every VALUE inside the lane is
still re-derived by the validator against its own metagraph read, including the
UID-to-hotkey bindings that stop a recycled UID from collecting another miner's
CyberGym share.

A second implementation of the v3 lane in any other repository is a fork
hazard, not a convenience: a vector composed against one copy and reproduced
against the other can disagree, which is the one failure this contract exists
to make impossible. `cathedralai/cathedral` is not a v3 allocation source.

## Connected repositories

The validator consumes contracts from two repositories without transferring
authority to them.

| Repository | What the validator consumes | What it cannot do |
|---|---|---|
| `cathedral-compute` | Compute worker evidence and provenance verification code | Claim the `cathedral-validator` command, sign with the validator wallet, or set weights |
| `cathedral-distill` | Distill receipt, lane, replay, and composition contracts | Bypass admission, choose owner allocations, sign with the validator wallet, or set weights |

Both dependencies are pinned to immutable reviewed commits. A dependency update
must update its lock, tests, and release evidence together.

## Decision boundary

The validator accepts no weight because a miner is registered, online, or
self-reports work. The active path checks:

1. signature and independently pinned key
2. Finney SN39 audience
3. freshness, expiry, and rollback state
4. the selected reward-policy contract
5. evidence and receipt admission
6. current hotkey to UID mapping
7. owner-controlled allocation and burn policy
8. the one-writer submission journal

Any required failed gate stops the decision. `NOT_PROVEN` is not success.

## Execution boundary

Thin mode verifies the signed candidate and reads the live metagraph. It does
not need Intel TDX on the validator host.

Authority mode independently replays controlled evidence. It requires a Linux
x86-64 host, the pinned verifier binary, the controlled evidence tree, and all
configured key and digest pins.

Workers provide hardware evidence. They never receive the validator wallet.
The validator host stores only the registered validator hotkey needed for a
permitted weight transaction. The validator coldkey is not installed there.

## Write boundary

`cathedral-validator serve` is non-writing by default.

`--offline` performs no chain access. `--dry-run` reads current chain state and
prints the exact candidate without writing. `--broadcast` permits one chain
attempt only after the release, policy, evidence, vector, wallet, and
single-writer gates pass.

A publisher, miner, receipt, evidence bundle, CLI, or Compute service cannot
bypass those gates or sign a weight transaction.

## Release boundary

Operators run `main` from a git checkout, installed editable. That is the
supported path and it is what SN39's own uid 30 runs.

The hardened path below — an immutable content-addressed release on Linux —
remains available for operators who want it, and is documented under "Supported
systemd install (relay)" in [README](README.md). Where it is used, the release
manifest binds:

- the exact Validator commit
- the locked Python environment
- the pinned Compute source archive
- validator configs and policy keys
- launcher and systemd units
- the verifier binary
- the bootstrap Python interpreter

The release builder rejects dirty source, mutable paths, unexpected packages,
installed configs or keys that differ from the reviewed release, and a Compute
package that claims the `cathedral-validator` console script. It binds the
installed dependency files into the manifest. The launcher rejects later
changes to those bound files.

## Logging boundary

The raw validator journal is private operator data. The public status stream is
a separate allowlisted projection. Neither stream includes wallet seeds,
private keys, bearer tokens, cloud credentials, or controlled raw evidence.

## Historical note

This code was initially extracted from a larger repository. The extraction
period is over. Its origin manifest and one-way sync tooling were retired when
this repository became the validator authority. Historical release documents
describe earlier states and are not operator routing.
