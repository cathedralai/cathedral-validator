# Historical SN39 second-miner record

## Do not use this as an operator runbook

The dedicated second-hotkey, UID8 first-time axon, UID124 replacement axon, and
two-UID UID30 successor paths are retired. Their console entry points are not a
supported launch surface. Historical recovery code remains because deleting it
would weaken recovery for an already journaled ambiguous attempt.

Use the [repository home page](../README.md) for the supported recurring direct
validator. The linked multi-compute page is a historical pointer only.

## Preserved finalized evidence

The first miner public hotkey is:

```text
5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G
```

The historical dedicated second miner public hotkey is:

```text
5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq
```

The aliases `serge_sat_test` and `serge_sat_test_2` are local wallet labels,
not chain identities.

- UID8 registration was included at block 8,947,050,
  `0xad3028f451ac5a4b10644368183d8f1ca1511b85ab2212736599c73f872f6093`.
- UID8 axon `34.46.19.69:8081`, protocol 4, was included at block 8,947,143,
  `0x4291de7f46263ddd710ecc6ad7f5f7c9fe99c399744c62a6af423e0406ae0ac4`.
- UID124 replacement axon `35.222.166.235:8081`, protocol 4, was included at
  block 8,947,452,
  `0x2fea7be3a2031f3e0523e26d2eeed919c7473c7ca844e5a6c243441cdc231e2e`,
  in extrinsic
  `0x8fabb01ac88246a3e41ddd4912e35fc4c9abb6432c7c1ce8ad762ee0292cc3a3`.
- Later finalized reads at blocks 8,947,463 and 8,947,509 reproduced both
  serving axons.
- Post-restart evidence returned QVL PASS and 20 SAT units for each machine.
  Their recorded TLS SPKI SHA-256 values were distinct:
  `5c317b51fdd10060374c41a5f0bbb9d6311f0cabaa40111dc94aa7446b232496`
  for UID8 and
  `a3f9a1a6dcfe3fad342501bcd347484d90f1d3e4c436274c170337667b8de579`
  for UID124.
- A later read-only snapshot at finalized block 8,949,280 reported UID30
  mechanism-0 storage `[[8, 65535], [124, 65535]]`.

These facts prove two registered serving UIDs and the recorded validator row.
They do not prove two physical machines behind one UID, positive subnet
emission, or TAO earnings. TLS SPKI distinguishes channels, not physical
platforms. The current fleet scorer requires a QVL-verified stable platform
identity for physical-machine credit.

## Recovery boundary

`python -m cathedral_thin.uid30_launch successor-recover` remains available
from a source checkout only for an exact
existing two-UID successor journal carrying a signed ambiguous attempt. It must
not create a new intent, sign, retry, or submit. Do not invoke it against a
pristine journal or use it to start a new launch.

An exact historical UID124 axon intent has one equivalent source-only reader:
`python -m cathedral_thin.independent_runtime.miner_axon_cli recover`. Use
`--help` for its required journal and proof inputs. It reads finalized state and
never announces or resubmits.

No retired preview, announce, or successor-submit command is supported. Git
history preserves their implementation and earlier operator text. The active
product path is the recurring direct validator on the repository home page.

Zero burn refers only to weight allocation. Registration cost is separate. A
weight row proves allocation from one validator only. Rewards remain NOT PROVEN
until subnet emission is positive and a reward or balance delta is observed.
