# Cathedral Validator boundary

This repository is the sole source for Cathedral SN39 validator behavior.

It owns:

- signed score and evidence verification;
- miner hotkey to UID resolution;
- allocation and burn enforcement;
- replay, rollback, and single-writer protection; and
- the authorized Bittensor weight transaction.

Cathedral Compute supplies worker evidence. Cathedral Distill supplies receipt
and lane contracts. Neither repository owns the validator wallet or submits
SN39 weights.

Registration, uptime, hardware ownership, attestation, or a self-reported score
does not earn weight. Only work which passes the active verification and policy
checks is eligible.

The recurring provenance audit is observational. It records findings but never
changes or blocks the signed vector submitted by the recurring relay.

The v3 CyberGym lane shape is shared through
`V3_CYBERGYM_LANE_FIELDS`. Every value is independently derived by this
repository. `cathedralai/cathedral` is not a v3 allocation source.

Public validator operation is not self-service during live testing. Historical
documents, tests, previews, and local runs do not authorize a chain write or
prove current deployment state.
