# Cathedral Validator boundary

This repository is the sole source for Cathedral SN39 validator behavior.

It owns:

- finalized miner discovery and signed fleet verification;
- local Intel TDX and SAT verification;
- miner hotkey to UID resolution and zero-burn machine-count scoring;
- exact-intent recovery and single-writer protection; and
- the authorized Bittensor weight transaction.

Cathedral Compute supplies worker evidence. Cathedral Distill supplies receipt
and lane contracts. Neither repository owns the validator wallet or submits
SN39 weights.

Registration, uptime, hardware ownership, attestation, or a self-reported score
does not earn weight. Only work which passes the active verification and policy
checks is eligible.

The supported recurring validator does not consume a signed vector, publisher,
or relay. It derives the full vector locally and submits it directly.

Historical v3 code still shares the `V3_CYBERGYM_LANE_FIELDS` shape. It is not
an input to the supported direct recurring validator. `cathedralai/cathedral`
is not a v3 allocation source.

Running `cathedral-validator --confirm-direct-write` permits it to sign and
submit weights. Historical documents, tests, and local runs do not prove a
current deployment or a successful on-chain submission.
