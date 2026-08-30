# Cathedral Validator

Cathedral Validator is a direct Bittensor SN39 validator. It derives its own
mechanism-0 weights from miner machines. It does not download a signed weight
vector and does not depend on a publisher or relay.

## One recurring path

Each cycle:

1. Reads one reverse-checked finalized Finney metagraph.
2. Discovers every serving non-validator miner axon.
3. Authenticates the validator request and fetches each miner's signed
   `/v1/fleet` response.
4. Verifies every machine with the pinned Intel TDX verifier and the existing
   SAT rule. The required verifier SHA-256 is
   `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148`.
   This pinned artifact is a linux/amd64 static executable.
5. Applies the existing global endpoint, TLS channel, and hardware dedupe.
6. Counts distinct verified machines per UID and normalizes the positive counts
   into one u16 vector with zero burn.
7. Writes the vector directly with the validator hotkey.

The writer records the exact signed intent before broadcast. A restart searches
finalized history for the same extrinsic hash. It never signs a replacement for
an unresolved attempt. A cycle reports `CONFIRMED` only after the exact stored
row and UID mappings match at inclusion and two later finalized heads.

## Run one proof

Install this checkout in a virtual environment. Use the reviewed verifier
executable and an existing Bittensor validator wallet.

```bash
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/cathedral-validator \
  --wallet-name cathedral \
  --wallet-hotkey default \
  --qvl /absolute/path/to/cathedral-tdx-verifier \
  --once \
  --confirm-direct-write
```

The runtime is pinned to Finney and SN39. It scores every serving miner. It has
no miner allowlist or alternate scoring mode.

The sole journal path is deterministic for the current user and signer:

```text
~/.local/state/cathedral-validator/direct-writer/
  finney-sn39-mechanism-0/<validator-hotkey>/state.json
```

The parent directory and journal must remain owner-only. There is no command
line state-path override.

## Current proof boundary

The local tests cover discovery, signed fleet enforcement, unchanged SAT,
deterministic multi-UID scoring, cooldown refusal before signing, exact-intent
persistence, ambiguous-submit recovery, and three-head stored-row confirmation.
They do not prove a production miner endpoint, production QVL availability,
validator permit, wallet funding, chain cooldown, or a live set-weights result.
