# Cathedral Validator

Cathedral Validator is a direct Bittensor SN39 validator. It derives its own
mechanism-0 weights from miner machines. It does not download a signed weight
vector or use a weight publisher or relay.

## One recurring path

Each cycle:

1. Reads one reverse-checked finalized Finney metagraph.
2. Discovers every serving non-validator miner axon.
3. Sends signed validator-authenticated requests and fetches each miner's
   `/v1/fleet` response. The miner still requires its fresh signed
   validator-access snapshot before it serves a validator.
4. Verifies every machine with the pinned Intel TDX verifier and the existing
   SAT rule. The required verifier SHA-256 is
   `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148`.
   This pinned artifact is a linux/amd64 static executable.
5. Applies the existing global endpoint, TLS channel, and hardware dedupe.
6. Counts distinct verified machines per UID and normalizes the positive counts
   into one u16 vector with zero burn.
7. Writes the vector directly with the validator hotkey.

One 120-second pre-sign budget starts before the finalized snapshot. No new
discovery result is accepted after 60 seconds, and no miner SAT result is
accepted after the 90-second miner cutoff. At most 32 miner tasks run together
across discovery and SAT. Queued or unfinished miners earn zero, and the
finalized anchor hash rotates their deterministic scheduling order. The writer
then performs the exact finalized-block freshness check before signing. The
120-second wall budget leaves 72 seconds against the 16-block target interval
at 12 seconds per block. Binding, evidence, fleet, QVL, and SAT durations are
monotonic telemetry only. A completed machine earns the same count anywhere
inside its deadline. Missing a deadline earns zero.

The writer records the exact signed intent before broadcast. A restart searches
finalized history for the same extrinsic hash. It never signs a replacement for
an unresolved attempt. A cycle reports `CONFIRMED` only after the exact stored
row and UID mappings match at inclusion and two later finalized heads.

## Run the validator

Install this checkout in a virtual environment. Use the reviewed verifier
executable and an existing Bittensor validator wallet.

```bash
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/cathedral-validator \
  --wallet-name YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
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

## QVL download pending

The required public linux/amd64 verifier download is pending
[issue #185](https://github.com/cathedralai/cathedral-validator/issues/185).
Until it publishes an immutable asset, there is no supported public download.
Do not substitute another binary or weaken the digest check.

## Current proof boundary

The local tests cover discovery, signed fleet enforcement, unchanged SAT,
deterministic multi-UID scoring, cooldown refusal before signing, exact-intent
persistence, ambiguous-submit recovery, and three-head stored-row confirmation.
They do not prove a production miner endpoint, production QVL availability,
validator permit, wallet funding, chain cooldown, or a live set-weights result.
