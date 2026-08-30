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
4. Verifies every machine as Intel TDX or AMD SEV-SNP, then applies the same
   SAT rule. The required TDX verifier SHA-256 is
   `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148`.
   This pinned artifact is a linux/amd64 static executable.
5. Applies the existing global endpoint, TLS channel, and hardware dedupe.
6. Counts distinct verified machines per UID and normalizes the positive counts
   into one u16 vector with zero burn.
7. Writes the vector directly with the validator hotkey.

For AMD, a credited machine proves an admitted boot measurement, distinct
hardware, the fresh validator challenge, the bound HTTPS key, and returned SAT
work. It does not prove the miner's OCI image digest or continuous runtime
integrity after boot. The miner's immutable-image check is local to its launcher.

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
an unresolved attempt. A cycle reports `CONFIRMED` only after destination UID
mappings match at inclusion and the exact stored row matches at inclusion and
two later finalized heads.

## Run the validator

Install this checkout in a virtual environment. Use the reviewed verifier
executable and an existing Bittensor validator wallet.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[snp-production]'
.venv/bin/cathedral-validator \
  --wallet-name YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  --qvl /absolute/path/to/cathedral-tdx-verifier \
  --snpguest /absolute/path/to/snpguest \
  --snp-policy /absolute/path/to/amd-sev-snp-policy.json \
  --confirm-direct-write
```

The runtime is pinned to Finney and SN39. It scores every serving miner. It has
no miner allowlist or alternate scoring mode. Add `--once` only for a bounded
first-launch verification. It still signs and submits one live vector, and it
exits zero only after exact finalized confirmation.

The sole journal path is deterministic for the current user and signer:

```text
~/.local/state/cathedral-validator/direct-writer/
  finney-sn39-mechanism-0/<validator-hotkey>/state.json
```

The parent directory and journal must remain owner-only. There is no command
line state-path override.

Run the recurring process under a restart supervisor. `CONTRADICTION_STOPPED`
is a deliberate terminal exit with status 2. For systemd, use
`Restart=on-failure` with `RestartPreventExitStatus=2` so that status is not
restarted. A supervisor must never clear the journal or the contradiction.
Review the stored signed intent and finalized chain state
before any manual journal clearance.

## Install the pinned QVL

Download the immutable linux/amd64 asset from the
[v1.0.0 verifier release](https://github.com/cathedralai/cathedral-sandbox/releases/tag/cathedral-tdx-verifier-v1.0.0),
verify its exact SHA-256, and make it owner-executable:

```bash
install -d -m 0700 "$HOME/.local/lib/cathedral-validator"
qvl="$HOME/.local/lib/cathedral-validator/cathedral-tdx-verifier-linux-amd64"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$qvl" \
  https://github.com/cathedralai/cathedral-sandbox/releases/download/cathedral-tdx-verifier-v1.0.0/cathedral-tdx-verifier-linux-amd64
printf '%s  %s\n' \
  4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148 \
  "$qvl" | sha256sum --check -
chmod 0500 "$qvl"
```

Pass that absolute path to `--qvl`. Do not substitute another binary or weaken
the digest check.

## Install the pinned AMD verifier and policy

Every production validator starts with both CPU verification paths. There is
no TDX-only runtime mode. Download `snpguest` 0.10.0 and verify the exact
binary before starting:

```bash
install -d -m 0700 "$HOME/.local/lib/cathedral-validator"
snpguest="$HOME/.local/lib/cathedral-validator/snpguest"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$snpguest" \
  https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest
printf '%s  %s\n' \
  70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0 \
  "$snpguest" | sha256sum --check -
chmod 0500 "$snpguest"
```

The SNP policy admits only measurements and component TCB floors observed in
a reviewed hardware run. It has this exact shape:

```json
{
  "schema": "cathedral_amd_sev_snp_policy_v1",
  "generations": {
    "genoa": {
      "allowed_measurements": ["REPLACE_WITH_96_LOWERCASE_HEX"],
      "minimum_tcb": "0xREPLACE_WITH_16_LOWERCASE_HEX"
    }
  }
}
```

Replace both values with the friend-test observation, keep measurements in
sorted order, and set the file mode to `0600`. Do not add a wildcard or lower
the observed TCB to make an unknown machine pass. Missing, malformed, or
unpinned SNP configuration stops the validator before wallet or chain access.
An AMD collateral outage also blocks the weight write. A malformed or late
miner response scores only that machine zero.

## Current proof boundary

The local tests cover discovery, signed fleet enforcement, unchanged SAT,
deterministic multi-UID scoring, cooldown refusal before signing, exact-intent
persistence, ambiguous-submit recovery, and three-head stored-row confirmation.
They do not prove a production miner endpoint, production QVL availability,
validator permit, wallet funding, chain cooldown, or a live set-weights result.
