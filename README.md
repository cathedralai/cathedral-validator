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

Use a Linux/amd64 host with CPython 3.12. The published verifier binaries do
not run on macOS or Arm hosts.

The validator needs only its Bittensor hotkey. Do not copy the coldkey,
mnemonic, or coldkey password to this host. Install this checkout in a virtual
environment, then use the reviewed verifier executables and the hotkey's
existing wallet name.

The first four commands below install the package. Before the final start
command, complete [the QVL setup](#install-the-pinned-qvl) and
[the AMD setup](#install-the-pinned-amd-verifier-and-policy).

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3.12 -m venv .venv
.venv/bin/pip install -e '.[snp-production]'
.venv/bin/cathedral-validator \
  --wallet-name YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  --expected-hotkey YOUR_HOTKEY_SS58 \
  --qvl /absolute/path/to/cathedral-tdx-verifier \
  --snpguest /absolute/path/to/snpguest \
  --snp-policy /absolute/path/to/amd-sev-snp-policy.json \
  --confirm-direct-write
```

`--expected-hotkey` is the public SS58 address for the loaded hotkey. Startup
stops before chain access if the local credential belongs to another address.
The validator opens `wallet.hotkey` only. It never reads or signs with a
coldkey. Add `--wallet-path /absolute/hotkey-only/wallets` only when the hotkey
is outside Bittensor's default wallet directory.

The runtime is pinned to Finney and SN39. It scores every serving miner. It has
no miner allowlist or alternate scoring mode. Add `--once` only for a bounded
first-launch verification. It still signs and submits one live vector, and it
exits zero only after exact finalized confirmation.

There is no non-writing launch mode. The process prints one JSON document for
each completed attempt:

- `CONFIRMED` or `RECOVERED_CONFIRMED` means the exact stored row matched at
  inclusion and two later finalized heads.
- `NOT_PROVEN` means success was not established. Read its `error`, preserve
  the journal, and do not submit a replacement for an ambiguous attempt.
- `EXPIRED_WITHOUT_INCLUSION` means recovery proved the stored signed intent
  reached the end of its mortal era without finalized inclusion. `--once`
  exits 2. Recurring mode waits, then starts the next cycle.
- `CONTRADICTION_STOPPED` is a terminal safety stop with exit status 2. Review
  the journal and finalized chain state before any restart or manual action.

For `--once`, only the two confirmed statuses exit zero. In recurring mode,
`NOT_PROVEN` waits for the next interval while `CONTRADICTION_STOPPED` exits.

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

The optional signed-release updater and the hotkey-only systemd layout are
documented in [Validator auto-update](docs/AUTO_UPDATE.md). Auto-update remains
unavailable until the reviewed public wheelhouse, hash lock, signed executable,
release archive, metadata, and public key are published. You can still run the
validator from this checkout. Do not enable updater units from the checkout.

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
no TDX-only runtime mode. Download the immutable binary from the
[snpguest 0.10.0 release](https://github.com/virtee/snpguest/releases/tag/v0.10.0)
and verify it before starting:

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
a reviewed hardware run. No shared SNP admission policy is published. Each
validator owns its allowlist.

Before starting the validator, observe a live friend-hardware run using the
[pinned AMD hardware-proof procedure](https://github.com/cathedralai/cathedral-sandbox/blob/8dde6eaca27116eed53386a1fa33ec70b74a01fb/docs/AMD_SEV_SNP_FRIEND_TEST.md)
and its exact Compute commit
`8dde6eaca27116eed53386a1fa33ec70b74a01fb`. Choose the fresh review challenge
yourself and require `LOCAL_PASS` while you observe the native guest run. Then:

1. Copy `report.measurement` into `allowed_measurements`.
2. Copy `report.reported_tcb_hex` into `minimum_tcb`.
3. Put both under the machine's Milan, Genoa, or Turin processor generation.
4. Follow the local [AMD verification rehearsal](docs/AMD_SEV_SNP_DEV_PREVIEW.md)
   and require `PROVEN_DEVELOPMENT_NO_WRITE`. It verifies that the selected
   processor generation matches the fresh report before you use the policy.

The resulting owner-controlled file has this exact shape:

```json
{
  "schema": "cathedral_amd_sev_snp_policy_v1",
  "generations": {
    "REPLACE_WITH_milan_genoa_OR_turin": {
      "allowed_measurements": ["REPLACE_WITH_96_LOWERCASE_HEX"],
      "minimum_tcb": "0xREPLACE_WITH_16_LOWERCASE_HEX"
    }
  }
}
```

Replace all three placeholders with the verified generation and observed
transcript values. Keep measurements in sorted order and set the file mode to
`0600`. Never pass the placeholder file to the validator. Do not accept an
unobserved transcript, add a wildcard, or lower the observed TCB to make an
unknown machine pass. Missing, malformed, or unpinned SNP configuration stops
the validator before wallet or chain access. An AMD collateral outage also
blocks the weight write. A malformed or late miner response scores only that
machine zero.

## Current proof boundary

The linked QVL and `snpguest` release assets are public and match the exact
SHA-256 values above.

The local tests cover discovery, signed fleet enforcement, unchanged SAT,
deterministic multi-UID scoring, cooldown refusal before signing, exact-intent
persistence, ambiguous-submit recovery, and three-head stored-row confirmation.
They do not prove a production miner endpoint, an observed live AMD policy,
validator permit, wallet funding, chain cooldown, or a live set-weights result.
