# Cathedral Validator

Cathedral Validator scores compute on Bittensor SN94 and writes weights directly
with your validator hotkey. It does not download a weight vector, use a relay,
or send your key to Cathedral.

## What it does

Each cycle, the validator:

1. Reads a finalized SN94 metagraph and finds serving miners.
2. Authenticates to each miner and requests its machine fleet.
3. Verifies Intel TDX or AMD SEV-SNP evidence and the same SAT workload.
4. Removes duplicate endpoints, TLS identities, and physical machines.
5. Gives each UID credit for its distinct verified machines, then converts those
   counts into one weight vector with zero burn.
6. Signs and submits the vector with your hotkey, then checks finalized chain
   state for the exact result.

Invalid, duplicate, or late machines receive no credit. AMD SEV-SNP machines
must match your reviewed local SNP policy. The validator release includes the
pinned TDX and SNP verifier programs.

## What you need

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Ubuntu 24.04 LTS is what Cathedral tests on.
- A hotkey registered on SN94 that holds a validator permit. The validator
  writes no weights without one. It keeps running, checks again every cycle,
  and reports `NOT_REGISTERED` or `NO_PERMIT` until the chain grants the permit
  at an epoch. A permit depends on your stake relative to other validators.
- Your Bittensor validator hotkey file and its public SS58 address, the
  `ss58Address` field inside that file. The file must be unencrypted (the
  `btcli` default for hotkeys) and readable only by its owner.
- A reviewed AMD SEV-SNP policy containing only measurements and TCB floors you
  trust. The template is in
  [Validator auto-update](docs/AUTO_UPDATE.md#before-installation).

### Machine

Two virtual CPUs, 4 GB of memory, and 20 GB of disk are enough. The validator
is light: one scoring cycle every 25 minutes, and between cycles it is idle.
Measured on the Cathedral production validator, a 4 vCPU cloud instance:

| Resource | Observed |
|---|---|
| Peak memory of the validator service | 349 MB |
| CPU time per scoring cycle | about 11 seconds |
| Disk used by the installed releases | 211 MB for three retained releases |

No GPU. No confidential-computing hardware on the validator host; the TDX and
SEV-SNP evidence it checks comes from the miners it scores.

### Network

Outbound only. The validator serves nothing and needs no inbound ports or
public address.

- The Bittensor Finney entrypoint, for finalized chain reads and your weight
  submissions.
- `raw.githubusercontent.com` and `github.com`, for the signed release channel
  and the release archives it downloads.
- Each serving SN94 miner, on the address and port it advertises on chain.
  These are arbitrary hosts and ports that change as miners come and go, so
  outbound traffic to them cannot be pinned to a fixed allowlist.

Never copy a coldkey, mnemonic, or coldkey password to the validator host. The
service receives only the hotkey file and checks it against the expected public
address before chain access.

## Install

Do not install or enable updater services from a source checkout. The install
script downloads the signed bootstrap release, verifies it against the
bootstrap signing key pinned inside the script, and installs the updater as
root-owned files. It installs no release and enables nothing. It is short.
Read it first if you want to. The bootstrap it installs, with its issue and
expiry times, is listed under
[Bootstrap trust](docs/AUTO_UPDATE.md#bootstrap-trust).

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo '7f4056ba35b4c8d836c30c363f1095d4cdd0ea0edeb3fe229d2638dd905358ef  install.sh' | sha256sum -c &&
sudo bash install.sh
```

The last line it prints is one JSON line ending in `"status":"installed"`.
If the digest line prints `FAILED`, nothing runs: the download is cached for
up to five minutes after a change, so retry after five minutes, and if it
still fails, stop and open an issue. If a check inside the script fails it
stops, changes nothing, and names the staging directory it kept for
inspection. `bootstrap manifest has expired` means the bootstrap is past its
expiry and a new one is due, not that anything was tampered with.

Then run the guided setup once with your hotkey file, its public address, and
your reviewed SNP policy, and read the local status:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --confirm-direct-write
sudo cathedral-validator-status
```

Setup installs the current signed `stable` release, starts the validator, and
enables the stable update timer. `SETUP_COMPLETE` on the last line means the
host is running. `SETUP_REFUSED` names the exact check that failed and changes
nothing.

## Operate

The validator is one recurring process. There is no alternate scoring mode and
no non-writing mode. A successful cycle prints `CONFIRMED` or
`RECOVERED_CONFIRMED` after the exact row is confirmed at inclusion and two
later finalized heads.

### Optional: TDX measurement allowlist

A TDX machine passes when its quote is genuine and current; by default any
guest image passes. To pay only guest images you have reviewed, install a
policy:

```json
{"schema": "cathedral_tdx_measurement_policy_v1",
 "mode": "shadow",
 "allowed_measurements": ["tdx-image-sha256:<64 hex>"]}
```

Entries are either `tdx-image-sha256:<64 hex>` (the v2 image identity) or
`tdx-measurement-sha256:<64 hex>` (the v1 launch measurement); a machine
passes when either of its values is listed. On GCP list the image identity:
v1 includes MROWNER, which GCP sets per VM, so every new VM of a listed image
would otherwise fail under `enforce` (cathedral-sandbox#265, docs/MRTD.md).
The currently pinned TDX verifier release does not emit the image
identity yet, so under that pin only v1 entries match; the cycle summary
reports `observed_images` once the pinned verifier emits it.

Generate it from the owner's signed measurement list with cathedral-sandbox's
`cathedral policy-registry export-measurement-policy` (`--registry`,
`--trusted-keys`, `--trusted-keys-digest`, `--state`, `--mode`, `--scope`,
`--out tdx-measurement-policy.json`; see its `--help` and the sandbox's
docs/MRTD.md). It verifies the signed release and writes the policy plus
`tdx-measurement-policy.json.source.json`, which records the release, its
digest, the policy file's digest and when the release expires. The policy
file takes no other keys; `allowed_measurements` is sorted and unique, and
`shadow` may list none. Install both files, and the env file that names the
policy, so the validator's service user can read them but not change them:

```bash
sudo install -o root -g cathedral-validator -m 0440 \
  tdx-measurement-policy.json /etc/cathedral-validator/tdx-measurement-policy.json
sudo install -o root -g cathedral-validator -m 0440 \
  tdx-measurement-policy.json.source.json \
  /etc/cathedral-validator/tdx-measurement-policy.json.source.json
sudo install -o root -g root -m 0600 \
  deploy/validator-update/direct-tdx-measurement.env.example \
  /etc/cathedral-validator/direct-tdx-measurement.env
```

Signed releases never change the systemd unit, and the unit from bootstrap
sequence 3 does not read that env file. Unless
`systemctl cat cathedral-validator-direct` shows
`EnvironmentFile=-/etc/cathedral-validator/direct-tdx-measurement.env`, add the
drop-in from
[Optional unit settings](docs/AUTO_UPDATE.md#optional-unit-settings) first.
The policy is read once, at start, so restart after installing or editing
either file, including the switch from shadow to enforce:

```bash
sudo systemctl restart cathedral-validator-direct
```

At start the service log shows
`{"tdx_measurement_policy": {"status": "LOADED", "mode": ..., "digest": ...,
"source": "recorded", "registry_release": ..., "registry_digest": ...,
"registry_valid_until": ...}}`: the
signed list release the policy was exported from, read from the
`.source.json` beside it. The record is advisory and never stops the
validator. `"source": "unrecorded"` means there is none (a hand-written
policy); `"unreadable"` means it is malformed, too large or unsafe and is
ignored, with a `warning`. A `warning` also appears when the record's
`policy_digest` is not the loaded policy's `digest` (the two files come from
different exports) or when the release's `registry_valid_until` has passed;
regenerate both files and restart. The check runs once, at start.
`"status": "NOT_LOADED"` means the env file exists but the unit does not read
it, so no policy applies. A policy that doesn't load (missing, unreadable,
malformed, or enforce with an empty list) stops the validator at start with
`TDX measurement policy refused:` and the unit retries every 15 seconds until
it is fixed.

In `"mode": "shadow"` the machines are paid as before, and each cycle's line
carries `evidence_summary.tdx_measurement`: every measurement the policy
judged this cycle, paid or not, with whether it is listed and how many
machines reported it (the 32 most common; `observed_omitted` counts the rest).
Once you have reviewed and listed them, switch to `"enforce"`: a machine whose
measurement is not listed fails with `tdx_measurement_not_allowed` and earns
zero; if it is a miner's primary, that miner's whole fleet is excluded. A
policy that admits no machine at all leaves the cycle with nothing to pay, so
it writes no weights. With a policy set, the evidence digest also binds its
mode and digest. When the source record names the loaded policy,
`evidence_summary.tdx_measurement` also carries `registry_release`; the
evidence digest does not, so it is unchanged with or without a record.

Expect more entries than images. RTMR0 follows the VM shape (vCPUs and
memory), RTMR1 the guest kernel and initrd, and RTMR3 what the guest extends
at runtime. A guest package upgrade that rebuilds the initramfs changes the
measurement while MRTD stays fixed, so under enforce a miner who patches their
guest earns zero until the new value is listed. Without the env file nothing
changes.

`sudo cathedral-validator-status` is the one local summary: service health,
signed release, update timer, and the latest recorded weight result. It does
not replace finalized chain verification. The service log is
`sudo journalctl -u cathedral-validator-direct.service -f`.

- `NOT_PROVEN` means success is unresolved. The next cycle resumes recovery
  before any new write.
- `EXPIRED_WITHOUT_INCLUSION` means the saved write reached the end of its
  mortal era without finalized inclusion. Recurring operation then moves on.
- `CONTRADICTION_STOPPED` is a deliberate terminal stop. Inspect the journal
  and finalized chain state before taking action.
- `NOT_REGISTERED` and `NO_PERMIT` mean the hotkey had no registration, or no
  validator permit, at the latest finalized block, so nothing was written. The
  validator keeps running, checks again every cycle, and starts writing on its
  own once the permit exists. The status summary reports the same result.
- `FINALIZED_FAILED_STOPPED` means a weight write was included in a finalized
  block and failed on chain. The validator stops and stays stopped. Clear it
  only with `cathedral-validator record-failed-write`, which proves the
  failure from finalized chain state before it records anything, then start
  the service. The exact steps are in
  [Failed weight write](docs/AUTO_UPDATE.md#failed-weight-write).

- `machine verification round is not fully proven` means a verifier returned
  INFRA (it could not reach a verdict: collateral, a timeout, unreadable
  output), so nothing was written and the last weights stay on chain, rather
  than zeroing machines for what may be a local outage. When the message adds
  that `CATHEDRAL_INFRA_HALT=scoped` would have written the round, the verifier
  passed another machine of that TEE kind in the same round, so it was at least
  partly working. The INFRA may still be a partial outage (Intel collateral is
  per platform, AMD's per chip, and a verifier timeout is INFRA too), or it may
  come from one miner's evidence, which today can stop every miner's weights.

  To write such rounds, opt in with a drop-in (not in `direct.env`, which
  setup compares byte for byte):

  ```
  # /etc/systemd/system/cathedral-validator-direct.service.d/infra-halt.conf
  [Service]
  Environment=CATHEDRAL_INFRA_HALT=scoped
  ```

  then `sudo systemctl daemon-reload` and restart the service. With it, an
  INFRA machine earns zero for that round, and a miner whose own axon machine
  is INFRA earns zero for its whole fleet (its fleet list is never fetched).
  In a partial outage that means honest machines lose that round's share to
  the machines that passed. A round with no PASS of an INFRA kind still halts.

Never delete or replace the journal to clear an error. The journal location,
pause and resume, and the recovery rules are in
[Validator auto-update](docs/AUTO_UPDATE.md).

For the whole path in order, from a fresh host to a confirmed weight row, see
the [Operator runbook](docs/OPERATOR_RUNBOOK.md).

## Updates

Signed releases update the validator, pinned TDX verifier, and pinned SNP
verifier together. The updater waits until the scoring cycle and write journal
are idle before it switches, and a release that fails verification or startup
keeps the last healthy one running. Public setup follows `stable` only.
Cathedral runs every release on its own canary host before publishing it to
`stable`.

Releases never replace the bootstrap updater, systemd units, host Python,
signing keys, hotkey, SNP policy, or operator configuration. Those change only
when this page publishes a new bootstrap.

## Trust

The install script pins the bootstrap signing key by fingerprint and refuses
any other key. The signed bootstrap manifest binds the exact bundle and the
runtime release key that every later release must be signed with. Setup and
the updater verify each release against that key before activating it. The
hotkey goes to the unprivileged validator service only, and never to the
updater or to Cathedral.

Two values are worth comparing against a source other than this repository
before you install: the script digest in the install block above, and the
bootstrap signing key fingerprint below. Cathedral publishes both together
with every bootstrap. The fingerprint changes only on key rotation:

```text
sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
```

The full trust boundary and what the updater can and cannot touch are in
[Validator auto-update](docs/AUTO_UPDATE.md).
