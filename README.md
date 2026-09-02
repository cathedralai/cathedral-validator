# Cathedral Validator

Cathedral Validator scores compute on Bittensor SN39 and writes weights directly
with your validator hotkey. It does not download a weight vector, use a relay,
or send your key to Cathedral.

## What it does

Each cycle, the validator:

1. Reads a finalized SN39 metagraph and finds serving miners.
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
- Your Bittensor validator hotkey file and its public SS58 address. The file
  must be unencrypted (the `btcli` default for hotkeys) and readable only by
  its owner.
- A reviewed AMD SEV-SNP policy containing only measurements and TCB floors you
  trust.

Never copy a coldkey, mnemonic, or coldkey password to the validator host. The
service receives only the hotkey file and checks it against the expected public
address before chain access.

## Install and start

Install only from the signed bootstrap below. Do not install or enable updater
services from a source checkout.

<!-- BEGIN GENERATED VALIDATOR INSTALL -->
Bootstrap sequence 1, signed 2026-09-02T15:26:48Z, valid until 2026-10-02T15:26:48Z.
Immutable release tag: `validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312`.

Pin these two fingerprints from a Cathedral announcement or another channel you
trust before you run anything. The installer refuses a bootstrap key whose
fingerprint differs from the one you pass.

- Bootstrap signing key: `sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013`
- Runtime release key bound inside the signed manifest: `sha256:56a0284790edac88e6b62e8256c43900ff3a43e590e0696c62ad224b5e0766bf`
- Stable floor bound by this bootstrap: sequence 1, metadata SHA-256
  `e99f8b81b377677797686d4263d3e619db03e7c950f136ced3065d5fd80ff2a5`

Download, verify, and install the signed bootstrap as root-owned files:

```bash
set -euo pipefail
sudo apt-get update && sudo apt-get install -y ca-certificates curl openssl python3.12 python3.12-venv
BASE=https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312
sudo install -d -o root -g root -m 0700 /var/tmp/cathedral-bootstrap
for f in updater-bootstrap.tar.gz updater-bootstrap.manifest.json updater-bootstrap.manifest.sig bootstrap-signing-public-key.pem; do
  sudo curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "/var/tmp/cathedral-bootstrap/$f" "$BASE/$f"
done
printf '%s\n' \
  '6436995b7c6d7e1853aa52db12675c00d495f1312264df34fe2e7b822e44983c  /var/tmp/cathedral-bootstrap/updater-bootstrap.tar.gz' \
  '655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312  /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.json' \
  '7b0aaebe67411f0e0f8d32fa5fff79a331c657022af87acf761228afa23d0c5a  /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.sig' \
  '390a10b2e18f1d9eeffd5146e166cc518cc13bb03c6f2784c101456d8042809e  /var/tmp/cathedral-bootstrap/bootstrap-signing-public-key.pem' \
  | sudo sha256sum --check --strict
test "sha256:$(sudo openssl pkey -pubin -in /var/tmp/cathedral-bootstrap/bootstrap-signing-public-key.pem -outform DER | sha256sum | cut -d' ' -f1)" = sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
sudo openssl pkeyutl -verify -pubin -inkey /var/tmp/cathedral-bootstrap/bootstrap-signing-public-key.pem \
  -rawin -in /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.json \
  -sigfile /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.sig
sudo sh -c 'tar -xOf /var/tmp/cathedral-bootstrap/updater-bootstrap.tar.gz payload/installer/install_updater_bundle.py > /var/tmp/cathedral-bootstrap/install_updater_bundle.py'
sudo /usr/bin/python3.12 /var/tmp/cathedral-bootstrap/install_updater_bundle.py \
  --bundle /var/tmp/cathedral-bootstrap/updater-bootstrap.tar.gz \
  --manifest /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.json \
  --signature /var/tmp/cathedral-bootstrap/updater-bootstrap.manifest.sig \
  --bootstrap-public-key /var/tmp/cathedral-bootstrap/bootstrap-signing-public-key.pem \
  --expected-bootstrap-key-fingerprint sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013 \
  --minimum-bootstrap-sequence 1
```

The installer prints one JSON line ending in `"status":"installed"` and enables
nothing. Then run the guided setup once with your hotkey file, its public
address, and your reviewed SNP policy, and read the local status:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --confirm-direct-write
sudo cathedral-validator-status
```

Setup installs the signed stable release at or above sequence 1 from
`https://raw.githubusercontent.com/cathedralai/cathedral-validator/validator-release-channel/validator/stable.json`,
starts the validator, and enables only the stable update timer. `SETUP_COMPLETE`
on the last line means the host is running. `SETUP_REFUSED` names the exact
check that failed and changes nothing.
<!-- END GENERATED VALIDATOR INSTALL -->

The signed installation path:

1. Verify the bootstrap with the separately pinned bootstrap key.
2. Install the fixed updater, service files, and bundled runtime release key.
3. Run one guided setup command with your hotkey file, its public address, and
   your reviewed SNP policy.
4. Install the first signed stable release, start the validator, and enable its
   stable update timer.

The detailed operator path and trust boundary are in
[Validator auto-update](docs/AUTO_UPDATE.md).

## What to expect

The validator is one recurring process. There is no alternate scoring mode and
no non-writing mode. A successful cycle prints `CONFIRMED` or
`RECOVERED_CONFIRMED` after the exact row is confirmed at inclusion and two
later finalized heads.

`sudo cathedral-validator-status` gives one local summary of the validator,
signed release, update timer, and latest recorded weight result. It does not
replace finalized chain verification.

- `NOT_PROVEN` means success is unresolved. Keep the journal. The next cycle
  resumes recovery before any new write.
- `EXPIRED_WITHOUT_INCLUSION` means the saved write reached the end of its
  mortal era without finalized inclusion. Recurring operation then moves on.
- `CONTRADICTION_STOPPED` is a deliberate terminal stop. Inspect the saved
  intent and finalized chain state before taking action.

The journal is stored at:

```text
/var/lib/cathedral-validator/.local/state/cathedral-validator/
  direct-writer/finney-sn39-mechanism-0/<validator-hotkey>/state.json
```

Never delete or replace the journal to clear an error. The service uses
`RestartPreventExitStatus=2`, so a contradiction remains stopped for review.
If the host reboots during an update, inspect
`cathedral-validator-boot-reconcile.service` before taking action.

## Updates

Routine signed releases update the validator, pinned TDX verifier, and pinned
SNP verifier together. The updater waits for the scoring cycle and write journal
to become safe before it switches releases. Failed verification or startup
keeps the last healthy release.

Routine releases do not replace the bootstrap updater, systemd units, host
Python, bootstrap signing key, runtime release public key, hotkey, SNP policy,
or operator configuration. Those are host trust settings and need an explicit
bootstrap migration when they change.

Public setup follows `stable` only. Cathedral tests the same signed release on
its separate canary host before publishing it to `stable`. Both paths passed
live testing end to end on 2026-09-02 before this bootstrap was published.
