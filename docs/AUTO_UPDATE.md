# Validator auto-update

Status: the release channel is implemented and is undergoing live resilience
testing. The public bootstrap artifacts are not published yet. Do not install
or enable updater units from a source checkout.

The repository home page is the only operator install guide. This page explains
why the updater is safe, what it changes, and what to inspect when recovery is
in progress.

This guide is for an independent validator operator. Your validator keeps its
own hotkey, computes its own weights, and signs its own chain writes.

## What updates automatically

One signed runtime release contains all three of these:

- the Cathedral validator
- the pinned Intel TDX verifier
- the pinned AMD SEV-SNP verifier

The stable timer checks for a release every six hours, with a randomized delay.
It verifies signed metadata, sequence, expiry, archive digest, and extracted tree
before activation. It waits for the current validator cycle and writer journal
to become safe. The new release must report ready before the update commits.

If verification or a normal startup attempt fails, the prior healthy release
remains active. If power is lost after a new release was authorized to start, a
boot gate will not roll back code that might have run. It reconciles durable
state before the validator starts. A later, higher signed sequence pointing to
a different archive repairs an activation whose execution became uncertain.

These host trust settings do not change in a routine release:

- bootstrap updater and systemd units
- CPython and other host packages
- offline bootstrap signing key
- runtime release public key
- validator hotkey
- AMD SEV-SNP policy
- operator environment files

Changing one of those items requires a separately authenticated bootstrap
migration. Routine validator and verifier changes do not require operator
action.

## Choose one channel

Use `stable` for a normal validator. `canary` is for a dedicated release-test
host.

The first installation records this choice. It is immutable for that host. The
updater refuses metadata from the other channel. Do not delete updater state to
force a switch. Use a new host for a different channel.

## Before installation

On Ubuntu 24.04, install the required host packages first:

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv openssl
```

Prepare these operator-owned inputs:

1. The hotkey file from
   `~/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY`.
2. The public SS58 address belonging to that hotkey.
3. A root-owned AMD SEV-SNP policy at
   `/etc/cathedral-validator/snp-policy.json`.

Do not place the coldkey file, mnemonic, or coldkey password on this host.

The SNP policy admits only hardware you have reviewed. There is no wildcard or
shared default policy. Its shape is:

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

Use `milan`, `genoa`, or `turin` only when it matches the reviewed report. Keep
measurements sorted. Never use the placeholder values, accept an unobserved
measurement, add a wildcard, or lower the observed TCB floor to admit a machine.

## Bootstrap trust

The bootstrap uses two distinct Ed25519 keys. You independently obtain and pin
the rare offline bootstrap signing public key and its fingerprint. That key
authenticates the bootstrap manifest. The signed manifest binds the exact
runtime release public key inside the bundle. The installer accepts no caller
replacement for the runtime key. It checks the signature, both fingerprints,
manifest, file set, and wheel hashes before installing anything. It installs no
release and enables no service by itself.

<!-- BEGIN GENERATED UPDATER BOOTSTRAP -->
Publication pending. The exact copy and paste install commands will be added to
`README.md` only after live testing with:

- immutable bundle, manifest, signature, and bootstrap-public-key URLs
- the independently authenticated bootstrap signing key fingerprint
- the bootstrap sequence checkpoint and signed issue and expiry times
- the runtime release key fingerprint bound inside the signed manifest
- the current stable metadata URL and authenticated minimum sequence
- exact download, verification, extraction, and install commands

When those values are published, the install command must pass the bootstrap
key only through `--bootstrap-public-key`, its pin through
`--expected-bootstrap-key-fingerprint`, and the replay checkpoint through
`--minimum-bootstrap-sequence`. There is no runtime-key argument.

Until those values are present, public installation is closed.
<!-- END GENERATED UPDATER BOOTSTRAP -->

After a successful bootstrap install, the signed examples are under:

```text
/usr/local/share/cathedral-validator-updater/examples/
```

The updater executable is:

```text
/usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update
```

## Operator inputs

Install the hotkey file, policy, and signed configuration examples. Replace
every placeholder and set the authenticated minimum sequences before
continuing.

```bash
sudo install -o root -g root -m 0600 \
  "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  /etc/cathedral-validator/validator-hotkey
sudo install -o root -g cathedral-validator -m 0440 \
  /absolute/reviewed/amd-sev-snp-policy.json \
  /etc/cathedral-validator/snp-policy.json
sudo install -o root -g root -m 0600 \
  /usr/local/share/cathedral-validator-updater/examples/direct.env.example \
  /etc/cathedral-validator/direct.env
sudo install -o root -g root -m 0600 \
  /usr/local/share/cathedral-validator-updater/examples/identity.env.example \
  /etc/cathedral-validator/identity.env
sudo install -o root -g root -m 0600 \
  /usr/local/share/cathedral-validator-updater/examples/update.env.example \
  /etc/cathedral-validator/update.env
sudoedit /etc/cathedral-validator/identity.env
sudoedit /etc/cathedral-validator/update.env
```

`identity.env` contains only the public SS58 address. `update.env` contains the
published channel URLs and authenticated minimum sequences. Neither contains a
wallet key.

## First signed start

After the bootstrap is published and installed, run one first-install activation
using the exact stable URL and minimum sequence published on `README.md`:

```bash
sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update \
  --bootstrap-first-install \
  --channel=stable \
  --metadata-url=REPLACE_WITH_PUBLISHED_STABLE_URL \
  --public-key=/etc/cathedral-validator/runtime-release-public-key.pem \
  --identity-file=/etc/cathedral-validator/identity.env \
  --minimum-sequence=REPLACE_WITH_AUTHENTICATED_STABLE_SEQUENCE
```

Do not guess either replacement value. The command refuses a host with an
existing release or committed channel. On success it installs the signed
release and starts the direct validator through the boot safety gate.

Enable the service and stable timer for future boots and releases:

```bash
sudo systemctl enable cathedral-validator-direct.service
sudo systemctl enable --now cathedral-validator-update.timer
```

Never enable both update timers.

## Confirm operation

```bash
sudo systemctl status cathedral-validator-direct.service
sudo systemctl status cathedral-validator-update.timer
sudo systemctl list-timers cathedral-validator-update.timer
sudo journalctl -u cathedral-validator-direct.service -n 100 --no-pager
sudo journalctl -u cathedral-validator-update.service -n 100 --no-pager
sudo journalctl -u cathedral-validator-boot-reconcile.service -n 100 --no-pager
```

The updater reports one of these normal results:

- `CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED`: a new archive became active.
- `CATHEDRAL_VALIDATOR_UPDATE_CURRENT`: the current signed record is unchanged.
- `CATHEDRAL_VALIDATOR_UPDATE_ADVANCED`: newer signed metadata renewed the
  current archive without a restart.
- `CATHEDRAL_VALIDATOR_UPDATE_PAUSED`: the pause file blocked new fetches or
  activations after pending recovery became safe.
- `CATHEDRAL_VALIDATOR_UPDATE_REFUSED`: a safety check failed. The message states
  which check failed.

Updater success proves release activation and startup readiness. It does not
prove a successful scoring round or chain write. Confirm those separately from
the validator status and finalized chain state.

The boot and start gates report these control results:

- `RECONCILED`: the host restarted while an update outcome was uncertain, and
  the boot reconcile service finished the durable recovery checks.
- `START_AUTHORIZED`: the validator start gate verified there is no unresolved
  updater state blocking a normal validator start.
- `PAUSED`: the updater saw `/etc/cathedral-validator/update.pause` and skipped
  fetching a new release. It does not hide unresolved recovery.

## Pause and resume

Pause new release fetches and activations:

```bash
sudo install -o root -g root -m 0600 /dev/null \
  /etc/cathedral-validator/update.pause
```

The validator keeps running. Boot reconciliation and recovery of an already
pending activation also keep running. The pause applies only after pending state
is safe. If recovery is still unresolved, the updater keeps reconciling and the
start gate still blocks unsafe starts.

Resume updates:

```bash
sudo rm /etc/cathedral-validator/update.pause
```

## Recovery rules

- Do not delete the validator journal or updater state.
- Do not replace the `current` link by hand.
- Do not run both channel timers.
- Do not retry a chain write whose outcome is unresolved.
- Keep the pause file in place while investigating repeated update refusal.
- A `CONTRADICTION_STOPPED` validator needs journal and finalized-chain review.

The updater has no access to the hotkey. The root updater verifies and switches
files. The unprivileged validator service alone receives the hotkey through a
systemd credential and signs its own weights.

## Maintainer notes

Use one offline bootstrap signing key for the rare bootstrap bundle and a
separate runtime release signing key for routine validator releases. Keep each
private key encrypted at rest. Keep at least two offline encrypted backups. Keep
the passphrase record separate from the encrypted key files. Before production
signing, restore one backup on a clean machine, confirm it derives the expected
public fingerprint, and sign and verify a fixed test message.

Routine validator and verifier releases are unattended after bootstrap. Changes
to the bootstrap updater, systemd units, host Python, bootstrap key, or bundled
runtime release public key are explicit bootstrap migrations.

Common release commands:

```bash
python3 deploy/validator-update/build_updater_bundle.py \
  --wheelhouse /secure/bootstrap/wheelhouse \
  --requirements /secure/bootstrap/requirements.txt \
  --bootstrap-signing-private-key /secure/bootstrap/bootstrap-signing-private.pem \
  --bootstrap-signing-public-key /secure/bootstrap/bootstrap-signing-public.pem \
  --runtime-release-public-key /secure/runtime/runtime-release-public.pem \
  --assets-dir /secure/bootstrap/assets \
  --bundle-out /secure/bootstrap/updater-bootstrap.tar.gz \
  --manifest-out /secure/bootstrap/updater-bootstrap.manifest.json \
  --signature-out /secure/bootstrap/updater-bootstrap.manifest.sig \
  --sequence 7 \
  --lifetime-seconds 604800
```

```bash
python3 deploy/validator-update/install_updater_bundle.py \
  --bundle /secure/bootstrap/updater-bootstrap.tar.gz \
  --manifest /secure/bootstrap/updater-bootstrap.manifest.json \
  --signature /secure/bootstrap/updater-bootstrap.manifest.sig \
  --bootstrap-public-key /secure/bootstrap/bootstrap-signing-public.pem \
  --expected-bootstrap-key-fingerprint sha256:REPLACE_WITH_BOOTSTRAP_FINGERPRINT \
  --minimum-bootstrap-sequence 7
```

```bash
python3 deploy/validator-update/build_signed_release.py \
  --private-key /secure/runtime/runtime-release-private.pem \
  canary \
  --pex /secure/candidate/cathedral-validator.pex \
  --qvl /secure/candidate/cathedral-tdx-verifier \
  --snpguest /secure/candidate/snpguest \
  --runtime-lock /secure/candidate/runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock \
  --runtime-distributions /secure/candidate/runtime/cathedral-validator.pex-distributions.json \
  --source-revision REPLACE_WITH_GIT_SHA \
  --archive-out-dir /secure/signed \
  --metadata-out /secure/signed/canary.json \
  --archive-url-template https://github.com/cathedralai/cathedral-validator/releases/download/validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz \
  --sequence 41 \
  --lifetime-seconds 604800
```

The signed archive written by `--archive-out-dir` is content addressed. Publish
the printed digest-named tarball, not a renamed copy.
