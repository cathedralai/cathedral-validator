# Validator auto-update

Status: the release channel passed live resilience testing on 2026-09-02 and
the public bootstrap artifacts are published; the README carries the exact
install commands. Do not install
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

The stable timer checks for a release after startup and every six hours, with a
randomized delay. It schedules a fresh first check whenever the timer is
re-enabled on a running host. It verifies signed metadata, sequence, expiry,
archive digest, and extracted tree before activation. It waits for the current
validator cycle and writer journal to become safe. The new release must report
ready before the update commits.

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

## Release channel

Public setup follows `stable`. Cathedral uses a separate internal canary host
to test the same signed archive before publishing its signed stable record.
Your validator never receives Cathedral wallet keys and Cathedral never
receives yours.

## Before installation

On Ubuntu 24.04, install the required host packages first:

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv openssl
```

Prepare these operator-owned inputs:

1. The hotkey file from
   `~/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY`. It must be the
   unencrypted keyfile `btcli` writes for hotkeys by default, readable only by
   its owner (mode `0600`, as `btcli` writes it), and it must contain a signing
   secret. An encrypted
   hotkey is refused because the unattended service has no password to decrypt
   it. A public-only file is refused because it cannot sign weights.
2. The public SS58 address belonging to that hotkey.
3. An owner-controlled AMD SEV-SNP policy file containing only measurements
   and TCB floors you reviewed.

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

The signed manifest also records the authenticated stable-release floor: the
minimum stable sequence and the digest of the exact signed stable record the
bootstrap was built from. The installer persists that floor and refuses any
later bootstrap that would lower it, whatever its bootstrap sequence. Until the
host commits its first stable record, that bound record stands in for it: a
different signed record at the same sequence is refused as equivocation, and a
strictly higher signed stable release is accepted as its successor. A bootstrap
therefore stays usable for new hosts after later stable publications, and
routine updates follow the monotonic signed release contract from the start.

<!-- BEGIN GENERATED UPDATER BOOTSTRAP -->
Published bootstrap, sequence 1, signed 2026-09-02T15:26:48Z, valid until
2026-10-02T15:26:48Z, immutable release tag `validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312`:

- bundle: `https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312/updater-bootstrap.tar.gz`
  (`6436995b7c6d7e1853aa52db12675c00d495f1312264df34fe2e7b822e44983c`)
- manifest: `https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312/updater-bootstrap.manifest.json`
  (`655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312`)
- signature: `https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312/updater-bootstrap.manifest.sig`
  (`7b0aaebe67411f0e0f8d32fa5fff79a331c657022af87acf761228afa23d0c5a`)
- bootstrap public key: `https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s1-655f65ceec7c4d9a0b8a7ed0389b2a4fc326d0e2958ba54bb6c6467499b5c312/bootstrap-signing-public-key.pem`
  (`390a10b2e18f1d9eeffd5146e166cc518cc13bb03c6f2784c101456d8042809e`)
- bootstrap signing key fingerprint, to be pinned independently: `sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013`
- runtime release key fingerprint bound inside the signed manifest: `sha256:56a0284790edac88e6b62e8256c43900ff3a43e590e0696c62ad224b5e0766bf`
- bootstrap sequence checkpoint: 1
- stable metadata URL: `https://raw.githubusercontent.com/cathedralai/cathedral-validator/validator-release-channel/validator/stable.json`
- authenticated stable minimum sequence: 1, bound metadata SHA-256 `e99f8b81b377677797686d4263d3e619db03e7c950f136ced3065d5fd80ff2a5`

The README's install block passes the bootstrap key only through
`--bootstrap-public-key`, its pin through `--expected-bootstrap-key-fingerprint`,
and the replay checkpoint through `--minimum-bootstrap-sequence`.
There is no runtime-key argument.
<!-- END GENERATED UPDATER BOOTSTRAP -->

## Set up and start

After installing the authenticated bootstrap, run its guided command:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --confirm-direct-write
```

The command verifies the inputs, checks that the hotkey file is an unencrypted
owner-only keyfile naming the public address you supplied, installs the signed
stable release the bootstrap was built from or a later signed stable release,
and enables only the stable update timer. It refuses files outside a Bittensor `hotkeys` directory, unsafe
existing files, or unresolved updater state. It never prints the hotkey.

Setup never starts or restarts the direct validator itself. The first signed
install starts it, and setup only records the boot dependency afterwards. If
setup is interrupted after that first start, re-run it while the validator is
still running. Once the installation is committed, a stopped validator, whether
stopped by a reboot, an operator, or a contradiction stop, makes every setup
rerun refuse. Review `sudo cathedral-validator-status`, the journal, and
finalized chain state before starting anything. The one exception is a first
install the updater never committed: re-running setup resumes the updater's own
durable recovery, which starts the writer only while the journal is idle and
never after a contradiction.

## Check it

```bash
sudo cathedral-validator-status
```

The result separates local service health, signed release state, updater state,
and the latest recorded weight result. A locally confirmed record does not by
itself prove current finalized chain state.

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
- `START_AUTHORIZED`: systemd launched the exact updater-controlled nested
  restart, and the start gate proved both updater locks and the durable
  `may_have_run` authorization still matched that one target.
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
- A first release that never reaches readiness after an updater crash is
  rescued only by a strictly higher signed stable release, never by a
  re-signed record at the same sequence.
- Do not retry a chain write whose outcome is unresolved.
- Keep the pause file in place while investigating repeated update refusal.
- A `CONTRADICTION_STOPPED` validator needs journal and finalized-chain review.

The updater has no access to the hotkey. The root updater verifies and switches
files. The unprivileged validator service alone receives the hotkey through a
systemd credential and signs its own weights.

The root-owned updater environment contains only the updater and its exact
cryptographic dependency closure. It does not install Bittensor, NumPy, or the
validator runtime dependency set. Those stay inside the signed validator PEX.

Release signing, bootstrap publication, and key custody are in
[Release maintainer guide](RELEASE_MAINTAINER.md).
