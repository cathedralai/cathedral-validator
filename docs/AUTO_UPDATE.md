# Validator auto-update

Status: the release channel is implemented and is undergoing live resilience
testing. The public bootstrap artifacts are not published yet. Do not install
or enable updater units from a source checkout.

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
- release public key
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

## Install the signed bootstrap

The bootstrap is an offline bundle with a signed manifest. Before execution,
the operator verifies it with an independently obtained Ed25519 public key and
published key fingerprint. The signed installer checks the same signature,
fingerprint, manifest, file set, and wheel hashes again. It installs no release
and enables no service by itself.

<!-- BEGIN GENERATED UPDATER BOOTSTRAP -->
Publication pending. Replace this block only after live testing with:

- immutable bundle, manifest, signature, and public-key URLs
- the independently authenticated public-key fingerprint
- the current stable metadata URL and authenticated minimum sequence
- exact download, verification, extraction, and install commands

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

## Add your operator inputs

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

## Install the first stable release

Run one first-install activation using the exact stable URL and minimum sequence
published in the generated bootstrap block above:

```bash
sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update \
  --bootstrap-first-install \
  --channel=stable \
  --metadata-url=REPLACE_WITH_PUBLISHED_STABLE_URL \
  --public-key=/etc/cathedral-validator/update-public-key.pem \
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
```

The updater reports one of these normal results:

- `CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED`: a new archive became active.
- `CATHEDRAL_VALIDATOR_UPDATE_CURRENT`: the current signed record is unchanged.
- `CATHEDRAL_VALIDATOR_UPDATE_ADVANCED`: newer signed metadata renewed the
  current archive without a restart.
- `CATHEDRAL_VALIDATOR_UPDATE_PAUSED`: pending recovery completed, then no new
  release was fetched or activated.
- `CATHEDRAL_VALIDATOR_UPDATE_REFUSED`: a safety check failed. The message states
  which check failed.

Updater success proves release activation and startup readiness. It does not
prove a successful scoring round or chain write. Confirm those separately from
the validator status and finalized chain state.

## Pause and resume

Pause new release fetches and activations:

```bash
sudo install -o root -g root -m 0600 /dev/null \
  /etc/cathedral-validator/update.pause
```

The validator keeps running. Boot reconciliation and recovery of an already
pending activation also keep running. The pause applies only after pending state
is safe.

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

Release signing and publication are documented separately in
[Release maintainer guide](RELEASE_MAINTAINER.md).
