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
- Your Bittensor validator hotkey file and its public SS58 address.
- A reviewed AMD SEV-SNP policy containing only measurements and TCB floors you
  trust.

Never copy a coldkey, mnemonic, or coldkey password to the validator host. The
service receives only the hotkey file and checks it against the expected public
address before chain access.

## Install and start

The public signed bootstrap bundle is not published yet. Do not install or
enable updater services from a source checkout.

<!-- BEGIN GENERATED VALIDATOR INSTALL -->
Publication pending. This block will contain the authenticated bundle URLs,
offline bootstrap-signing-key fingerprint, bootstrap and stable sequence
checkpoints, and exact install commands after the artifacts pass live testing.
<!-- END GENERATED VALIDATOR INSTALL -->

After publication, the signed installation path will:

1. Verify the bootstrap with the separately pinned bootstrap key.
2. Install the fixed updater, service files, and bundled runtime release key.
3. Let you add the hotkey file, public hotkey address, and SNP policy.
4. Install the first signed stable release and start the validator.
5. Enable one stable-channel timer for later releases.

The detailed operator path and trust boundary are in
[Validator auto-update](docs/AUTO_UPDATE.md).

## What to expect

The validator is one recurring process. There is no alternate scoring mode and
no non-writing mode. A successful cycle prints `CONFIRMED` or
`RECOVERED_CONFIRMED` after the exact row is confirmed at inclusion and two
later finalized heads.

- `NOT_PROVEN` means success is unresolved. Keep the journal. The next cycle
  resumes recovery before any new write.
- `EXPIRED_WITHOUT_INCLUSION` means the saved write reached the end of its
  mortal era without finalized inclusion. Recurring operation then moves on.
- `CONTRADICTION_STOPPED` is a deliberate terminal stop. Inspect the saved
  intent and finalized chain state before taking action.

The journal is stored at:

```text
~/.local/state/cathedral-validator/direct-writer/
  finney-sn39-mechanism-0/<validator-hotkey>/state.json
```

Never delete or replace the journal to clear an error. The service uses
`RestartPreventExitStatus=2`, so a contradiction remains stopped for review.

## Updates

Routine signed releases update the validator, pinned TDX verifier, and pinned
SNP verifier together. The updater waits for the scoring cycle and write journal
to become safe before it switches releases. Failed verification or startup
keeps the last healthy release.

Routine releases do not replace the bootstrap updater, systemd units, host
Python, bootstrap signing key, runtime release public key, hotkey, SNP policy,
or operator configuration. Those are host trust settings and need an explicit
bootstrap migration when they change.

Each host chooses `stable` or `canary` once. The updater refuses a later channel
switch. Normal operators use `stable`. Canary is for an explicit release-test
host.
