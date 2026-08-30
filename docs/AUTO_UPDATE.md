# Validator auto-update

Status: implementation candidate. Installation is not self-service or
launch-ready. No reviewed updater wheelhouse, hash lock, or signed updater
executable is published yet. Do not enable these units from a repository
checkout. The real Linux validator release gate must pass after the final SNP
runtime is integrated, and the updater installer artifacts described below
must be published from a reviewed release before an operator uses this design.

Each validator opts in on its own machine. Cathedral never receives its wallet
or hotkey. UID30 follows the signed `canary` channel. Other operators follow
the signed `stable` channel. Stable metadata identifies the exact signed canary
record and archive selected for promotion. The maintainer verifies UID30's
finalized result before performing that separate manual promotion step.

The release signing key stays on an offline release workstation. Validator
machines receive only its public key.

## Safety boundary

The direct validator holds a per-hotkey cycle lock across recovery, machine
verification, signing, submission, and confirmation. The updater waits up to
five minutes for the same lock. While holding it, the updater checks the writer
journal again, records a durable pending activation, switches `current`, and
restarts exactly `cathedral-validator-direct.service`.

The root updater never executes downloaded code. The service starts the new
release as the unprivileged `cathedral-validator` account. It receives one
hotkey through a systemd credential. It never receives a coldkey.

The service loads the pinned TDX verifier, AMD SEV-SNP policy and verifier,
wallet hotkey, chain client, process lock, and existing writer journal before
it reports `READY=1`. During an activation the updater still holds the cycle
lock, so the new process cannot begin a fresh scoring, signing, or submission
cycle before the monotonic update record commits.

An auto-updated validator binary necessarily receives the local hotkey at
runtime so it can sign weights. Opting into a release channel therefore trusts
the pinned release-signing authority over validator code. It does not disclose
the hotkey to Cathedral, but malicious signed code could misuse it locally.

If the first readiness attempt fails while the updater still holds the lock,
the updater restores and restarts the prior release. No fresh chain cycle was
able to start. If the host stops after the symlink switch, the next update
reads the pending record and completes the exact target. Crash recovery never
rolls back a target which might already have run. A later failure still needs
operator review of the journal and finalized chain state.

## What is verified

1. HTTPS metadata signed by the locally pinned Ed25519 public key.
2. A validity window no longer than 14 days.
3. A root-configured minimum bootstrap sequence, plus monotonic local state.
4. The immutable archive and deterministic extracted-tree SHA-256 digests.
5. For stable, the canary sequence, signed-payload digest, full metadata digest,
   and archive digest.
6. The final idle direct-writer journal while the full-cycle lock is held.

When the AMD production verifier loads, it also reads the signed release's
root-owned `PEX-INFO`. It requires the direct-validator entry point, locked
runtime distributions, the `snp-production` extra, and the exact Sandbox VCS
commit. Editable and development installs instead retain the PEP 610 check.

## Install the direct service

Create the `cathedral-validator` system account. Install one reviewed hotkey at
`/etc/cathedral-validator/validator-hotkey`, owned by root with mode `0600`. Do
not place a coldkey on this host or in that directory. Install the reviewed
SNP policy and pinned `snpguest` binary at the fixed paths outside every
release directory.

```bash
sudo install -o root -g root -m 0644 \
  deploy/validator-update/cathedral-validator.sysusers \
  /etc/sysusers.d/cathedral-validator.conf
sudo systemd-sysusers /etc/sysusers.d/cathedral-validator.conf
sudo install -d -o root -g root -m 0755 \
  /etc/cathedral-validator /usr/local/lib/cathedral-validator
sudo install -o root -g cathedral-validator -m 0440 \
  /absolute/reviewed/snp-policy.json \
  /etc/cathedral-validator/snp-policy.json
sudo install -o root -g cathedral-validator -m 0550 \
  /absolute/reviewed/snpguest \
  /usr/local/lib/cathedral-validator/snpguest
sudo install -o root -g root -m 0644 \
  deploy/validator-update/cathedral-validator-direct.service \
  /etc/systemd/system/cathedral-validator-direct.service
sudo install -o root -g root -m 0600 \
  deploy/validator-update/direct.env.example \
  /etc/cathedral-validator/direct.env
sudo systemctl daemon-reload
```

Do not start the direct service yet. Its first release does not exist. The
bootstrap below installs that release, creates the service-owned idle journal
and cycle lock, then waits for readiness. The service copies only the hotkey
into an ephemeral runtime wallet. Its persistent home stores the writer
journal and locks, not wallet files. PEX expands executable code only under
`/run/cathedral-validator-pex`. Systemd deletes and recreates that owner-only
runtime directory on every service restart, so an older release cannot seed a
persistent executable cache for its successor.

## Maintainer integration contract

This section defines the acceptance contract for the future public installer.
It is not an operator installation path today. A release must publish the
reviewed wheelhouse and matching `updater-requirements.lock` before these
commands become usable. The lock must hash-pin the reviewed validator wheel,
`cryptography`, and every transitive installer dependency.

The updater lives in a retained root-owned environment outside every home
directory. The unit executes this environment directly. It never depends on a
source checkout or user venv hidden by `ProtectHome=true`.

```bash
sudo /usr/bin/python3.12 -m venv \
  /usr/local/lib/cathedral-validator-updater
sudo /usr/local/lib/cathedral-validator-updater/bin/python -m pip install \
  --no-index --require-hashes \
  --find-links /absolute/reviewed/updater-wheelhouse \
  --requirement /absolute/reviewed/updater-requirements.lock
sudo test "$(head -n 1 /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update)" = \
  '#!/usr/local/lib/cathedral-validator-updater/bin/python'
```

Install `update.env.example` as root-owned mode `0600`. Set the exact hotkey
journal path and an authenticated minimum sequence from the signed release
record. Install the signing public key at:

```text
/etc/cathedral-validator/update-public-key.pem
```

Install the two update services and timers in `/etc/systemd/system`, reload
systemd, then run exactly one first-install bootstrap. For a normal validator:

```bash
sudo install -o root -g root -m 0600 \
  deploy/validator-update/update.env.example \
  /etc/cathedral-validator/update.env
sudo install -o root -g root -m 0644 \
  /absolute/reviewed/update-public-key.pem \
  /etc/cathedral-validator/update-public-key.pem
sudo install -o root -g root -m 0644 \
  deploy/validator-update/cathedral-validator-update.service \
  deploy/validator-update/cathedral-validator-update.timer \
  deploy/validator-update/cathedral-validator-canary-update.service \
  deploy/validator-update/cathedral-validator-canary-update.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
```

Edit `update.env` before continuing. Then run the bootstrap with the same URL,
journal, and authenticated minimum sequence:

```bash
sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update \
  --bootstrap-first-install \
  --channel stable \
  --metadata-url https://releases.cathedral.com/validator/stable.json \
  --public-key /etc/cathedral-validator/update-public-key.pem \
  --journal /var/lib/cathedral-validator/.local/state/cathedral-validator/direct-writer/finney-sn39-mechanism-0/YOUR_HOTKEY/state.json \
  --minimum-sequence YOUR_AUTHENTICATED_STABLE_SEQUENCE
```

UID30 uses `--channel canary`, the canary metadata URL, and the authenticated
canary sequence. The command refuses an existing current release or committed
channel state. On success it prints `CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED`.
Then enable the direct service and one timer only:

```bash
# UID30
sudo systemctl enable cathedral-validator-direct.service
sudo systemctl enable --now cathedral-validator-canary-update.timer

# Other independent validators
sudo systemctl enable cathedral-validator-direct.service
sudo systemctl enable --now cathedral-validator-update.timer
```

The readiness result proves initialization and journal recovery completed
before a fresh cycle. It does not prove a successful evidence round or chain
write. Confirm those from the validator journal and finalized on-chain state.

## Optional private telemetry

Telemetry stays off when
`/etc/cathedral-validator/direct-telemetry.env` is absent. To opt in, first
install the separate telemetry account, spool directory, and exporter. Then
install `direct-telemetry.env.example` at that path, root-owned mode `0600`,
and restart the direct service.

The optional file expands to exactly `--telemetry-spool` and
`--telemetry-reader-group`. It contains no endpoint or token. Only the
separate unprivileged exporter reads the collector token. An absent or empty
optional file adds no validator argument and leaves startup unchanged.

## Build and sign a canary offline

Build on a reviewed linux/amd64 release workstation with CPython 3.12. PEX
`2.101.1` first creates a strict dependency lock, including the pinned
`snp-production` Compute contract, then produces one relocatable zipapp. Build
it twice from the same commit and require identical SHA-256 output before
signing.

```bash
export SOURCE_DATE_EPOCH=0
python3.12 -m pip wheel --no-cache-dir --no-deps \
  /absolute/reviewed/cathedral-validator \
  --wheel-dir /absolute/reviewed/project-wheels-one
# Repeat into project-wheels-two and require the two wheel files to be identical.
export VALIDATOR_WHEEL=/absolute/reviewed/project-wheels-one/cathedral_scaffold-RELEASE_VERSION-py3-none-any.whl
uvx --from pex==2.101.1 pex3 lock create \
  --style strict \
  "cathedral-scaffold[snp-production] @ file://${VALIDATOR_WHEEL}" \
  'cathedral @ git+https://github.com/cathedralai/cathedral-sandbox.git@8dde6eaca27116eed53386a1fa33ec70b74a01fb' \
  --python /usr/bin/python3.12 \
  --interpreter-constraint 'CPython==3.12.*' \
  --no-build \
  --indent 2 \
  --output /absolute/reviewed/validator.pex.lock
uvx --from pex==2.101.1 pex \
  --lock /absolute/reviewed/validator.pex.lock \
  --python /usr/bin/python3.12 \
  --interpreter-constraint 'CPython==3.12.*' \
  --entry-point cathedral_thin.independent_runtime.direct_validator:main \
  --validate-entry-point \
  --inherit-path=false \
  --no-compile \
  --strip-pex-env \
  --python-shebang '/usr/bin/python3.12' \
  --output-file /absolute/reviewed/cathedral-validator.pex
chmod 0555 /absolute/reviewed/cathedral-validator.pex
```

The signer rejects an arbitrary directory, virtual environment, shell
wrapper, absolute virtualenv shebang, missing production extra, missing exact
Compute VCS requirement, inherited site-packages, or any entry point other
than the direct validator. The private Ed25519 PEM must be owner-only. Never
copy it to a validator.

The required `Real validator release` CI job repeats this build from the
reviewed source, requires byte-identical output, passes the artifact through
the offline signer's bundle validation and fixed-tree extraction, imports the
pinned production Compute contract and SNP verifier from inside the PEX, and
requires the packaged validator to reach its pre-write readiness boundary.
Fixture-only tests do not satisfy this release gate.

```bash
python deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/release-key.pem canary \
  --pex /absolute/reviewed/cathedral-validator.pex \
  --archive-out /absolute/public/validator-1.2.3.tar.gz \
  --metadata-out /absolute/public/canary.json \
  --archive-url https://releases.example/validator-1.2.3.tar.gz \
  --sequence 12
```

The builder reads the version from the locked Cathedral wheel, creates the
fixed release tree and deterministic archive, computes both digests, signs a
seven-day canary record, and verifies its output before writing it.

## Promote the same canary offline

After UID30 testing, promote the exact signed canary file. The builder verifies
the file and copies its exact release fields. It does not rebuild the archive.
This cryptographically proves artifact identity, not that UID30 completed a
successful live cycle. The maintainer must verify UID30's finalized result
before running this manual promotion step.

```bash
python deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/release-key.pem stable \
  --canary-metadata /absolute/public/canary.json \
  --metadata-out /absolute/public/stable.json \
  --sequence 8
```

Publish the archive and metadata as immutable HTTPS objects. Never overwrite a
sequence with different content.

## Pause updates

```bash
sudo install -o root -g root -m 0600 /dev/null \
  /etc/cathedral-validator/update.pause
```

Remove the file to resume checks.
