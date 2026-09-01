# Validator release maintainer guide

This is for the small group that builds, signs, tests, and publishes Cathedral
validator releases. It is not an operator installation guide.

## Trust boundary

Two distinct Ed25519 private keys stay off GitHub Actions, validator hosts,
cloud VMs, and the repository.

- The runtime release key signs routine canary and stable metadata.
- The rarer offline bootstrap key signs the updater bootstrap manifest.

Operators authenticate the bootstrap public key and fingerprint outside the
bundle. That signed bootstrap binds and installs the exact runtime release
public key. The installer has no caller option to replace it. Keep separate
encrypted backups and separately recorded fingerprints. Rotation of either key
is a bootstrap migration, not a routine runtime release.

Routine validator and verifier releases are unattended after bootstrap.

Before production signing:

1. Generate each private key encrypted at rest.
2. Keep at least two offline encrypted backups of each key.
3. Store the passphrase record separately from the encrypted key files.
4. Restore one backup on a clean machine.
5. Confirm it derives the expected public fingerprint.
6. Sign and verify a fixed test message before using the key on a release.

## Build the retained candidate

Run the manual `validator release candidate` workflow on the reviewed source
commit. The workflow:

- installs release tools and the Setuptools build backend only from the
  committed CPython 3.12, Ubuntu 24.04 x86_64 hash lock
- builds the project wheel twice
- resolves and builds the validator PEX twice
- downloads and verifies the exact QVL and `snpguest` binaries
- reproduces the strict runtime archive
- downloads the updater's three third-party wheels against a separate committed
  hash lock, then adds only the reproduced local project-wheel hash
- uploads retained inputs for 30 days
- creates GitHub build-provenance attestations for every release input

Project-wheel builds use the pinned backend with build isolation disabled and
network access refused. A downloaded backend or a third-party wheel whose bytes
do not match the committed review hash stops the candidate build.

Download the artifact named
`cathedral-validator-release-inputs-<SOURCE_REVISION>`. Verify every file against
`INPUTS.json`, then verify each GitHub attestation against
`cathedralai/cathedral-validator`. Refuse unsigned, missing, mismatched, or
unattested inputs.

## Sign the canary offline

Use absolute owner-controlled paths. The signer rejects symlinks, unsafe modes,
an unpinned runtime, an unsupported entry point, or a malformed source
revision. Verify the supplied source revision against the workflow artifact
before signing.

```bash
python deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  canary \
  --pex /secure/candidate/runtime/cathedral-validator.pex \
  --qvl /secure/candidate/runtime/cathedral-tdx-verifier \
  --snpguest /secure/candidate/runtime/snpguest \
  --runtime-lock /secure/candidate/runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock \
  --runtime-distributions /secure/candidate/runtime/cathedral-validator.pex-distributions.json \
  --source-revision REPLACE_WITH_40_CHARACTER_COMMIT \
  --archive-out-dir /secure/signed \
  --metadata-out /secure/signed/canary.json \
  --archive-url-template \
    'https://github.com/cathedralai/cathedral-validator/releases/download/validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz' \
  --sequence REPLACE_WITH_NEXT_CANARY_SEQUENCE \
  --lifetime-seconds 604800
```

The output archive is deterministic and content-addressed. Publish the printed
digest-named tarball from `/secure/signed`. Never rename it and never reuse a
sequence for different metadata.

By default the signer accepts archive URLs only from
`cathedralai/cathedral-validator`. A disposable live-test mirror must be named
explicitly with `--expected-archive-repository OWNER/TEST_MIRROR` on canary,
recovery, and stable signing. Use the same exact lower-case repository value in
all three commands. URLs, `.git` suffixes, case aliases, and redirect targets
are refused. The live acceptance controller performs this compatibility check
during preflight before it creates a VM.

## Validate, then publish canary

Validate the exact local archive, metadata, public key, GitHub repository, and
channel branch without writing. Run the script from the reviewed checkout. It
does not require an editable install or `PYTHONPATH`:

```bash
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/canary.json \
  --archive /secure/signed/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem
```

Before adding `--publish`, the repository must be public and an administrator
must enable GitHub immutable releases. The publishing identity needs release
write access and `Administration` repository read access for the
immutable-release setting. The
publisher refuses if the setting is unavailable or disabled.

Only after validation succeeds, repeat with `--publish`. The publisher writes
in this order:

1. create an empty release draft
2. upload and verify the exact content-addressed archive
3. publish and verify the immutable release and tag
4. anonymously download and verify the archive
5. atomically commit immutable signed history and the mutable canary pointer
6. anonymously verify the pointer

An interrupted retry resumes an exact empty or fully uploaded draft. It refuses
partial or different draft assets and never overwrites them.
Raw pointer verification uses cache-busted bounded retries but still requires
the exact signed bytes. If a pointer is missing on an existing branch, the next
release must exceed a stable set of retained signed history. An exact retained
record resumes an interrupted pointer write. An empty initial branch resumes
only at its exact source commit. Missing, invalid, duplicated, deleted, or
changing history stops publication. History and pointer move in one commit with
a non-force branch compare-and-swap, so a concurrent lower sequence loses.

```bash
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/canary.json \
  --archive /secure/signed/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem \
  --publish
```

Observe a real canary host updating from its timer. Test activation, restart,
power-loss recovery, pause, invalid signature, archive tamper, replay,
same-sequence equivocation, unreachable metadata, busy-cycle lock, pending
writer journal, and failed readiness. Record the signed sequence, archive
digest, old and new process state, and final healthy release for each case.

### Run the bounded live acceptance controller

The committed controller performs this matrix with disposable signing keys and
two automatically deleted Ubuntu hosts. It never loads a wallet or runs a
validator cycle. It reads commits and attestations from this repository, but it
refuses to publish test releases or hostile fault pointers here. All GitHub
writes go to a separate public test mirror with immutable releases enabled.

Mirror both reviewed commits first and make the mirror's `main` point to release
B. Download and unpack both attested candidate artifacts, then run the read-only
preflight from a clean checkout at release B. The authenticated `gcloud`
identity must have `serviceusage.services.list`, IAP tunnel access, the required
Compute permissions to read, provision, reset, and tear down the disposable
resources, and both `iap.googleapis.com` and
`cloudresourcemanager.googleapis.com` enabled in the test project. The
controller always uses authenticated IAP. It refuses a direct-IP transport and
does not attach a service account to either test host.

```bash
env \
  RUN_ID=REPLACE_WITH_UNIQUE_RUN_ID \
  CANDIDATE_A_DIR=/secure/candidate-a \
  CANDIDATE_B_DIR=/secure/candidate-b \
  SOURCE_REVISION_A=REPLACE_WITH_MERGED_RELEASE_A_SHA \
  SOURCE_REVISION_B=REPLACE_WITH_MERGED_RELEASE_B_SHA \
  EVIDENCE_DIR=/secure/empty-live-test-evidence \
  TEST_GITHUB_REPOSITORY=cathedralai/cathedral-validator-release-e2e \
  BUDGET_USD=2.00 \
  ./scripts/live_validator_update_e2e.sh --preflight
```

Run the identical environment with `--execute` only after preflight prints
`PREFLIGHT_PASS`. Success is `LIVE_UPDATE_E2E_PASS`, followed by
`TEARDOWN_COMPLETE`. The controller returns failure unless both hosts, boot
disks, firewall, subnet, and network are proven absent. The test mirror's
branches and immutable prerelease remain public as the audit record.

## Promote the exact canary

Promote only the exact canary metadata that passed the live test. Promotion
copies its release fields and adds the signed canary identity. It does not
rebuild the archive.

```bash
python deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  stable \
  --canary-metadata /secure/signed/canary.json \
  --metadata-out /secure/signed/stable.json \
  --sequence REPLACE_WITH_NEXT_STABLE_SEQUENCE
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/stable.json \
  --archive /secure/signed/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/stable.json \
  --archive /secure/signed/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem \
  --publish
```

Observe a separate stable host activate the identical archive digest through
its timer before calling the release complete.

## Recover with a retained release

If a canary activation becomes execution-uncertain, issue a strictly higher
canary sequence for a different retained archive. The signer verifies the
current canary, retained signed record, retained archive, and content-addressed
URL before it signs.

```bash
python deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  resign-canary \
  --current-canary-metadata /secure/signed/current-canary.json \
  --retained-metadata /secure/retained/known-good.json \
  --retained-archive /secure/retained/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --metadata-out /secure/signed/recovery-canary.json \
  --sequence REPLACE_WITH_HIGHER_CANARY_SEQUENCE \
  --lifetime-seconds 604800
```

Validate and publish the recovery metadata with the same publisher. Do not
edit channel JSON by hand and do not overwrite immutable history.

## Build the signed updater bootstrap

Bootstrap releases are rare. Build one only when the updater, service units,
host requirements, or runtime release key must change. Use the candidate's exact
wheelhouse and hash lock plus the reviewed deploy assets from the same source
revision.

The privileged updater environment intentionally contains only the Cathedral
project wheel, `cryptography`, `cffi`, and `pycparser`. It does not contain
Bittensor or NumPy. Those validator dependencies stay in the signed runtime PEX.
The candidate workflow proves the isolated updater import and command before the
wheelhouse becomes a retained signing input.

```bash
python deploy/validator-update/build_updater_bundle.py \
  --wheelhouse /secure/candidate/updater-wheelhouse \
  --requirements /secure/candidate/updater-requirements.lock \
  --bootstrap-signing-private-key \
    /secure/offline/bootstrap-signing-private-key.pem \
  --bootstrap-signing-public-key \
    /secure/offline/bootstrap-signing-public-key.pem \
  --runtime-release-public-key \
    /secure/offline/runtime-release-public-key.pem \
  --assets-dir /absolute/reviewed/deploy/validator-update \
  --bundle-out /secure/signed/updater-bootstrap.tar.gz \
  --manifest-out /secure/signed/updater-bootstrap.manifest.json \
  --signature-out /secure/signed/updater-bootstrap.manifest.sig \
  --sequence REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE \
  --lifetime-seconds 2592000
```

The target repository must be public and have GitHub immutable releases
enabled. The publishing identity needs release write access and permission to
read that setting through `Administration` repository read access. The
publisher refuses a repository without this enforcement. It authenticates the
signed bundle against the externally pinned bootstrap key, publishes one exact
four-asset release, checks its immutable GitHub record and tag target, then
downloads every asset anonymously and compares the bytes.

Validate the test release without writing:

```bash
python deploy/validator-update/publish_github_bootstrap.py \
  --bundle /secure/signed/updater-bootstrap.tar.gz \
  --manifest /secure/signed/updater-bootstrap.manifest.json \
  --signature /secure/signed/updater-bootstrap.manifest.sig \
  --bootstrap-public-key \
    /secure/offline/bootstrap-signing-public-key.pem \
  --expected-bootstrap-key-fingerprint \
    sha256:REPLACE_WITH_BOOTSTRAP_FINGERPRINT \
  --minimum-bootstrap-sequence REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE \
  --repository OWNER/DISPOSABLE_TEST_REPOSITORY \
  --track test \
  --target-revision REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT
```

Repeat the identical command with `--publish` only after validation succeeds.
The disposable test repository must be a public fork or mirror containing the
exact target commit. It must also have immutable releases enabled.
After the live test passes, publish the same four local files with `--track
production` and `--repository cathedralai/cathedral-validator`, again validating
before adding `--publish`.

Bootstrap publication has no mutable branch or pointer. Test and production use
separate content-addressed tags. An identical retry is idempotent. An existing
tag, release, target, or asset set with different state is an equivocation and
the publisher refuses it. It never fills a partial asset set or replaces an
asset.

An interrupted retry resumes only an exact empty or fully uploaded draft. A
partial or different draft remains refused for manual investigation.

Record both key fingerprints, sequence, issue time, expiry, exact tag, target
revision, and manifest digest. Then replace the generated block in `README.md`
with exact URLs, the bootstrap signing key fingerprint, authenticated minimum
bootstrap and stable sequences, and commands run successfully on a clean
live-test host.

Install the published bootstrap on the live-test host as root with:

```bash
sudo /usr/bin/python3.12 deploy/validator-update/install_updater_bundle.py \
  --bundle /secure/signed/updater-bootstrap.tar.gz \
  --manifest /secure/signed/updater-bootstrap.manifest.json \
  --signature /secure/signed/updater-bootstrap.manifest.sig \
  --bootstrap-public-key /secure/offline/bootstrap-signing-public-key.pem \
  --expected-bootstrap-key-fingerprint sha256:REPLACE_WITH_BOOTSTRAP_FINGERPRINT \
  --minimum-bootstrap-sequence REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE
```

Never add a caller-supplied runtime key to the install command.

Do not publish a bootstrap guide before that host test passes. Do not claim a
runtime release updates the bootstrap layer.
