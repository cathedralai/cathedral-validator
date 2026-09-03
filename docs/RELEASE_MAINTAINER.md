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
6. anonymously verify the exact commit-pinned pointer
7. wait for the mutable branch pointer to serve the same bytes

An interrupted retry resumes an exact empty or fully uploaded draft. It refuses
partial or different draft assets and never overwrites them.
GitHub raw branch URLs advertise a five-minute cache and ignore query strings
for cache selection. The publisher first proves the immutable commit URL. It
then waits through the full advertised cache lifetime plus one minute and
confirms the fixed branch URL serves the same bytes from the publisher's
anonymous network vantage. This does not claim global CDN observation. It does
prevent a successful publication before an old response's advertised lifetime
has elapsed. A refusal includes only digests and outcome counts and is safe to
retry. Signed metadata must retain enough life for both bounded checks and an
additional five-minute publication margin.
Validation applies this headroom even without `--publish`, so a dry check does
not approve metadata too old for a later write. The publisher checks lifetime
again before moving the channel and again before reporting success. If slow
release preparation consumes the margin, it can leave the immutable release
and tag published while refusing to move the channel. These margins are
admission headroom, not promises that external GitHub operations finish within
that time. Re-sign a higher sequence that references the same content-addressed
archive, then retry.

If the final lifetime check refuses after pointer verification, the channel has
already moved to metadata that is now expired. Updaters reject it and retain
their current installed release. New installs can fail until recovery. Re-sign
the same content-addressed archive with a higher sequence and fresh lifetime,
then publish it immediately. Never replay or edit the expired signed bytes.
If a pointer is missing on an existing branch, the next release must exceed a
stable set of retained signed history. An exact retained record resumes an
interrupted pointer write. An empty initial branch resumes only at its exact
source commit. Missing, invalid, duplicated, deleted, or changing history stops
publication. History and pointer move in one commit with a non-force branch
compare-and-swap, so a concurrent lower sequence loses.

```bash
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/canary.json \
  --archive /secure/signed/cathedral-validator-REPLACE_WITH_ARCHIVE_SHA256.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem \
  --publish
```

Observe a real canary host updating from its timer. Test activation, restart,
same-boot timer disable and re-enable, power-loss recovery, pause, invalid
signature, archive tamper, replay, same-sequence equivocation, unreachable
metadata, busy-cycle lock, pending writer journal, and failed readiness. Record
the signed sequence, archive digest, old and new process state, and final
healthy release for each case.

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

The stable host follows the public operator path only. The controller stages a
disposable bittensor-wallet hotkey and a reviewed SNP policy as operator inputs,
runs the installed `cathedral-validator-setup` from the signed bootstrap, proves
that the setup never printed hotkey material, reads
`cathedral-validator-status --json` after the first install and after the stable
timer activates the promoted release, proves an idempotent setup rerun changes
nothing, and finally proves that a setup rerun refuses a stopped writer and that
status reports `NEEDS_REVIEW`. The signed test bootstrap carries the reviewed
deploy assets with only the two channel URLs rewritten to the run's isolated
mirror branches. The canary host uses the internal direct-updater path, which is
not a public operating mode. The disposable hotkey is never registered and never
written to evidence.

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
`PREFLIGHT_PASS`. Success prints `TEARDOWN_COMPLETE`, followed by
`LIVE_UPDATE_E2E_PASS`. The controller returns failure unless both hosts, boot
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
  --stable-release-metadata /secure/signed/current-stable.json \
  --assets-dir /absolute/reviewed/deploy/validator-update \
  --bundle-out /secure/signed/updater-bootstrap.tar.gz \
  --manifest-out /secure/signed/updater-bootstrap.manifest.json \
  --signature-out /secure/signed/updater-bootstrap.manifest.sig \
  --sequence REPLACE_WITH_NEXT_BOOTSTRAP_SEQUENCE \
  --lifetime-seconds 2592000
```

The builder verifies `current-stable.json` with the runtime release public key
and embeds its exact sequence as the first-install rollback floor. Do not enter
the sequence by hand.

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
revision, and manifest digest. Then regenerate `scripts/install.sh` by
substituting only the per-publication values below into the script already in
the tree. Never retype or reconstruct the script from the release artifacts.
Every other line is fixed text that carries the staging hardening, and
reconstructing the script is how that hardening gets silently reverted.

Substitute only these:

- the `BASE=` release tag
- the tarball, manifest, and signature digests in the `sha256sum` list
- the `--minimum-bootstrap-sequence` argument
- in `docs/AUTO_UPDATE.md`, the generated bootstrap block: sequence, issue and
  expiry timestamps, immutable tag, asset URLs and digests, runtime release
  key fingerprint, and stable floor sequence and digest

Leave everything else byte for byte, including the `mktemp` staging
assignment, the `cleanup` function and its path guard, the `trap` that keeps
the staging directory when a check fails, every `"$BOOTSTRAP_DIR/..."` path,
the two-column `printf` form, the quoted heredoc that checks the bundle
against the signed manifest, the `sh -c` argument form used for extraction,
and the trailing `cleanup` and `trap - ERR`.

Then pin the regenerated script on the README: replace the digest in its
`sha256sum -c` line with the SHA-256 of the new `scripts/install.sh`. The
README and the script land in one commit, so `main` is always self-consistent.
`raw.githubusercontent.com` caches for up to five minutes, so an operator who
fetches within minutes of the merge can see one digest mismatch; a retry
resolves it.

The bootstrap signing key digest and its fingerprint are not per-publication
values. They change only on key rotation. Do not retype them as if they
rotate with each bootstrap; the public key file digest in the `sha256sum`
list and the DER SPKI fingerprint on the `test` line are different values and
neither changes when a bootstrap is republished.

A regenerated script that fails `tests/thin/test_operator_docs_safety.py`
means the hardening was dropped or the README digest was not updated. Fix the
script or the pin. Do not relax the test.

Verify on a clean live-test host before publishing the guide, with
`/var/tmp/cathedral-bootstrap` pre-planted as a world-writable directory
holding a symlink to a file you can check afterwards. The install must
succeed and that file must be untouched.

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
