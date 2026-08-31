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

## Build the retained candidate

Run the manual `validator release candidate` workflow on the reviewed source
commit. The workflow:

- builds the project wheel twice
- resolves and builds the validator PEX twice
- downloads and verifies the exact QVL and `snpguest` binaries
- reproduces the strict runtime archive
- builds the updater wheelhouse and complete hash lock
- uploads retained inputs for 30 days
- creates GitHub build-provenance attestations for every release input

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
  --source-revision REPLACE_WITH_40_CHARACTER_COMMIT \
  --archive-out /secure/signed/cathedral-validator.tar.gz \
  --metadata-out /secure/signed/canary.json \
  --archive-url-template \
    'https://github.com/cathedralai/cathedral-validator/releases/download/validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz' \
  --sequence REPLACE_WITH_NEXT_CANARY_SEQUENCE
```

The output archive is deterministic and content-addressed. Never reuse a
sequence for different metadata.

## Validate, then publish canary

Validate the exact local archive, metadata, public key, GitHub repository, and
channel branch without writing:

```bash
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/canary.json \
  --archive /secure/signed/cathedral-validator.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem
```

Only after that succeeds, repeat with `--publish`. The publisher writes in this
order:

1. immutable GitHub release and content-addressed archive
2. anonymous archive download and digest verification
3. immutable signed channel history
4. mutable signed canary pointer
5. anonymous pointer verification

```bash
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/canary.json \
  --archive /secure/signed/cathedral-validator.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem \
  --publish
```

Observe a real canary host updating from its timer. Test activation, restart,
power-loss recovery, pause, invalid signature, archive tamper, replay,
same-sequence equivocation, unreachable metadata, busy-cycle lock, pending
writer journal, and failed readiness. Record the signed sequence, archive
digest, old and new process state, and final healthy release for each case.

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
  --archive /secure/signed/cathedral-validator.tar.gz \
  --public-key /secure/offline/runtime-release-public-key.pem
python deploy/validator-update/publish_github_channel.py \
  --metadata /secure/signed/stable.json \
  --archive /secure/signed/cathedral-validator.tar.gz \
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
  --retained-archive /secure/retained/known-good.tar.gz \
  --metadata-out /secure/signed/recovery-canary.json \
  --sequence REPLACE_WITH_HIGHER_CANARY_SEQUENCE
```

Validate and publish the recovery metadata with the same publisher. Do not
edit channel JSON by hand and do not overwrite immutable history.

## Build the signed updater bootstrap

Bootstrap releases are rare. Build one only when the updater, service units,
host requirements, or runtime release key must change. Use the candidate's exact
wheelhouse and hash lock plus the reviewed deploy assets from the same source
revision.

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
  --issued-unix REPLACE_WITH_CURRENT_UNIX_TIME \
  --lifetime-seconds 2592000
```

Publish the bundle, manifest, detached signature, and bootstrap signing public
key as immutable assets. Independently verify anonymous downloads. Record both
key fingerprints, sequence, issue time, and expiry from the signed manifest.
Then replace the generated blocks in `README.md` and `docs/AUTO_UPDATE.md` with
exact URLs, the bootstrap signing key fingerprint, authenticated minimum
bootstrap and stable sequences, and commands run successfully on a clean
live-test host. Never add a caller-supplied runtime key to the install command.

Do not publish a bootstrap guide before that host test passes. Do not claim a
runtime release updates the bootstrap layer.
