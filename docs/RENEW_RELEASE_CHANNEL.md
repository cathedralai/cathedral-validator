# Renew the validator release channel

Three signed things expire. When they do, hosts refuse them, and nothing
renews them automatically. This page gives the key holder the shortest correct
command sequence for each renewal. The full rules are in the
[Release maintainer guide](RELEASE_MAINTAINER.md).

Every `file:line` below is at `main` = `eb1264f`. This change moves lines only
in `updater.py` after line 789, in `cathedral-validator-status`, and in
`docs/AUTO_UPDATE.md` after line 182. **[Unverified]**
marks a claim that code in this repository cannot settle.

## What expires

| Artifact | Published at | Now | Longest lifetime | Refused by | Signing key |
|---|---|---|---|---|---|
| canary metadata | `validator/canary.json` on branch `validator-release-channel` | seq 4, expired 2026-09-15T21:06:38Z | 14 days (`updater.py:58`) | updater (`updater.py:272-273`) | runtime release key |
| stable metadata | `validator/stable.json` on the same branch | seq 3, expired 2026-09-15T21:26:27Z | 14 days | updater | runtime release key |
| bootstrap manifest | release `validator-bootstrap-production-s2-1a55c6c2…` (`scripts/install.sh:12`) | seq 2, expires 2026-10-03T00:00:04Z (`docs/AUTO_UPDATE.md:121-122`) | 90 days (`install_updater_bundle.py:52`) | installer (`install_updater_bundle.py:596-597`) | bootstrap key |

The sequences and dates above were read from the channel branch at `1e9dba3`
and from the published manifest. Its bytes match the digest that
`scripts/install.sh:28` pins.

What breaks:

- Expired channel metadata: every update check is refused before anything is
  touched (`updater.py:1968-1975`, `:2254-2256`). Running validators keep
  running their installed release. First installs fail too, because setup runs
  the updater against the stable record (`cathedral-validator-setup:763-774`).
- Expired bootstrap: `scripts/install.sh` fails on every new host. The updater
  never reads the bootstrap expiry, so running hosts are not affected.

The alarm `scripts/check_release_expiry.py` reads all three from where hosts and
the installer read them. It fails from 5 days before any expiry. It runs daily in
`.github/workflows/release-expiry.yml`. While it fails, a second job keeps one
open issue, "Release channel expiry alarm", assigned to the key holder (the
repository variable `RELEASE_EXPIRY_ASSIGNEE`, default `wallscaler`), and adds a
comment each failing day, so GitHub emails the assignee. It closes the issue
when the check passes again. That job checks out nothing and holds only
`issues: write`.

## Machines, keys, and files

- **Offline signer.** It holds both private keys (`RELEASE_MAINTAINER.md:8-12`)
  and a checkout of this repository. It needs Python 3 with `cryptography`
  (`build_signed_release.py:29-34`). An encrypted key prompts for its
  passphrase (`build_signed_release.py:420-425`, `build_updater_bundle.py:275-276`).
  **[Unverified]** what software the owner's signer has.
- **Connected host.** It has `git`, `curl`, Python 3 with `cryptography`, and a
  `gh` login with release write and `Administration` read on
  `cathedralai/cathedral-validator` (`RELEASE_MAINTAINER.md:107-111`,
  `publish_github_channel.py:411-417`). It never holds a private key.
- Moving files between the two is the owner's own procedure. **[Unverified]**
- Every input must be owned by the invoking user and not group- or
  world-writable. Paths must be absolute
  (`build_signed_release.py:509-547`, `publish_github_channel.py:140-156`,
  `build_updater_bundle.py:210-258`). Run `umask 077` first on both machines.
- The updater refuses metadata issued more than 300 s in its future
  (`updater.py:270-271`). Check `date -u` on the signer before signing.

On the connected host:

```bash
umask 077
mkdir -p /secure/renew /secure/signed
git clone https://github.com/cathedralai/cathedral-validator.git "$HOME/cv"
git -C "$HOME/cv" bundle create /secure/renew/cv.bundle main
```

On the signer, with `cv.bundle` carried over:

```bash
umask 077
mkdir -p /secure/renew /secure/signed
git clone /secure/renew/cv.bundle "$HOME/cv"
```

Make a fresh bundle after B1 so that it contains the candidate commit.

## Case (a): re-sign current stable and canary, no rebuild

The tooling already allows this, so no new tool was needed.

- `resign-canary` signs a strictly higher canary sequence over the exact
  release fields of a retained record (`build_signed_release.py:1266-1336`).
  - It loads expired inputs at their own issue time (`:1171-1179`).
  - It refuses a sequence that does not exceed the current canary (`:1286-1297`).
  - It re-verifies the archive bytes and tree before signing (`:1303-1309`, `:1088-1114`).
  - It refuses any change to the archive URL or the archive, tree, or entrypoint digest (`:1328-1334`).
- `stable` promotion copies that canary's release and binds its signed record
  (`:1371-1378`). It needs the canary to be valid when it signs (`:1356-1364`),
  so it must come after `resign-canary`.
- Lifetime is 60 s to 14 days (`:1117-1127`), the same limit the updater
  enforces (`updater.py:58`, `:259-268`).
- The signer on `main` accepts the published archive. Between the archive's
  release tag commit `9538938` and `eb1264f`, nothing changed in
  `deploy/validator-update/`, `updater.py`, or `requirements/`. This was checked
  with `git diff` in this change.
- Hosts on the same archive take the renewed record as `ADVANCED`, with no
  restart (`updater.py:2007-2037`). Fresh installs accept it: the bootstrap's
  stable floor is sequence 2 (`docs/AUTO_UPDATE.md:136`, `updater.py:1976-1992`).
- Test: `tests/thin/test_signed_release_builder.py::test_expired_channel_renews_without_rebuild_within_updater_limits`.
- The A2 and A3 commands and A4's no-write validation were also run through
  their command lines with a throwaway key and a synthetic expired release.
  They printed the outputs listed below.

**A1. Fetch the inputs.** Connected host, no key.

```bash
ARCHIVE=c3c6a541927c2d28858dd5dc33ab8f9a37707ebed63124884bc6071b33a701c2
git -C "$HOME/cv" fetch origin validator-release-channel
git -C "$HOME/cv" show origin/validator-release-channel:validator/canary.json > /secure/renew/canary-4.json
git -C "$HOME/cv" show origin/validator-release-channel:validator/stable.json > /secure/renew/stable-3.json
curl -fsSL --proto '=https' --tlsv1.2 -o "/secure/renew/cathedral-validator-$ARCHIVE.tar.gz" \
  "https://github.com/cathedralai/cathedral-validator/releases/download/validator-$ARCHIVE/cathedral-validator-$ARCHIVE.tar.gz"
sha256sum /secure/renew/canary-4.json /secure/renew/stable-3.json "/secure/renew/cathedral-validator-$ARCHIVE.tar.gz"
```

- Source: the channel paths are in `publish_github_channel.py:49`, `:106-118`. The URL rule is `build_signed_release.py:602-637`.
- Output: three files.
- Check: the digests must be `f081e0de…` (canary seq 4), `569cf7ce…` (stable seq 3), and `$ARCHIVE`. These are the history file names on the branch, `validator/history/<channel>/<seq>-<sha256>.json` (`publish_github_channel.py:106-110`).
- If a digest differs, the channel has moved since this page was written. Stop, read the sequences it now shows, and use each one plus one in A2 and A3.

**A2. Re-sign canary as sequence 5.** Offline signer, runtime release key.

```bash
cd "$HOME/cv"
python3 deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  resign-canary \
  --current-canary-metadata /secure/renew/canary-4.json \
  --retained-metadata /secure/renew/canary-4.json \
  --retained-archive /secure/renew/cathedral-validator-c3c6a541927c2d28858dd5dc33ab8f9a37707ebed63124884bc6071b33a701c2.tar.gz \
  --metadata-out /secure/signed/canary-5.json \
  --sequence 5 \
  --lifetime-seconds 1209600
```

- Source: `RELEASE_MAINTAINER.md:255-265`. The CLI is `build_signed_release.py:1422-1434`, `:1485-1496`.
- Output: `/secure/signed/canary-5.json`. Success prints nothing and exits 0. A refusal prints `release build refused: …` (`:1508-1509`).
- `1209600` is the 14-day maximum. The guide's default is `604800`. The owner decides.

**A3. Promote it to stable sequence 4.** Offline signer, runtime release key.

```bash
python3 deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  stable \
  --canary-metadata /secure/signed/canary-5.json \
  --metadata-out /secure/signed/stable-4.json \
  --sequence 4 \
  --lifetime-seconds 1209600
python3 - /secure/signed/canary-5.json /secure/signed/stable-4.json <<'PY'
import json, sys, time
for path in sys.argv[1:]:
    s = json.load(open(path))["signed"]
    print(s["channel"], s["sequence"], s["release"]["archive_sha256"],
          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s["expires_unix"])))
PY
```

- Source: `RELEASE_MAINTAINER.md:227-233`. The CLI is `build_signed_release.py:1435-1445`, `:1497-1507`.
- Output: `/secure/signed/stable-4.json`.
- Check: the lines read `canary 5 c3c6a541…` and `stable 4 c3c6a541…`, each expiring 14 days out.
- `promote_stable` does not compare against the old stable sequence. The publisher (`publish_github_channel.py:1096-1100`) and every host (`updater.py:821-838`) refuse one that does not advance.

**A4. Publish canary 5, then stable 4.** Connected host, no private key.

Copy `canary-5.json`, `stable-4.json`, and the runtime release public key from
the signer. Then run:

```bash
bash -euo pipefail <<'A4'
cd "$HOME/cv"
PUB=/secure/renew/runtime-release-public-key.pem
test "sha256:$(openssl pkey -pubin -in "$PUB" -outform DER | sha256sum | cut -d' ' -f1)" = \
  sha256:56a0284790edac88e6b62e8256c43900ff3a43e590e0696c62ad224b5e0766bf
TGZ=/secure/renew/cathedral-validator-c3c6a541927c2d28858dd5dc33ab8f9a37707ebed63124884bc6071b33a701c2.tar.gz
for m in canary-5 stable-4; do
  python3 deploy/validator-update/publish_github_channel.py --metadata "/secure/signed/$m.json" --archive "$TGZ" --public-key "$PUB"
  python3 deploy/validator-update/publish_github_channel.py --metadata "/secure/signed/$m.json" --archive "$TGZ" --public-key "$PUB" --publish
done
A4
```

The block runs in a child `bash -euo pipefail`, so the first failure stops it
and leaves your shell open. B2, C2, and C5 work the same way.

- Source: `RELEASE_MAINTAINER.md:100-105`, `:156-162`, `:234-242`. The key fingerprint is `docs/AUTO_UPDATE.md:133`, checked the same way as `scripts/install.sh:32`.
- Output: for each record, `CATHEDRAL_VALIDATOR_RELEASE_VALIDATED_NO_WRITE channel=… sequence=…`, then `CATHEDRAL_VALIDATOR_RELEASE_PUBLISHED … channel_revision=<sha>` (`publish_github_channel.py:1191-1201`).
- Validation runs the updater's own verifier (`:289-294`). It refuses metadata with 760 s (about 13 minutes) or less of life left (`:78-86`, `:295-301`).
- The existing immutable release for this archive is reused, not re-uploaded (`:538-568`).
- Each publish waits at least six minutes for the cached branch URL to serve the new bytes (`:59-63`, `:1137-1142`).

**A5. Check.** Connected host:

```bash
python3 scripts/check_release_expiry.py
```

- Expect `OK:` for stable seq 4 and canary seq 5. From 2026-09-28T00:00:04Z the bootstrap line reads `EXPIRES SOON` until case (c) is done.
- On a canary host and on a stable host, run
  `sudo systemctl start cathedral-validator-canary-update.service` (canary) or
  `sudo systemctl start cathedral-validator-update.service` (stable). Then run
  `journalctl -u <that unit> -n 3 -o cat`. Expect `CATHEDRAL_VALIDATOR_UPDATE_ADVANCED`
  (`updater.py:2037`, `:2257`), then `sudo cathedral-validator-status`.
  **[Unverified]** live; the code path is covered by
  `tests/thin/test_updater.py::test_higher_metadata_for_current_archive_advances_without_restart`.

## Case (b): cut a new release with merged fixes

Merge the fixes first. Then take one reviewed commit on `main` through the full
path. The same candidate also feeds case (c).

**B1. Build the candidate.** Connected host.

```bash
gh workflow run release-candidate.yml --repo cathedralai/cathedral-validator --ref main
gh run list --repo cathedralai/cathedral-validator --workflow release-candidate.yml --limit 1
RUN=REPLACE_WITH_RUN_ID
gh run watch "$RUN" --repo cathedralai/cathedral-validator --exit-status
SHA=$(gh run view "$RUN" --repo cathedralai/cathedral-validator --json headSha -q .headSha)
gh run download "$RUN" --repo cathedralai/cathedral-validator \
  -n "cathedral-validator-release-inputs-$SHA" -D /secure/candidate
```

- Source: the workflow is manual-only (`release-candidate.yml:3-4`). The artifact is `cathedral-validator-release-inputs-<sha>`, kept for 30 days (`:275-280`, `RELEASE_MAINTAINER.md:31-55`).
- **[Unverified]** the `gh` subcommands and flags. They are standard `gh` CLI, not code in this repository.

**B2. Verify the candidate.** Connected host.

```bash
SHA="$SHA" bash -euo pipefail <<'B2'
cd /secure/candidate
python3 - "$SHA" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path("/secure/candidate")
m = json.loads((root / "INPUTS.json").read_text())
names = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} - {"INPUTS.json"}
assert m["schema"] == "cathedral_validator_release_inputs_v1" and m["source_revision"] == sys.argv[1]
assert names == set(m["files"]), sorted(names ^ set(m["files"]))
for name, digest in m["files"].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
print("INPUTS_OK", m["source_revision"])
PY
for f in INPUTS.json *.whl runtime/* updater-requirements.lock updater-wheelhouse/*.whl; do
  gh attestation verify "$f" --repo cathedralai/cathedral-validator >/dev/null || { echo "UNATTESTED $f"; exit 1; }
done
chmod 0755 runtime/cathedral-validator.pex runtime/cathedral-tdx-verifier runtime/snpguest
echo CANDIDATE_OK
B2
```

- Source: the `INPUTS.json` format is `release-candidate.yml:251-271`. The attested files are `:282-291`. The rule is `RELEASE_MAINTAINER.md:51-55`.
- Check: `INPUTS_OK <SHA>` and then `CANDIDATE_OK` print.
- The `chmod` restores the executable bit the workflow set (`release-candidate.yml:233-238`). The signer needs it (`build_signed_release.py:534`, `:760-761`). **[Unverified]** that a downloaded artifact loses file modes.

**B3. Sign the canary.** Offline signer, runtime release key. Check out
`$SHA`, because the signer checks the runtime lock against the checkout
(`build_signed_release.py:693-695`). Set `NEXT_CANARY` to the current canary
sequence plus one: 6 if case (a) ran, else 5.

```bash
SHA=REPLACE_WITH_CANDIDATE_COMMIT_FROM_B1
NEXT_CANARY=REPLACE_WITH_CURRENT_CANARY_SEQUENCE_PLUS_ONE
cd "$HOME/cv" && git checkout "$SHA"
python3 deploy/validator-update/build_signed_release.py \
  --private-key /secure/offline/runtime-release-private-key.pem \
  canary \
  --pex /secure/candidate/runtime/cathedral-validator.pex \
  --qvl /secure/candidate/runtime/cathedral-tdx-verifier \
  --snpguest /secure/candidate/runtime/snpguest \
  --runtime-lock /secure/candidate/runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock \
  --runtime-distributions /secure/candidate/runtime/cathedral-validator.pex-distributions.json \
  --source-revision "$SHA" \
  --archive-out-dir /secure/signed \
  --metadata-out "/secure/signed/canary-$NEXT_CANARY.json" \
  --archive-url-template \
    'https://github.com/cathedralai/cathedral-validator/releases/download/validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz' \
  --sequence "$NEXT_CANARY" \
  --lifetime-seconds 1209600
```

- Source: `RELEASE_MAINTAINER.md:64-80`.
- Output: it prints the path of the new `cathedral-validator-<archive sha256>.tar.gz` (`build_signed_release.py:1484`).

**B4. Publish the canary.** Connected host. Use A4's two publisher commands
with the new metadata and the new archive (`RELEASE_MAINTAINER.md:100-105`,
`:156-162`). This time the publisher creates the immutable release
(`publish_github_channel.py:540-564`).

**B5. Accept the canary.** Watch a canary host activate it
(`RELEASE_MAINTAINER.md:164-169`): `journalctl` shows
`CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED`, and `sudo cathedral-validator-status`
reads `OPERATING_CONFIRMED`. The bounded live controller is optional
(`:171-219`); how much of it to run is the owner's call. **[Unverified]** live.

**B6. Promote and publish stable.** Run A3 with
`--canary-metadata "/secure/signed/canary-$NEXT_CANARY.json"` and the current
stable sequence plus one. Then run A4 for that stable file with the new archive
(`RELEASE_MAINTAINER.md:227-243`). If the canary expired during acceptance,
re-sign it first with A2, because promotion needs a valid canary
(`build_signed_release.py:1356-1364`).

## Case (c): new bootstrap before 2026-10-03T00:00:04Z

Two things must exist first:

- A fresh stable record from case (a) or (b). The bootstrap builder refuses an
  expired one (`build_updater_bundle.py:767-771`, `:549-552`).
- A verified candidate from B1-B2. The bootstrap needs its updater wheelhouse
  and lock, plus deploy assets from the same revision
  (`RELEASE_MAINTAINER.md:272-275`). The builder also takes the installer from
  its own checkout (`build_updater_bundle.py:660-668`).

The updater layer is identical at the current bootstrap's source `c9e15fb`, at
`9538938`, and at `eb1264f`: nothing changed in `deploy/validator-update/`,
`updater.py`, or `requirements/`. So a candidate from `main` changes nothing
functionally. **[Unverified]** whether the owner still holds the candidate
inputs used for bootstrap sequence 2.

**C1. Build and sign bootstrap sequence 3.** Offline signer, bootstrap key.
Copy the verified `/secure/candidate` and `stable-4.json` (or the case (b)
stable record) to the signer.

```bash
SHA=REPLACE_WITH_CANDIDATE_COMMIT_FROM_B1
cd "$HOME/cv" && git checkout "$SHA"
python3 deploy/validator-update/build_updater_bundle.py \
  --wheelhouse /secure/candidate/updater-wheelhouse \
  --requirements /secure/candidate/updater-requirements.lock \
  --bootstrap-signing-private-key /secure/offline/bootstrap-signing-private-key.pem \
  --bootstrap-signing-public-key /secure/offline/bootstrap-signing-public-key.pem \
  --runtime-release-public-key /secure/offline/runtime-release-public-key.pem \
  --stable-release-metadata /secure/signed/stable-4.json \
  --assets-dir "$HOME/cv/deploy/validator-update" \
  --bundle-out /secure/signed/updater-bootstrap.tar.gz \
  --manifest-out /secure/signed/updater-bootstrap.manifest.json \
  --signature-out /secure/signed/updater-bootstrap.manifest.sig \
  --sequence 3 \
  --lifetime-seconds 2592000
```

- Source: `RELEASE_MAINTAINER.md:283-299`. The CLI is `build_updater_bundle.py:896-929`. The three outputs must not exist yet (`:839-843`).
- Output: one JSON line (`build_updater_bundle.py:963-978`).
- Check: `bootstrap_signing_key_fingerprint` is `sha256:9339edab…6013` (`scripts/install.sh:32`).
- Check: `runtime_release_key_fingerprint` is `sha256:56a02847…66bf` (`docs/AUTO_UPDATE.md:133`).
- Check: `stable_release_minimum_sequence` is the stable sequence you just published.
- `2592000` is 30 days, as in the guide. The cap is 90 days (`build_updater_bundle.py:47`). The owner decides.

**C2. Publish to a disposable test repository.** Connected host. Copy the
three outputs and `bootstrap-signing-public-key.pem`.

```bash
SHA="$SHA" REPO=OWNER/DISPOSABLE_TEST_REPOSITORY TRACK=test bash -euo pipefail <<'C2'
cd "$HOME/cv" && git checkout "$SHA"
BOOT=(--bundle /secure/signed/updater-bootstrap.tar.gz
  --manifest /secure/signed/updater-bootstrap.manifest.json
  --signature /secure/signed/updater-bootstrap.manifest.sig
  --bootstrap-public-key /secure/signed/bootstrap-signing-public-key.pem
  --expected-bootstrap-key-fingerprint sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
  --minimum-bootstrap-sequence 3 --target-revision "$SHA"
  --repository "$REPO" --track "$TRACK")
python3 deploy/validator-update/publish_github_bootstrap.py "${BOOT[@]}"
python3 deploy/validator-update/publish_github_bootstrap.py "${BOOT[@]}" --publish
C2
```

- Source: `RELEASE_MAINTAINER.md:316-333`.
- Validation runs the installer's own `verify_bundle` (`publish_github_bootstrap.py:242-257`).
- Output: `CATHEDRAL_VALIDATOR_BOOTSTRAP_VALIDATED_NO_WRITE`, then `…_PUBLISHED track=test sequence=3 tag=validator-bootstrap-test-s3-<manifest sha256> …` (`:732-737`, tag format `:74-76`).
- **[Unverified]** that a public test mirror with immutable releases and the target commit exists.

**C3. Install gate on a clean test host.** Run the root install command in
`RELEASE_MAINTAINER.md:397-405` against the four files. Pre-plant
`/var/tmp/cathedral-bootstrap` as `:390-393` says. The install must succeed
and the planted file must stay untouched. **[Unverified]** live. The guide
requires this before publishing the operator page; skipping it is the owner's
decision.

**C4. Publish to production.** Connected host.

```bash
SHA="$SHA" REPO=cathedralai/cathedral-validator TRACK=production bash -euo pipefail <<'C4'
cd "$HOME/cv" && git checkout "$SHA"
BOOT=(--bundle /secure/signed/updater-bootstrap.tar.gz
  --manifest /secure/signed/updater-bootstrap.manifest.json
  --signature /secure/signed/updater-bootstrap.manifest.sig
  --bootstrap-public-key /secure/signed/bootstrap-signing-public-key.pem
  --expected-bootstrap-key-fingerprint sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
  --minimum-bootstrap-sequence 3 --target-revision "$SHA"
  --repository "$REPO" --track "$TRACK")
python3 deploy/validator-update/publish_github_bootstrap.py "${BOOT[@]}"
python3 deploy/validator-update/publish_github_bootstrap.py "${BOOT[@]}" --publish
C4
```

- Source: `RELEASE_MAINTAINER.md:334-336`.
- Output: `…_PUBLISHED track=production sequence=3 tag=validator-bootstrap-production-s3-<manifest sha256>`.

**C5. Point `install.sh`, the generated block, and the README at it.**
Connected host, repository write, no key. Only the per-publication values
change (`RELEASE_MAINTAINER.md:347-378`). The bootstrap key digest and its
fingerprint stay the same (`:380-384`).

```bash
bash -euo pipefail <<'C5'
cd "$HOME/cv" && git checkout main && git pull --ff-only && git checkout -b bootstrap-s3
OLD_SEQ=2 OLD_ISSUED=2026-09-03T00:00:04Z OLD_EXPIRES=2026-10-03T00:00:04Z
OLD_MANIFEST=1a55c6c2a9a4d1a4328288e045def747a3a22ce9a742f49dca1895ca4c940e7e
OLD_BUNDLE=a9c4a083f42988d1d2cbadf5daf95f7aec57fc24caa2d1acb46335fc0ce70319
OLD_SIG=1102f2b98f9de575479a0065033cb3ba2fa9e052d01406ce9a185d9ee20e2121
OLD_STABLE_SEQ=2 OLD_STABLE_SHA=5c1a486047b85036c701b61ecc483c3fb748bdd3922fc2df5090cb493e79f8b0
OLD_INSTALL_SHA=$(sha256sum scripts/install.sh | cut -d' ' -f1)
NEW_MANIFEST=$(sha256sum /secure/signed/updater-bootstrap.manifest.json | cut -d' ' -f1)
NEW_BUNDLE=$(sha256sum /secure/signed/updater-bootstrap.tar.gz | cut -d' ' -f1)
NEW_SIG=$(sha256sum /secure/signed/updater-bootstrap.manifest.sig | cut -d' ' -f1)
read -r NEW_SEQ NEW_ISSUED NEW_EXPIRES NEW_STABLE_SEQ NEW_STABLE_SHA < <(python3 - /secure/signed/updater-bootstrap.manifest.json <<'PY'
import json, sys, time
m = json.load(open(sys.argv[1]))
iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
b, f = m["bootstrap_metadata"], m["stable_release_floor"]
print(b["sequence"], iso(b["issued_unix"]), iso(b["expires_unix"]), f["sequence"], f["metadata_sha256"])
PY
)
test -n "$NEW_STABLE_SHA"
COMMON=(-e "s/production-s$OLD_SEQ-$OLD_MANIFEST/production-s$NEW_SEQ-$NEW_MANIFEST/g"
  -e "s/$OLD_MANIFEST/$NEW_MANIFEST/g" -e "s/$OLD_BUNDLE/$NEW_BUNDLE/g" -e "s/$OLD_SIG/$NEW_SIG/g")
sed -i "${COMMON[@]}" -e "s/--minimum-bootstrap-sequence $OLD_SEQ\$/--minimum-bootstrap-sequence $NEW_SEQ/" scripts/install.sh
sed -i "${COMMON[@]}" \
  -e "s/^Published bootstrap, sequence $OLD_SEQ, signed $OLD_ISSUED, valid until\$/Published bootstrap, sequence $NEW_SEQ, signed $NEW_ISSUED, valid until/" \
  -e "s/^$OLD_EXPIRES, immutable release tag/$NEW_EXPIRES, immutable release tag/" \
  -e "s/^- bootstrap sequence checkpoint: $OLD_SEQ\$/- bootstrap sequence checkpoint: $NEW_SEQ/" \
  -e "s/stable minimum sequence: $OLD_STABLE_SEQ, bound metadata SHA-256 \`$OLD_STABLE_SHA\`/stable minimum sequence: $NEW_STABLE_SEQ, bound metadata SHA-256 \`$NEW_STABLE_SHA\`/" \
  docs/AUTO_UPDATE.md
sed -i "s/$OLD_INSTALL_SHA  install.sh/$(sha256sum scripts/install.sh | cut -d' ' -f1)  install.sh/" README.md
test "$(git diff --name-only | tr '\n' ' ')" = "README.md docs/AUTO_UPDATE.md scripts/install.sh "
if grep -n -e "$OLD_MANIFEST" -e "$OLD_BUNDLE" -e "$OLD_SIG" -e "$OLD_INSTALL_SHA" \
  scripts/install.sh docs/AUTO_UPDATE.md README.md; then echo "OLD VALUES REMAIN"; exit 1; fi
python3 -m pytest -q tests/thin/test_operator_docs_safety.py
git diff --stat
C5
```

- Source: the values are `scripts/install.sh:12`, `:26-31`, `:75`, `docs/AUTO_UPDATE.md:120-137`, and `README.md:83`. Their meaning is in `RELEASE_MAINTAINER.md:354-361` and `:370-372`.
- Check: the block ends with the docs safety test passing (`RELEASE_MAINTAINER.md:386-388`) and a diff of exactly `README.md`, `docs/AUTO_UPDATE.md`, and `scripts/install.sh`. It stops earlier if another file changed or an old value remains. The test needs `pytest`.
- Commit the three files in one commit, open a PR, and merge it before the deadline.
- Publish the new script digest with the bootstrap key fingerprint (`RELEASE_MAINTAINER.md:375-378`).
- This block was run against a copy of this tree with made-up sequence-3 values. It changed exactly those three files, and the docs safety test passed.

**C6. Check.** Run `python3 scripts/check_release_expiry.py`. Expect `OK:`
for `updater bootstrap manifest sequence 3`. Then run the README install on a
clean host (V-02's test). **[Unverified]** live.

## Staying ahead

- The alarm fails daily from 5 days before any expiry, and emails the assignee
  through the alarm issue. Metadata lives at most 14 days, so re-sign both
  channels with case (a) before each record expires. The bootstrap is signed
  for 30 days (`--lifetime-seconds 2592000`, the owner's choice; the limit is
  90), so rebuild it with case (c) every month.
- `sudo cathedral-validator-status` shows the installed channel's expiry under
  `release_metadata` and prints a `warning:` within 5 days
  (`docs/AUTO_UPDATE.md`, "Check it"). It ships in the bootstrap
  (`build_updater_bundle.py:74-81`), so it reaches a host only with a bootstrap
  built from a commit that has it.
- **[Unverified]** GitHub behaviour this depends on. GitHub notifies about a
  failed scheduled run only the user who last changed its schedule. It disables
  scheduled workflows in a public repository after 60 days without activity.
  Check who receives the failure email.
