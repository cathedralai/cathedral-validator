# SN39 versioned release sealing

The historical launch seal stays at `release.json` and `release.json.sig`.
Never replace or delete those files to publish another release.

New seals use their exact release payload digest:

```text
releases/sha256/<release-payload-sha256>.json
releases/sha256/<release-payload-sha256>.json.sig
```

The release digest printed by preflight and finalize is the complete release
identifier. Record it in the immutable release notes. There is no mutable
`latest` pointer in this protocol.

## Read-only preflight

Run preflight through the root-owned immutable-install launcher:

```bash
sudo /usr/bin/python3 -I -E -s \
  /usr/local/libexec/cathedral-sn39-release preflight \
  /var/lib/cathedral-validator/journal-<64-hex-digest>.json
```

Preflight runs the same journal, archive, controlled-replay, release-key, and
publication-conflict checks as finalize. It does not create a publication lock,
staging file, replay blob, release, or signature file. Success prints
`SN39_PUBLIC_RELEASE_PREFLIGHT_PASS`, `"mutations": false`, the release digest,
and the two versioned artifact paths.

Preflight does not reserve the result. Finalize rechecks every destination
under the publication lock before its first write.

## Finalize

Finalize is a separately approved mutation:

```bash
sudo /usr/bin/python3 -I -E -s \
  /usr/local/libexec/cathedral-sn39-release finalize \
  /var/lib/cathedral-validator/journal-<64-hex-digest>.json
```

Finalize does not submit a chain transaction. It publishes the optional
content-addressed replay blob, the versioned release, and its detached
signature. It checks the complete publication plan for conflicts before the
first blob or release write. A process crash can leave an incomplete but
non-conflicting generation. An identical rerun completes it without replacing
different bytes.

The producer may rotate
`/var/lib/cathedral-validator-controlled-sn39/current` between epochs. The
finalizer accepts only a root-owned leaf symlink to a direct sibling epoch
directory. It opens every ancestor and the selected epoch with `O_NOFOLLOW`,
then reads every envelope through the held directory descriptor. A later
rotation cannot mix evidence from two epochs.

## External reproduction

Use the digest printed by preflight or finalize:

```bash
python -I -B -u scripts/run_sn39_public_reproduction.py \
  --release-sha256 sha256:<release-payload-sha256>
```

Omitting `--release-sha256` intentionally reproduces the historical root seal.
The versioned reproducer checks that the fetched release bytes match the digest
in the requested path before it verifies the detached signature.

## Required gates

A passing source test does not authorize a seal. Before preflight, prove:

1. The producer and validator revisions and every release pin match the
   immutable installation.
2. The active validator runs only through the manifest-bound launcher from a
   pristine release tree and versioned environment.
3. The journal has no pending submission and contains the exact finalized
   receipt being sealed.
4. A claimed replay checkpoint has matching controlled envelopes, public
   evidence, candidate set, and pinned verifier bytes.
5. The supported shadow provenance gate is currently passing.
6. An independent operator can reproduce the versioned release from a clean
   checkout after publication.
