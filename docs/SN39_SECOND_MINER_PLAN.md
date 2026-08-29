# SN39 dedicated second-miner plan

## Outcome target

The intended future state is two independently identified Cathedral miners on
SN39. UID30 assigns equal semantic scores to both miners and assigns zero weight
to a burn destination.

The first miner remains pinned by hotkey, not by a permanent UID:

- Wallet hotkey label: `serge_sat_test`
- Public hotkey: `5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G`

The dedicated second miner is pinned separately:

- Wallet hotkey label: `serge_sat_test_2`
- Public hotkey: `5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq`

Never place a mnemonic, private key, or wallet password in this repository, a
pull request, a plan artifact, a VM startup script, or an operator log.

## Read-only planning command

`cathedral-second-miner-plan preview` performs finalized public reads only. It:

1. Pins Finney, netuid 39, mechanism 0, Cathedral UID30, the Cathedral coldkey,
   and both miner public hotkeys.
2. Confirms UID30 still has its validator permit and the first miner still has
   the expected owner.
3. Reports whether the second hotkey is unregistered, lacks its finalized HTTPS
   axon, either miner violates the HTTPS axon contract, or both have reached the
   point where fresh machine proofs are required.
4. Derives the exact complete two-miner row only after the second hotkey has a
   finalized UID.
5. Writes owner-only JSON plus a detached SHA-256 digest without overwriting an
   existing file.

The planning command does not load a wallet. It has no registration, axon
announcement, extrinsic composition, weight submission, daemon, or retry path.
Every plan artifact contains `authorized_for_chain_write: false`.

Example, after installing the reviewed revision:

```bash
install -d -m 0700 "$HOME/.cathedral/second-miner"
cathedral-second-miner-plan preview \
  --output "$HOME/.cathedral/second-miner/plan.json"
```

## Bounded axon announcement command

`cathedral-second-miner-announce` is a separate, first-time axon writer for the
dedicated second miner. It is not part of the read-only planner. It is pinned to:

- Wallet hotkey label `serge_sat_test_2`.
- Public hotkey `5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq`.
- Endpoint `34.46.19.69:8081` over HTTPS.
- Finney, SN39, protocol 4, and the Cathedral coldkey owner.
- A separate runtime root, preview schema, lock, and ambiguity journal under
  `/var/lib/cathedral-validator/second-miner-axon`.

The UID is not hard-coded. `preview` refuses until the dedicated hotkey resolves
exactly once at a finalized head, then binds the assigned UID into canonical
owner-only JSON and its detached SHA-256. `announce` accepts only those exact
reviewed bytes, rechecks the same finalized UID and owner, recollects fresh QVL,
SAT, and TLS SPKI evidence, proves the signing wallet is the dedicated hotkey,
persists a no-retry intent, and permits at most one `serve_axon` call. `recover`
performs finalized readback without signing or resubmitting.

The command has no registration, rent, daemon, weight, or retry path. It does
not share the consumed UID124 journal and it rejects the UID124 successor flags.
It permits a write only from the canonical unannounced row `0.0.0.0:0`, serving
false. The exact target is a no-write success. Every other existing axon is a
hard refusal that requires a separately reviewed successor lineage.

Run the reviewed command only in a Linux x86-64 environment. The pinned QVL is
a Linux x86-64 ELF executable with SHA-256
`35bb55f89f411d5dcf5f72be90488e999ee68c41dfc0429a0dcb8cc2b448b6bb`.
Native macOS execution reports infrastructure failure and is a stop condition.
Do not replace the verifier, skip QVL, or treat macOS incompatibility as a quote
result.

If the command runs in a container, mount only the reviewed source, pinned QVL,
the `cathedral` wallet needed for `serge_sat_test_2`, and the dedicated runtime
root. Keep the wallet mount read-only. Keep the runtime root writable only by
the container user, mode 0700, with preview, digest, lock, and journal files at
0600. Do not print, copy, or capture a mnemonic, private key, wallet password,
raw keyfile, or decrypted signing material in terminal output or logs.

After registration has finalized, create the no-write review artifact:

```bash
cathedral-second-miner-announce preview \
  --ip 34.46.19.69 \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier
```

Review the JSON and detached digest. A later, explicitly authorized operator
uses the digest once:

```bash
cathedral-second-miner-announce announce \
  --reviewed-sha256 <exact-detached-sha256> \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier \
  --confirm-miner-announce \
  --assert-exclusive-announcer
```

Exit status 3 means the intent is ambiguous. Preserve the journal and run the
read-only recovery command. Never repeat `announce` after an ambiguous result.
Only a complete successful receipt that postdates preflight plus canonical
finalized readback is `finalized_proven`. If the SDK success receipt is missing
inclusion fields or is stale, exact later readback is recorded as
`finalized_recovered`, not proof of the inclusion receipt.

## Bounded UID124 generation-2 successor

`cathedral-uid124-axon-generation2` is a separate one-attempt command for the
existing `serge_sat_test` hotkey at UID124. It does not accept arbitrary
predecessor flags. Its reviewed source pins all of the following:

- Exact target `35.222.166.235:8081` over HTTPS.
- Exact predecessor preview
  `/var/lib/cathedral-validator/miner-axon-preview-r2-20260828T1940Z.json`,
  SHA-256
  `27ef74f1f1f9b2cecf762dd850ebe81aa8d0ab03e42c1dc9023961cc7a89ee29`.
- Exact canonical predecessor journal
  `/var/lib/cathedral-validator/miner-axon-announcement.json`, SHA-256
  `b5b401ad8a1610471b15f2a75546f1ecba19c160d9cc35a361995a5274e48c8f`.
- The existing canonical UID124 lock and journal. It atomically replaces the
  finalized generation-1 journal only after preserving those exact bytes as
  generation-2 predecessor lineage.
- UID124, the first miner hotkey, the Cathedral coldkey owner, UID30 as the
  evidence collector, the pinned QVL, positive canonical SAT, and the target
  TLS SPKI.

The preview is a new owner-only artifact and includes all predecessor pins. The
live command rechecks the canonical predecessor receipt and readback, current
UID124 identity and axon, the 128-finalized-block fence, fresh endpoint proof,
and signing hotkey before installing one no-retry generation-2 intent. A
complete successful inclusion receipt plus a later canonical exact readback is
`finalized_proven`. Missing or incomplete receipt fields require exact later
readback and produce `finalized_recovered`. Any unresolved result remains
ambiguous and must be recovered without resubmission.

Create and review the no-write artifact in the reviewed Linux x86-64 runtime:

```bash
cathedral-uid124-axon-generation2 preview \
  --ip 35.222.166.235 \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier
```

After review, an explicitly authorized operator supplies only the new preview
digest. The command injects the exact predecessor pins from reviewed source:

```bash
cathedral-uid124-axon-generation2 announce \
  --reviewed-sha256 <exact-new-preview-sha256> \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier \
  --confirm-miner-announce \
  --assert-exclusive-announcer
```

This command has no registration, rent, daemon, UID8, or weight path. It does
not run during installation and this source change proves no chain write.

## Current boundary

The original UID124 VM has stopped. Its replacement machine is available at
`35.222.166.235:8081`, but UID124 still advertises the predecessor endpoint
`34.68.36.156:8081`. The generation-2 command above bounds the separate
replacement operation, but no new preview, announcement, or finalized readback
is claimed by this source change. The second machine at `34.46.19.69:8081` uses
the dedicated second hotkey and remains separate from the UID124 command.

The unregistered result at finalized block 8,946,847 on 2026-08-28 is a
historical pre-registration snapshot, not current authority. After registration,
the planner and axon preview must derive the assigned UID again from one current
finalized head. Never copy a UID from this document into a chain write.

The registration was included at block 8,947,050,
`0xad3028f451ac5a4b10644368183d8f1ca1511b85ab2212736599c73f872f6093`.
Two later finalized reads reproduced the dedicated hotkey, Cathedral coldkey,
and UID8 mapping:

- Block 8,947,052,
  `0xead9481536e22462492eaea827d50f1dbc3dd8b8c485f6ba4ac5ca3995e21576`.
- Block 8,947,053,
  `0xbad83ca212baddb7a421974374be2f1e8f50de8be80774c47119985924b9b310`.

At both reads, UID8 was canonically unannounced: `0.0.0.0:0`, protocol 0,
serving false. UID124 remained mapped to the first hotkey and the same Cathedral
coldkey. UID30's mechanism-0 row remained `[[124, 65535]]`. These reads prove
registration and unchanged prior allocation. They do not prove an axon
announcement, a two-miner weight row, subnet emission, or TAO earnings.

Both previous one-shot launch tools are consumed artifacts. The UID124 axon
announcement tool is pinned to the first hotkey and exact endpoint. The UID30
launch tool is pinned to the completed one-miner vector. Neither tool is a safe
path for a second miner. Only `cathedral-second-miner-announce` has the second
miner's identity and isolated first-attempt lineage.

The UID124 replacement endpoint is also separate from this command. A second
machine using `serge_sat_test` remains the same UID124 identity, not the second
miner. Repointing UID124 requires the generation-2 successor contract above to
prove the consumed UID124 journal as its predecessor and write a new reviewed
intent to the canonical lineage. Do not pass UID124 inputs to the second-miner
command.

## Required live sequence

Each step below needs separate operator review and explicit authorization. The
two bounded axon commands cover steps 5 through 8. They do not perform
registration, submit an announcement during installation, or expose a weight
writer.

1. Completed outside this change. Bootstrap the second machine with the
   dedicated second public hotkey and verify its immutable startup contract.
2. Completed outside this change. Obtain fresh QVL PASS, canonical SAT success,
   and a TLS SPKI distinct from the first machine.
3. Completed outside this change. Register `serge_sat_test_2` once. The
   registration inclusion and later finalized reads are recorded above.
4. Completed by the finalized reads above. Confirm the dedicated public hotkey,
   Cathedral coldkey ownership, assigned UID8, and canonical unannounced row.
5. Run `cathedral-second-miner-announce preview`. Review the assigned UID,
   second public hotkey, external IP, HTTPS port 8081, genesis, fresh endpoint
   proof, local lineage paths, and detached digest.
6. Submit that exact reviewed digest once with the two explicit confirmations.
   If the outcome is ambiguous, preserve the journal and recover without a
   second call. Confirm the exact axon at inclusion and at two later finalized
   heads.
7. Run and review the UID124 generation-2 preview. Require the exact pinned
   generation-1 preview and journal, current UID124 predecessor axon, exact
   replacement endpoint, fresh QVL and SAT proof, and reviewed detached digest.
8. Submit that exact UID124 generation-2 digest once. If the outcome is
   ambiguous, preserve the canonical journal and recover without a second call.
   Confirm the exact replacement axon at inclusion and two later finalized
   heads.
9. Rerun the read-only planner. Require both hotkeys to resolve uniquely and
   require the complete intended row below.
10. Build and review a new one-shot UID30 successor. Bind it to fresh QVL and SAT
   proofs for both axons, distinct TLS SPKIs, the latest finalized identities,
   UID30's permit and cooldown, zero burn destination, and one exact write.
11. Submit once. Confirm the complete UID30 row at inclusion and at two later
   finalized heads.

## Weight semantics

UIDs are resolved from hotkeys at a finalized head. For example, if the first
miner remains UID124 and the second registers as UID200, equal input scores
`[1.0, 1.0]` encode through Bittensor 10.5 as:

```json
[[124, 65535], [200, 65535]]
```

This is max-normalized u16 encoding. It is not a 65,535 total split such as
32,768 plus 32,767. A mechanism-weight submission replaces UID30's complete
row, so omitting either miner removes it from the row. UID30 itself and the
subnet-owner burn hotkey must not appear as destinations.

Zero burn here refers only to weight allocation. It does not remove the
registration cost.

## Success gates

The second-miner launch is complete only after all gates pass:

- Two distinct miner hotkeys resolve to two distinct finalized SN39 UIDs owned
  by the Cathedral coldkey.
- Both finalized axons expose HTTPS port 8081 with protocol 4.
- Both machines pass fresh QVL and canonical SAT verification.
- Their TLS SPKI identities differ.
- The reviewed preview names exactly both current UIDs with raw weights 65,535
  and has no burn destination.
- One successful UID30 extrinsic replaces the complete row.
- Inclusion and two later finalized reads reproduce the same exact row.

Registration, an axon, or an assigned UID does not prove rewards. A UID30 weight
row proves allocation from that validator only. TAO earnings remain not proven
until subnet emission is positive and a reward or balance delta is observed.
