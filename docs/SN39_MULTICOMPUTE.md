# SN39 bounded multi-machine compute

## Supported outcome

One miner UID may expose up to 32 HTTPS worker candidates. The validator gives
credit only for independently re-derived work from distinct verified physical
platforms. It does not credit declared capacity, uptime, endpoint count, or an
attestation without successful work.

The scoring and proof commands are preview-only. A separate bounded command
accepts one exact reviewed proof digest and performs one fixed transition from
`[[8, 65535], [124, 65535]]` to `[[124, 65535]]`. It does not add a recurring
authority mode.

## Current chain evidence

The read-only finalized snapshot at block 8,949,280 reports:

- UID8, hotkey `5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq`, serving
  `34.46.19.69:8081`.
- UID124, hotkey `5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G`, serving
  `35.222.166.235:8081`.
- UID30 mechanism-0 storage `[[8, 65535], [124, 65535]]`.
- UID30 validator permit true.
- Subnet emission zero.

This proves two weighted serving UIDs at one finalized head. It does not prove
two machines behind one UID or TAO earnings. The commands below always read a
fresh finalized head. Do not treat the snapshot as permanent state.

## Score contract

```text
raw_uid_units = sum(independently re-derived verified work_units
                    across unique admitted physical platforms)
```

- One machine contributes at most 20 units in a scoring window.
- One UID exposes at most 32 candidates and contributes at most 640 units.
- Normalization happens only after raw units are aggregated per UID.
- Machine count, declared capacity, uptime, and attestation-only evidence add
  zero units.
- An over-cap fleet excludes the whole UID.
- A verified duplicate endpoint, TLS SPKI, or stable platform identity zeros
  every verified claimant across the scoring batch. Selection order never
  chooses a winner.
- An unverified claim cannot poison a verified claimant.

TLS SPKI is channel identity only. Physical identity comes from the pinned QVL
result. Multi-machine credit requires all of these exact QVL fields:

- `platform_identity_kind` is `stable`.
- `platform_identity_verified` is true.
- `claims_bound_to_quote` is true.
- `stable_platform_id` equals `platform_id` and has the form
  `tdx-platform-sha256:<64 lowercase hex>`.

The internal machine ID is SHA-256 over that validated domain-tagged identity.
The scorer has a profile-neutral aggregation boundary, but the live verifier is
TDX-only. AMD SEV-SNP fleet identity remains NOT PROVEN and disabled for
production scoring and chain writes. The separate
[AMD SEV-SNP development preview](AMD_SEV_SNP_DEV_PREVIEW.md) has no writer and
does not alter this production boundary.

## Signed worker access

The validator first collects and QVL-verifies the chain axon. It then fetches
the fleet over the same unchanged TLS SPKI. Every remaining candidate receives
independent evidence and work checks.

Fleet discovery is `POST /v1/fleet` with the exact body `{}`. The response is
`cathedral_worker_fleet_v1` and contains the worker hotkey plus candidate HTTPS
endpoints. The primary chain axon is injected first. Only an HTTP 404 permits
the one-endpoint compatibility fallback. A 401, malformed response, wrong
hotkey, over-cap response, channel change, or other error is a refusal.

The only authorization header is `X-Cathedral-Validator-Request`. Its value is
standard padded base64 of canonical JSON schema
`cathedral_validator_request_v1`. The sr25519 signature binds the exact
validator hotkey, worker hotkey, network, netuid, method, path, body digest,
TLS SPKI digest, nonce, and a validity interval no longer than 120 seconds.
The request key must equal the pinned UID30 hotkey before any worker request.
No wallet secret appears in the request or output.

The miner verifies access through its atomically refreshed, Ed25519-signed
`cathedral_validator_access_snapshot_v1`. The validator does not send this
snapshot.

## Rollout order

1. Deploy the worker-side signed access and fleet endpoint first. Keep the
   reviewed legacy audit allowance during migration.
2. Publish an exact fleet for the canonical consolidation hotkey. The root is
   its finalized chain axon.
3. Reconfigure the second machine under the same worker hotkey before claiming
   same-UID credit.
4. Run the generic preview and resolve all infrastructure blockers.
5. Run the exact UID30 no-write proof. Review the owner-only JSON and detached
   SHA-256.
6. Review the complete JSON and detached SHA-256. Do not submit a
   `NOT_PROVEN_NO_WRITE` artifact.
7. If the bounded consolidation is approved, stop every other UID30 writer and
   use the separate digest-bound command below.

The presently published worker image does not expose the signed fleet access
contract. Until the worker rollout completes, a same-UID two-machine proof is
expected to remain NOT PROVEN.

## Generic no-write preview

```bash
install -d -m 0700 "$HOME/.cathedral/multicompute-preview"
cathedral-multicompute-preview \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier \
  --wallet-name cathedral \
  --wallet-hotkey default \
  --output "$HOME/.cathedral/multicompute-preview/scoring.json"
```

This dedicated command imports no Cloud client or chain writer. It has no rent,
canary, confirmation, journal, nonce, extrinsic, or submission option. A
complete preview exits 0 even when individual invalid candidates appear as exclusions.
Whole-preview failures remain blockers. The output always includes:

```json
{
  "authorized_for_chain_write": false,
  "chain_write_submitted": false
}
```

## Exact UID30 consolidation proof

The consolidation owner is pinned by public hotkey, not by a permanent UID:

```text
5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G
```

It currently resolves to UID124 with root axon `35.222.166.235:8081`. The
current UID8 machine is evidence for a different hotkey until it is deliberately
reconfigured into this signed UID124 fleet.

```bash
install -d -m 0700 "$HOME/.cathedral/uid30-fleet"
cathedral-uid30-fleet-preview \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier \
  --output "$HOME/.cathedral/uid30-fleet/two-machine-proof.json"
```

The command records the complete current UID30 row and all weighted serving
UIDs. It separately evaluates the consolidation target. A complete target
requires:

- Exactly two signed fleet endpoints rooted at the pinned miner's chain axon.
- Two distinct endpoints, TLS SPKIs, stable platform identities, internal
  machine IDs, quote digests, and report-data digests.
- QVL PASS and exactly 20 canonical SAT units for each machine.
- Target raw score 40.
- An unchanged current row, UID mapping, serving axons, root TLS channel, and
  signed fleet across the finalized recheck.

If complete, the artifact reports
`PROVEN_TWO_MACHINE_NO_WRITE_PREVIEW` and the non-authorizing target row
`[[124, 65535]]` while UID124 remains the resolved owner. If incomplete, it
reports `NOT_PROVEN_NO_WRITE`, records exact reasons, and exits 2. When the
target differs from current storage, it reports `changes_current_chain_row:
true`.

The preview command has no submit, recover, confirm, nonce, extrinsic, or
journal mode. It always records zero target burn,
`authorized_for_chain_write: false`, and `chain_write_submitted: false`. The
separate one-shot command accepts the preview only after its exact canonical
bytes match both the detached digest and the operator-supplied digest.

## One-shot UID30 consolidation

Outcome target:

```text
signer: UID30
previous finalized row: [[8, 65535], [124, 65535]]
submitted row: [[124, 65535]]
burn destination: none
burn weight: 0
signed-attempt budget: 1
```

Run this only on the host containing the canonical Cathedral wallet and
`/var/lib/cathedral-validator` journal. First inspect the JSON and copy the
64-character digest from its `.sha256` file. Then run:

```bash
cathedral-uid30-fleet-submit submit \
  --preview "$HOME/.cathedral/uid30-fleet/two-machine-proof.json" \
  --reviewed-sha256 <reviewed-64-character-sha256> \
  --qvl /absolute/path/to/reviewed/cathedral-tdx-verifier \
  --confirm-uid30-fleet-consolidation \
  --assert-exclusive-writer
```

The one-shot command is hard-pinned to the public Finney archive endpoint
`wss://archive.chain.opentensor.ai:443`. There is no endpoint option. An
existing `CATHEDRAL_CHAIN_ENDPOINT` setting does not redirect this path. The
preview refresh, predecessor proof, write preflight, signing, submission,
inclusion proof, recovery, and later finalized reads all reuse the pinned
archive route. Before it loads QVL or reserves an attempt, the command requires
that archive to reproduce the exact finalized predecessor call and
`[[8, 65535], [124, 65535]]` storage row.

Immediately before signing, the command:

- repeats the two-machine QVL and SAT proof;
- requires the same two reviewed physical identities and endpoints;
- rechecks UID30 ownership, validator permit, stake, cooldown, mechanism, and
  weight-version gates;
- re-proves the exact finalized two-UID predecessor and its canonical journal;
- reserves one attempt before signing;
- submits only UID124 weight 65535; and
- proves the exact call and storage at inclusion and two later finalized heads.

The command has no UID, weight, burn, broadcast, or retry option. A refusal
before a signed intent restores the predecessor journal byte for byte. Any
uncertainty after signing prints `AMBIGUOUS_DO_NOT_RETRY` and leaves the attempt
fenced.

Do not run `submit` again after an ambiguous result. Recover the same attempt:

```bash
cathedral-uid30-fleet-submit recover \
  --preview "$HOME/.cathedral/uid30-fleet/two-machine-proof.json" \
  --reviewed-sha256 <reviewed-64-character-sha256> \
  --assert-exclusive-writer
```

Recovery never signs or submits. It locates and proves only the journaled
transaction. If the mortal transaction expired without inclusion, the one
attempt remains consumed.

## Stop conditions

Stop and preserve the evidence when any of these occurs:

- The request-signing hotkey differs from UID30.
- The chain axon fails fresh QVL or changes TLS SPKI.
- Fleet discovery returns anything other than the exact signed schema or the
  404-only compatibility case.
- A candidate lacks a quote-bound verified stable platform identity.
- An endpoint, channel, or platform identity is duplicated.
- SAT replay differs, exceeds the cap, or fails.
- The UID mapping, current weights, serving axon, canonical block, or signed
  fleet changes during the proof.
- The pinned consolidation hotkey is absent from current storage.

Do not treat a preview digest as general chain authority. It authorizes only
the fixed command above after the explicit confirmation and exclusivity gates.
A UID30 allocation proves only that validator's weight row. Rewards remain NOT
PROVEN until subnet emission is positive and a reward or balance delta is
observed.
