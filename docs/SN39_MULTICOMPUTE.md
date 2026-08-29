# SN39 bounded multi-machine compute

## Supported outcome

One miner UID may expose up to 32 HTTPS worker candidates. The validator gives
credit only for independently re-derived work from distinct verified physical
platforms. It does not credit declared capacity, uptime, endpoint count, or an
attestation without successful work.

The current implementation is preview-only. It does not submit weights. It
does not add a recurring authority mode.

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
TDX-only. AMD SEV-SNP fleet identity remains NOT PROVEN and disabled.

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
6. Treat any future chain-write design as a separate reviewed change. This
   implementation supplies no such authority.

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

The artifact schema is not accepted by a writer. The command has no submit,
recover, confirm, nonce, extrinsic, or journal mode. It always records zero
target burn, `authorized_for_chain_write: false`, and
`chain_write_submitted: false`.

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

Do not turn a preview digest into chain authority. A UID30 allocation proves
only that validator's weight row. Rewards remain NOT PROVEN until subnet
emission is positive and a reward or balance delta is observed.
