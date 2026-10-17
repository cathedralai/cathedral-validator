# SEV-SNP roster export (Cathedral join)

The direct validator can post a signed roster of the AMD SEV-SNP machines each
round paid to the Cathedral API (polariscomputer #1469, step 3). The API uses a
row only as a place to look for a customer guest on the same chip. It verifies
that guest natively before it seals it. A roster grants nothing.

Off by default. Nothing is sent unless `CATHEDRAL_SNP_ROSTER_URL` is set.

## Document

`cathedral_validator_roster_v1`, the API's wire contract
(polariscomputer `docs/SNP_JOIN_ROSTER.schema.json`, copied to
`tests/fixtures/cathedral_validator_roster_v1.schema.json`).

| Field | Value |
|---|---|
| `network`, `netuid` | `test` and 584 on testnet, `finney` and 94 on mainnet. |
| `validator` | This validator's uid and hotkey at the scored block. |
| `sequence`, `block` | Both the finalized block the round was scored at. It rises every cycle and needs no local state. |
| `generated_at` | UTC, whole seconds, at post time. |
| `rows` | The round's paid rows with `tee_kind` `sev_snp` only: `uid`, `hotkey`, `endpoint`, `machine_id`, sorted by (uid, machine_id, endpoint). TDX and unpaid machines are left out. An empty list is valid. |
| `roster_id` | `sha256:` + hex SHA-256 of the canonical JSON without `roster_id` and `signature`. |
| `signature` | sr25519 by the validator hotkey over `cathedral-validator-roster-v1\0` + `roster_id`. |

Unlike telemetry, the roster carries endpoints and machine identifiers, so it
is never spooled for the public exporter. The validator process posts it
directly to the private intake route.

## Settings

Environment variables, not flags: a runtime from before this setting ignores
them, where an unknown flag would exit with status 2 after an update rollback.
Put both in `/etc/cathedral-validator/direct.env`.

| Variable | Value |
|---|---|
| `CATHEDRAL_SNP_ROSTER_URL` | The API intake route, a plain HTTPS URL, for example `https://<api host>/v1/cathedral/snp/roster`. |
| `CATHEDRAL_SNP_ROSTER_TOKEN_FILE` | Absolute path of the ingest token, owned by `cathedral-validator`, mode `0600`, for example `/etc/cathedral-validator/snp-roster.token`. Read every cycle, so a rotated token needs no restart. |

At start the validator prints one `snp_roster` line: `ENABLED`, or `DISABLED`
with the reason when only one variable is set, the URL is not plain HTTPS, or
the token path is relative. A bad configuration leaves the export off. It never
stops the validator.

## Each cycle

After the weight write returns (any status, including a commit awaiting its
reveal), the validator builds, signs and posts the roster once, with a 10 s
timeout and no redirects. The cycle line carries `snp_roster`: `POSTED` with
`roster_id`, `sequence` and `rows`, or `FAILED` with a short reason (for
example `API refused the roster with HTTP 422: roster sequence is not newer`).
A failure never changes the round, its weights or its receipt, and is not
retried: the next cycle posts a newer roster.

The API refuses a roster older than its intake window
(`CATHEDRAL_SNP_JOIN_ROSTER_MAX_AGE_SECONDS`, default 1800 s), so the cycle
interval (default 1500 s) keeps the listing fresh.

## API side

The API must pin this validator's hotkey in `CATHEDRAL_SNP_JOIN_VALIDATOR_HOTKEYS`,
store the token's SHA-256 in `CATHEDRAL_SNP_JOIN_ROSTER_TOKEN_SHA256`, and name
the same chain in `CATHEDRAL_SNP_JOIN_NETWORK` and `CATHEDRAL_SNP_JOIN_NETUID`
(`test` and 584 for the testnet unit). The route answers 404 while
`CATHEDRAL_SNP_JOIN_ENABLED` is off.
