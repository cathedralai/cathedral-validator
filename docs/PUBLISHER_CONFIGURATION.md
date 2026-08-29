# Publisher configuration

The SN39 origin has one production posture:

```text
CATHEDRAL_ENV=production
CATHEDRAL_LAUNCH_PROFILE=v2-converged
```

The systemd unit fixes the environment. The protected EnvironmentFile fixes the
profile. Startup refuses production without the profile.

`CATHEDRAL_ENV=production` is the only production marker. Abbreviations such as
`CATHEDRAL_ENV=prod` and legacy `ENV`, `APP_ENV`, or `CATHEDRAL_PRODUCTION`
production markers stop startup with a migration error. Attestation and app
startup use the same canonical detector, so they cannot disagree about whether
development bypasses are allowed.

## What the profile owns

`v2-converged` enables the V2 miner API, bitset submission, lazy challenge
issuance, the verification worker, the verified per-miner payout bridge, and
startup pinning of the per-miner configuration. The production service role is
fixed to `all`. V1 miner routes are blocked by the production origin guard.
Validators still consume the same signed-vector wire format.

The profile requires:

- one Ed25519 key for rows, V2 receipts, JWKS, and weight vectors. Its derived
  public key must match the canonical relay pin, with weight-vector key ID
  `cathedral-weight-policy`. Any programmatic or legacy dedicated weight-key
  input must contain the same key bytes or production startup stops
- a stable V2 submit-token secret
- a stable per-miner seed secret
- dedicated bearer-token and HMAC secrets for the confidential-TDX score source
- one shared Postgres store for V2 verification and score composition

A split V2 database, an explicitly disabled profile-owned feature, or a missing
required secret stops startup.

## Economic settings

The shipped production file states the repository's existing canonical
recurring producer and relay contract explicitly:

| Setting | Shipped value | Meaning |
|---|---|---|
| `CATHEDRAL_ALLOCATION_CONTRACT` | `v2` | Emit the V2 validated-supply contract required by the canonical relay |
| `CATHEDRAL_VALIDATED_SUPPLY_ENABLED` | `true` | Include the signed `validated_supply` policy block |
| `CATHEDRAL_WEIGHTS_MODE` | `proportional` | Score distinct accepted challenges |
| `CATHEDRAL_PERMINER_SCORING_MODE` | `bonus` | Preserve base scoring and add the bounded assigned-work bonus |
| `CATHEDRAL_PERMINER_BONUS_MULT` | `0.2` | Fix the assigned-work bonus metadata and latent base-lane behavior |
| `CATHEDRAL_PERMINER_HISTORY_FLOOR` | `0.25` | Fix the assigned-work history floor metadata and latent base-lane behavior |
| `CATHEDRAL_PERMINER_REQUIRE_COLDKEY` | `true` | Preserve the canonical per-miner identity-readiness posture |
| `CATHEDRAL_WEIGHTS_WINDOW_HOURS` | `24` | Keep score history and signed policy metadata on one 24-hour window |
| `CATHEDRAL_WEIGHTS_TIER2_MULT` | `3` | Keep the legacy base-lane tier-2 multiplier stable |
| `CATHEDRAL_WEIGHTS_TIER_WEIGHTS` | empty | Use the pinned tier-1=1 and tier-2=3 base-lane map |
| `CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS` | `off` | Do not filter the vector through the optional metagraph snapshot |
| `CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS` | `600` | Require the registration snapshot used by confidential-score admission to be at most 10 minutes old |
| `CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE` | `false` | Preserve hotkey identity instead of silently regrouping scores by coldkey |
| `CATHEDRAL_V2_CHALLENGE_SOURCE` | `planted` | Preserve the existing planted-SAT challenge source |
| `CATHEDRAL_V2_REAL_FRACTION` | `0` | Prevent an explicit mixed or all-real override from replacing planted challenges |
| `CATHEDRAL_V2_REQUIRE_SOLVER_META` | `false` | Keep solver metadata optional in the accepted submit contract |
| `CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST` | empty | Let every authenticated hotkey mint its own signed submit token. Registration is enforced later during confidential-score composition |
| `CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS` | `300` | Keep submit tokens valid for five minutes |
| `CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES` | `16384` | Fix the maximum accepted bitset request body |
| `CATHEDRAL_SUBMIT_MAX_CONCURRENCY` | `24` | Configure a positive bitset submission ceiling before the hard-cap clamp |
| `CATHEDRAL_SUBMIT_HARD_CAP` | `8` | Clamp each process to eight concurrent bitset submissions. Zero and unbounded admission are forbidden |
| `CATHEDRAL_SUBMIT_BUSY_WAIT_SECS` | `0.35` | Wait up to 0.35 seconds for a saturated bitset slot before returning a retryable 429 |
| `CATHEDRAL_V2_BLOB_UPLOAD_ENABLED` | `false` | Keep the verified-but-unpaid manifest/blob compatibility lane unreachable |
| `CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED` | `false` | Keep direct origin CNF delivery as the one production distribution contract |
| `CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED` | `false` | Do not advertise or perform unconfigured external result publication |
| `CATHEDRAL_V2_VERIFY_WORKER_ENABLED` | `true` | Drain admitted bitset submissions into verification and scoring |
| `CATHEDRAL_EXTERNAL_SCORES_ENABLED` | `true` | Compose the validated confidential score source |
| `CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED` | `true` | Accept authenticated score reports |
| `CATHEDRAL_EXTERNAL_SCORES_MODE` | `confidential_primary` | Never substitute unvalidated base scores |
| `CATHEDRAL_EXTERNAL_SCORES_SOURCE` | `cathedral_confidential_tdx` | Admit the canonical validated TDX source only |
| `CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM` | `true` | Confirm the exclusive confidential-primary posture |
| `CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED` | `true` | Exclude score rows without a current registered hotkey before signing |
| `CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE` | `false` | Preserve the current confidential producer report contract while hardware proof is verified upstream |
| `CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS` | `3600` | Compose only complete confidential-score snapshots from the previous hour |
| `CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS` | `3600` | Reject newly submitted score reports older than one hour |
| `CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS` | `120` | Reject reports dated more than two minutes in the future |
| `CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES` | `4096` | Keep every replica able to accept the same complete fleet snapshot |
| `CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES` | `1048576` | Fix the authenticated report body cap at one MiB |
| `CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED` | `true` | Return an error instead of serving an expired signed vector as healthy |
| `CATHEDRAL_WEIGHT_POLICY_BURN_UID` | empty | Resolve the burn destination by hotkey at the finalized head |
| `CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2` | `10` | Apply the V2 contract's fixed 10% burn |
| `CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS` | `1800` | Keep each signed vector within the canonical wire lifetime |

Changing any row changes policy or protocol behavior. Treat it as a reviewed
release, not routine deployment configuration.

Production requires every row exactly as shown. Even another recognized value,
such as `v3`, `flat_recent`, `pm_primary`, `filter`, or `corpus`, stops startup.
Introducing one requires a separate named profile and review. Staging the value
under the existing production profile is not supported.

Together these values produce the already-existing `validated_supply_v1`
contract: 90% validated Intel TDX and 10% fixed burn. The canonical recurring
relay rejects a vector without this V2 policy block. This PR pins configuration
to that repository contract. It does not deploy the publisher or submit weights.

The bounded UID30 fleet-launch writer remains a separate zero-burn launch and
test path. This PR does not change its 0-burn constraint.

The strict profile rejects unknown values. Compatibility mode preserves the old
fallbacks for local tests and old fixtures only.

## Canonical per-miner challenge contract

The profile owns the V2 challenge contract in code. Production rejects both
legacy `CATHEDRAL_PERMINER_*` aliases and V2-prefixed per-process tier
overrides. Startup pins every replica to:

| Field | Tier 1 | Tier 2 |
|---|---:|---:|
| epoch bucket | 1 hour | 1 hour |
| epoch allotment | 10,000 | 10,000 |
| page limit | 50 | 50 |
| score weight | 1 | 2 |
| generator method | `biased` | `ajm` |
| variables | 400 | 400 |
| clauses | 1,704 | 1,704 |

The canonical JSON digest is
`f2e8a3e6c8a4901e6a3358026952f3ac0a5ad3b2f27c21d6ae5f01eed99488a1`.
Startup emits both the structured contract and this digest.

## One production miner and weight path

Production miners fetch the V2 per-miner challenge and CNF, then submit only to
`/v2/agents/submit-bitset`. The verification worker writes accepted solves to
the canonical per-miner score ledger. The manifest submit, manifest receipt,
local blob upload, alternate CNF artifact, and external result-publish paths are
development/history compatibility only and return 404 in production. They are
not advertised in the production challenge response.

The positive production protocol allowlist also returns 404 for the V1 shared
challenge, V1 per-miner, V1 submit and receipt, SAT snapshot, audit-scanner,
arena, attestation, TEE-GPU, and V2 shadow namespaces. The only scored miner
routes are V2 challenge, direct CNF, bitset submit, and bitset receipt status.
All production routes default to 404. The explicit support allowlist retains
health, JWKS, public leaderboards, authenticated confidential-score intake, and
the two operator health endpoints. OpenAPI and unlisted observability routes
are not part of this production posture.

The historical `/api/cathedral` compatibility prefix is never stripped in
production. Every `/api/cathedral/*` request returns 404, including one whose
suffix matches an allowed route. The exact catalog contains only the unprefixed
routes enumerated by the production protocol and support allowlists.

Validators consume only `/v1/validator/weights/next`. The old
`/v2/validator/weights/next` shadow composer returns 404 in production because
it does not implement the confidential-primary plus fixed-burn contract.

## Empty proportional ledger

Compatibility mode falls back from an empty proportional ledger to the old
`eval_runs` flat-recent feed. The production profile does not. It reports
`proportional_empty`, composes an empty base lane, and then applies only
explicitly configured per-miner or external lanes and the signed burn policy.
Old feed rows never become an unrequested payout source.

## Development bypasses

Production rejects enabled escape hatches for stub attestation,
unauthenticated external scores, mainnet mechanism override, submit hard-cap
bypass, multi-worker or unlocked V2 ingress, and the separate CyberGym intake.
It also rejects the retired shared-board refill/seed/generator modes, V1 async
submit and verification workers, PM async/shadow modes, per-miner shadow mode,
V2-to-V1 shadow routes, destructive retention, optional abuse/per-hotkey or
pending-queue admission modes, and every TEE-GPU or Chutes configuration input
except the required disabled master switch. TEE-GPU is pinned off because this
is the CPU SAT publisher. CyberGym and GPU compute intake require separate
profiles. Setting a listed boolean to false is accepted unless its whole
configuration family is forbidden.

Production fixes `CATHEDRAL_CLIENT_IP_MODE=headers`,
`CATHEDRAL_TRUSTED_PROXY_HOPS=1`, `CATHEDRAL_RATELIMIT_RPM=120`,
`CATHEDRAL_SUBMIT_MAX_CONCURRENCY=24`, `CATHEDRAL_SUBMIT_HARD_CAP=8`, and
`CATHEDRAL_SUBMIT_BUSY_WAIT_SECS=0.35`. The concurrency pair yields an effective
eight-request bitset admission bound. Saturated requests receive a retryable 429
after the fixed 0.35-second wait.
Other worker threads and batch sizes remain capacity tuning. They do not select
another protocol or scoring policy.

The optional materialized and dashboard snapshot modes are pinned off. Their
background builders and alternate read-serving behavior need a separate
reviewed profile before production use.

The unset profile is named `unset_compatibility` in startup output. It is not a
production option.

## Effective configuration record

Every app startup prints one line beginning with `[publisher_config]`. The JSON
record includes:

- production or development/compatibility posture
- launch profile and service role
- the backend the opened store accepted, not a guess from URL presence
- the non-secret publisher generation ID and a password-free database identity
  fingerprint so replicas and rollouts can be compared
- weight-policy key ID, derived public key, network, and netuid
- allocation, scoring, per-miner, payable-hotkey, and external-score modes
- effective validated-supply activation and forced-burn percentage
- external-score, report, and registration-snapshot freshness windows
- external-score count and body caps
- V2 convergence, planted-only challenge mix, submit-token scope, solver-metadata contract, origin expiry posture, fixed client admission identity, configured, hard-cap, and effective bitset concurrency, and the busy-wait bound
- only set/unset markers for secret-bearing environment variables

The protected submit-metrics endpoint reports the same configured, hard-cap,
effective, and busy-wait values so operators can compare runtime admission with
the startup record.

Signing keys, tokens, seed secrets, HMAC secrets, object-store secret keys, and
the database URL never appear in the record.

Production also rejects unchanged example placeholders, short or low-diversity
required secrets, and a signing key whose derived public key differs from the
canonical relay pin. It verifies the opened store is Postgres before emitting
the effective record.

Use the record as the first deployment comparison. It is not proof that the
database contains current scoring inputs or that a signed vector was published.
The same deployment identity appears on the health and readiness responses.
`CATHEDRAL_PUBLISHER_GENERATION_ID` is an operator-supplied, non-secret rollout
label. Set the same value on every replica and change it when shared protocol
secrets or deployment configuration rotate. Secret-derived hashes are not
emitted because public health or broadly readable logs would turn them into
offline secret-verification and cross-environment correlation values.

## Compatibility boundary

Local development and compatibility tests may leave `CATHEDRAL_ENV` and
`CATHEDRAL_LAUNCH_PROFILE` unset. This preserves the earlier per-feature flag
behavior. Do not deploy the unset posture. The production unit makes this
boundary enforceable by setting `CATHEDRAL_ENV=production` itself.
