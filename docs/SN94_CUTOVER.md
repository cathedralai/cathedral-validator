# SN39 to SN94: release and cutover gates

This is a release checklist, not a claim that SN94 is operating. Keep one
authorized production writer for the Cathedral hotkey. Never copy its private
key into a website, collector, repository, or test fixture.

## Source in this integration

- Adopt the existing timelocked v4 writer (#272), its persistent
  `REVEAL_NOT_APPLIED` stop (#289), and applied-reveal telemetry (#281).
- Keep serving miner UIDs eligible when they acquire a validator permit
  (#285); the signing validator itself remains excluded.
- Restore the exporter's module entrypoint (#283). Use executable private
  PEX caches, not `/run`, and create the documented sysusers/tmpfiles parents.
- Persist a sanitized commit candidate before signing so a hard exit during
  submission does not itself lose the round. Publish only after the exact
  journaled plan has a proven applied reveal. Persistence failure remains a
  reported telemetry failure, never permission to invent a row or retry a
  contradictory chain write.

The code still refuses other production netuids than the compiled SN94.
Changing `--netuid` on an old SN39 installation is not a supported migration.
This integration adapts the preserved #277 rehearsal work narrowly: exact
`CATHEDRAL_TESTNET=1`, `--network test --netuid 584`, a pinned testnet genesis,
separate `testnet-sn584-...` journals, and test-network signed requests/events.
It adds no localnet stub, verifier bypass or private miner-address exception.
Production network, verifier and journal defaults remain unchanged. Broader
deployment-config work remains in #268. An older #279 testnet run or fake-chain
unit tests do not qualify this exact artifact.
Recovery checks the selected chain's genesis directly from the node before
reading pending-intent or reveal history. A wrong/unreadable genesis leaves the
journal unchanged; existing terminal stops remain stopped without chain access.

## Before any mainnet change

1. Independently review this exact source revision and build the immutable
   Linux release inputs with `release-candidate.yml`. That workflow produces
   unsigned inputs; it does not activate the validator.
2. The release-key owner signs a new runtime and compatible bootstrap. The
   existing signed SN39 archive is not made SN94-ready by renewing its expiry.
   Runtime updates do not replace installed systemd units. Verify forward and
   rollback configuration compatibility before publication.
3. Rehearse the exact signed candidate: finalized intended write/reveal,
   interruption recovery without duplicate signing, controlled not-applied
   stop, exporter acknowledgement, and the same website path. Testnet evidence
   must be labelled testnet, not mainnet. Never ship synthetic localnet QVL
   evidence as hardware attestation.
4. Refresh SN94 registration, permit, stake threshold, cooldown, minimum
   weights, tempo, reveal version and period at a finalized head. Obtain an
   explicit cap for any registration/stake transaction. Registration alone
   does not establish a validator permit.
5. Verify which host currently writes SN39 and its installed archive. Wait
   for any unresolved write/reveal to finish; retain the original release,
   configuration and journal. Stop the SN39 writer only in the approved
   cutover window. Do not run old and new production writers in parallel.
6. Install the coordinated signed runtime/bootstrap, not an unsigned branch
   wheel. Opt in to the observed commit-reveal policy using the service drop-in
   described in `AUTO_UPDATE.md`; do not edit managed `direct.env` ad hoc.
7. Require one finalized SN94 reveal and a subsequent clean cycle from the
   installed digest. Start the exporter only after its exact collector URL,
   credentials and collector chain policy have been verified.

## Leaderboard acceptance

The paired site change accepts exactly Finney SN94 and the labelled testnet
SN584 rehearsal, rejects SN39 and unmatched pairs, and allows the bounded
commit-reveal round age. It does not itself repair the private collector.
That collector must validate the event signature and actual chain identity /
permit for the selected network, preserve zero burn and vector completeness,
and accept an older observation only within the documented reveal-age bound.
The existing private collector's source has been adapted for both fixed chain
endpoints/genesis pins without replacing its cryptographic or chain checks.
Its ingestion and snapshot routes enforce the same freshness bound. This
source preparation is not evidence of deployment, exporter activation or a
real accepted event.

Require exporter `EXPORTED` with the exact event ID, collector snapshot 200,
and public `/v1/leaderboard/snapshot` 200 with the same network, anchor,
evidence digest and finalized reveal block. Verify actual rows, not merely
the page's HTTP status. Stop the testnet exporter before a single-feed mainnet
cutover so rehearsal data cannot replace production data.

## Dated live observations, not release acceptance

At 2026-10-05 22:23 UTC, the September 30 handoff's Hetzner host was reached
read-only: `cathedral-validator-direct.service` and
`sn94-testnet-validator.service` were active. The installed production archive
was `6021d599424ccd01cbd6114f948c8d815f3307e3f4b91d036cb3371830f926c8`,
source `1ab0530dc18ad612d8f45b752d948f8e29e64694`. No service was changed.
The production telemetry service/timer had no unit file installed, and `/run`
was mounted `noexec`. The public board's snapshot previously returned 404.
These observations explain the remaining operational work; they are not a
successful SN94 cutover or a populated leaderboard.

## Exact public-testnet rehearsal

Use a dedicated testnet-only wallet and the separately approved rehearsal
host/services. Do not reuse the Finney key. Run this **same signed release**
with `CATHEDRAL_TESTNET=1`, `--network test`, and `--netuid 584`; the exporter
needs the same environment and explicit netuid. Keep its spool and credentials
separate from production. Testnet mode keeps both release verifiers enabled.
It never enables the production updater or status unit for a testnet journal.
The testnet process is managed separately from the production signed channel.

First independently confirm the subnet's live commit-reveal policy matches
the selected opt-in. Require applied reveal, interrupted-cycle recovery and
the persistent not-applied stop against the installed digest. Then require
the exact exporter event acknowledgement, collector acceptance and public
testnet-labelled projection. A Python-signed fixture proves cross-language
serialization and signature compatibility only, never real hardware or chain
qualification. Stop the rehearsal feed before selecting the mainnet feed.
