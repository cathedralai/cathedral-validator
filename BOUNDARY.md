# Boundary

What this repo took from `cathedralai/cathedral`, what it left behind, and why.

## Deliberate divergence: the event-log group split (commit 04d6b3b)

This repo is no longer a pure byte-identical derivation. Seven upstream files
carry a corrective fix, declared in `tools/manifest.sh` and confirmed by
`manifest.sh verify` as divergences rather than drift.

The upstream deploy contract cannot hold as shipped. `scaffold/events.py`
refuses to open a group-readable event log, while
`deploy/sn39/cathedral-sn39-public-status.service` reads that same journal
through `SupplementaryGroups=cathedral-validator-log`. Satisfying either one
breaks the other, and `config/validator-mainnet-sn39.toml` is pinned by the
SN39 release manifest, so the path could not be adjusted in place.

The fix keeps the raw journal private (0600, no reader group) because it
carries hotkeys, receipts and arbitrary caller-supplied fields, and adds a
sanitized projection through a strict allowlist for the publisher to read.
The reader group moves to that surface. Files: `scaffold/events.py`,
`scaffold/cli.py`, `scaffold/validator_thin.py`,
`scripts/publish_sn39_validator_status.py`,
`config/validator-mainnet-sn39.toml`,
`deploy/sn39/cathedral-validator-sn39.service`,
`deploy/sn39/cathedral-sn39-public-status.service`, and
`deploy/sn39/cathedral-sn39-release-launcher.py`.

The launcher is part of this contract and not an afterthought: it builds the
COMPLETE environment for `os.execve`, so the unit's own `Environment=` never reaches
the child and whatever the launcher sets is the entire access decision. It once set
`CATHEDRAL_VALIDATOR_JSONL_GROUP` and never `CATHEDRAL_VALIDATOR_STATUS_GROUP`,
which inverted the split: the raw journal came out 0640 group-readable while the
projection stayed 0600 and unreadable by the reader it exists for.

Pinned by `tests/thin/test_status_sanitization.py`,
`tests/thin/test_status_stream_contract.py` (all three files together) and
`tests/thin/test_launcher_log_group_split.py`.

This should be upstreamed; until then, a re-sync must preserve it.

## Divergences retired at the `dabf10b` sync

Upstream absorbed four of the declared divergences, so they are no longer declared
and the files are byte-identical again.

**`config/validator-mainnet-sn39.toml` is NOT among them.** An earlier revision of
this section listed it as retired while the section above listed it as part of the
active status-split divergence, and that contradiction is what licensed a re-sync to
copy upstream over it: `[logs].status_jsonl` was dropped, nothing wrote the sanitized
projection, and `cathedral-sn39-public-status.service` could never satisfy its
`ConditionPathExists`, so systemd recorded the condition as skipped rather than
failed and the public status stream stopped silently. It remains declared, and
`tools/sync-from-upstream.sh` now refuses to overwrite any declared divergence.

| File | Why it can go |
|---|---|
| `config/validator-mainnet-sn39-launch.toml` | #407 moved `controlled_dir` to the value this repo already carried |
| `deploy/sn39/cathedral-validator-sn39-launch.service` | absorbed upstream |
| `deploy/sn39/cathedral-validator-sn39-reconcile.service` | absorbed upstream |
| `scripts/build_sn39_release_manifest.py` | see below — **partially** |

`scripts/build_sn39_release_manifest.py` is the one that needed a judgement call
rather than a merge. Upstream's #403-#406 rewrote `immutable_tree_digest` and, in
passing, **broadened** directory symlinks from "only a venv `lib64 -> lib`" to "any
symlink resolving inside the tree". Taking that wholesale would have loosened a
control as a side effect of a sync, so the narrowing is re-applied on top of
upstream's new ownership and mode checks, keeping upstream's `directory-symlink`
digest label and root-relative target so the commitment stays byte-identical to
upstream's for the shapes both accept. The file therefore stays a divergence, and
`tests/thin/test_release_manifest_venv_symlinks.py` fails if a future sync drops the
narrowing. Whether to keep narrowing is an owner decision; it is now a visible one.

## Retired: the authority-mode config no longer costs a publisher test

`config/validator-mainnet-sn39.toml` is a declared divergence and sets
`[provenance] mode = "authority"`. Upstream's copy is `shadow`.

This used to cost
`test_sn39_launch_gate_matrix.py::test_shipped_relay_profile_runs_without_a_launch`,
which asserted the shipped relay profile was byte-identical to the operator
profile across a list of trust-bearing fields -- and that list included
`provenance`. That is the one field the two profiles are *supposed* to disagree
on: a relay must stay `shadow`, while an operator running the authority lane
sets `authority`, and the difference is exactly what the launch gate is scoped
to. The assertion therefore said the opposite of its intent, and passed upstream
only because both shipped profiles happen to be `shadow`.

**Fixed upstream in `cathedral#422`** rather than forked here: `provenance` is
out of that list, and the relay's own guarantee is asserted directly
(`args.provenance == "shadow"`), which holds whatever the operator profile says.
Confirmed by reproducing the downstream condition in the upstream tree -- with
upstream's operator config temporarily set to `authority`, the test failed
before the change and passed after.

Measured after the fix: setting this repo's operator profile back to `shadow`
changes the publisher failure set **not at all**. The authority-mode divergence
costs zero tests. `test_mainnet_launch_bundle_is_byte_pinned_and_shadow_by_default`
still fails, but on the byte-pinning half -- the config diverges from the pinned
digest, which is true regardless of mode -- so it belongs to the section below.

## Known: the provenance pin's form costs one assertion, not one test

`pyproject.toml`'s `provenance` extra is pinned by commit SHA over `git+https://`,
while upstream pins the same commit as a GitHub tarball with a `#sha256=`. Both
resolve to identical bytes; only the addressing differs.

Upstream has no choice: its copy of that pin must match
`requirements/sn39-reproduction.lock`, and `pip --require-hashes` rejects VCS
requirements outright, so a hash-locked file cannot use a commit pin. This repo
does not carry that constraint into the extra, so it uses the form a repository
rename cannot invalidate — which is not hypothetical, since the tarball form is
exactly what broke in #16 and again in `cathedral#421`.

The cost is one assertion inside
`test_validator_two_mode.py::test_immutable_install_binds_venv_and_masks_legacy_writer`,
which requires `"#sha256=" + EXPECTED_CATHEDRAL_ARCHIVE_SHA256` to appear in
`pyproject.toml`. **It costs no additional test**: that test already failed here
before #22, on an earlier assertion about the log-group env split, so what changed
is which line it stops on. Verified by running it at `a369c9b` (pre-#22) and
reading the failure — `CATHEDRAL_VALIDATOR_STATUS_GROUP` vs
`CATHEDRAL_VALIDATOR_JSONL_GROUP`, not the pin.

## Known: the render divergence is now the WHOLE publisher failure set

`scaffold/render.py` is a local addition, and `scaffold/validator_thin.py` /
`scaffold/cli.py` diverge partly to drive it. Upstream's publisher tests assert the
plain-text journal (`FEED fetch source=...`); this repo emits the rendered one, so
they fail here and pass upstream.

**These are not extraction defects and they predate the `dabf10b` sync** — they
fail identically on the pre-sync tree. They were invisible before only because
upstream failed them too at `fd02392d`; upstream has since fixed them, which is what
made the gap appear.

### The current baseline, measured

In a fully provisioned environment (`[test,publisher,provenance]`, no PostgreSQL,
no outbound network) at derived-from `7f3888a`:

| | |
|---|---|
| Upstream `scaffold/publisher/tests` | **1393 passed, 0 failed** |
| Here | **26 failed, 1366 passed** |

All 26 sit in exactly three files — `test_validator_two_mode.py` (16),
`test_validator_thin_validated_supply.py` (9), `test_validator_lifecycle.py` (1) —
and every one of them is this divergence. Nothing else in the publisher suite fails
here any more, so the comparison rule below has become sharp: **a failure outside
those three files is new, and a failure inside them should be checked against this
list rather than assumed.**

### The rule caught something the day it was written

The first CI run after this was documented reported **22**, not 21 -- one extra,
in `test_solution_manifest_v2.py`, a fifth file. That is precisely what the rule
says to look at, and looking was right.

It was a test whose forgery did not always forge. It tampered with a submit
token by replacing the last base64 character, but the signature is a 32-byte
HMAC in unpadded base64url: 43 characters carrying 258 bits, of which decoding
discards 2. So `{A,B,C,D}` all decode to the same 32 bytes, and whenever the real
last character was one of those four the "forged" token was still valid and the
submission was accepted. 4 of 64 characters, ~6.2% of runs, verified
exhaustively across the whole alphabet.

It passed locally in three different environments and had not appeared in the
two previous CI runs, so on its own it read as drift. Fixed upstream in
`cathedral#424` by flipping a bit in the DECODED signature, and asserting the
forged token actually differs before sending it. 0/64 after.

Worth recording for what it says about this baseline: **a deterministic count is
not a deterministic suite.** What found this was comparing against a known SET,
not a known number -- a count of 22 means nothing without knowing 21 of them were
expected and which the twenty-second was.

Getting here removed four separate causes that used to be mixed into the number,
each of which had been read at some point as "inherited, environmental":

| Was failing | Actually |
|---|---|
| ~34 across many files | one process-wide rate limiter shared by the whole session (`cathedral#420`) |
| `test_sn39_launch_gate_matrix.py` | a test coupling the relay profile to the operator's `provenance` (`cathedral#422`) |
| `test_confidential_cpu_publisher_canary.py` (3) | the canary could not import its dependencies inside a venv at all (`cathedral#423`) |
| `test_v2_solver_metadata.py` (3) | tests predating the thin-admit split (`cathedral#423`) |
| `test_snapshot_candidates.py` | needed the `provenance` extra, which could not install (#16 / #22) |

So the real cost of the render divergence is now written down without anything
else hiding inside it: either the renderer gets upstreamed, or those 26
assertions stay red here.

## Derived-from

| | |
|---|---|
| Upstream | `cathedralai/cathedral` |
| Extraction started at | `c8028af479861a61072b20fc2f93620b9c599fe7` (#398) |
| **Current derived-from SHA** | **`7864c2787c74c3d5fdf2ac4e1795dbcbaecf035c`** (#424, "the forged submit token did not always forge") |
| Previous derived-from | `7f3888a8ff93105e8c717b830bd1d70e23f6a58f` (#423, canary virtualenv fix) |
| Previous derived-from | `aa791358601f9ef2e95c5ac5e717c77c17963dbd` (#420, per-test rate-limit budget) |
| Before that | `ebc65f0de6e01b6582f25fe71bf0b3ac4f04ad51` (#418, compose-time staleness ceiling) |
| Before that | `5c380162ba1a786ebf8c7f5ca70941e9688ce2ba` (#413, CyberGym scores bridge) |
| Before that | `dabf10bcd5de76b6f98a6ce6772df2fc063da8db` (#417, "give artifact adapters the publisher DB, not the mechanism DB") |
| Before that | `fd02392dc969bbea09e3107febb64f1f5f748391` (#399) |

This table is prose and a human keeps it current, so it can go stale — and it did.
Between the `5c38016` sync and the `ebc65f0` one, `README.md` still said `dabf10b`
while `MANIFEST.origin.tsv` already said `5c38016`, and nothing complained. The
manifest is the machine-checked record: CI reads the SHA out of it, clones upstream
at exactly that commit, and fails if a single mirrored byte differs. **When this
table and the manifest disagree, the manifest is right.** Step 6 of the re-sync
checklist below exists to keep them from disagreeing at all.

Work began at `c8028af`. `fd02392d` merged mid-extraction, so the tree was
re-synced to it before the first commit. Everything here reflects `fd02392d`.
The `fd02392d` merge moved the provenance pin, rewrote the sn39 sysusers and
tmpfiles unit names, and added `docs/SN39_LAUNCH_CUTOVER_20260726.md`; all three
are carried here.

Nothing in the upstream repo was modified, moved, or deleted. This is a copy.
That matters because three things pin current upstream paths: the reproduction
lock (`requirements/sn39-reproduction.lock`) pins the work repo as a GitHub
archive at an exact commit, the release manifest and file digests are computed
over the current tree, and the public reproduction path verifies against
specific paths. A derived copy at new paths breaks none of them. Moving or
deleting anything upstream would break all three.

## Selection rule

The ownership test used throughout: **does it decide what goes on chain, or
verify what does?** If yes, it belongs to the validator and is carried here. If
it instead produces scored work or the evidence for it, it belongs to the work
lanes and stays upstream.

Applied mechanically rather than by judgement wherever possible. The included
Python set is the **import closure** of the validator entry points plus the
publisher, computed from the AST of every import statement in the tree, not
from a hand-written list. Data files were added where a shipped test reads them
from a repo-relative path.

## Included top-level paths

| Path | Why |
|---|---|
| `scaffold/` (17 modules + 3 of `lanes/`) | The validator import closure |
| `scaffold/publisher/` (whole, incl. `tests/`) | Validator side per the split plan |
| `cathedral_thin/` | Thin validator package |
| `tests/thin/` | Thin validator tests |
| `tests/boundary/` | New here: proves the SAT lane stays out |
| `deploy/sn39/`, `deploy/thin/` | Validator systemd units |
| `deploy/edge-router/` | Asserted on by `test_miner_error_contract.py` |
| `deploy/golden/` | Golden ingress vector, asserted on by two v2 ingress tests |
| `config/` (whole) | Pinned provenance key bundles, validator configs, policy examples |
| `requirements/` | Reproduction and build locks, asserted on by the shipped tests |
| `scripts/` (11 of 22) | Validator-owned; every one is referenced by a shipped test |
| `fixtures/` | Publisher test fixtures |
| `docs/` (13 of 20 top-level entries) | Validator docs. 12 `.md` files plus the `docs/evidence/` directory, which counts as one entry and holds 6 files, so 18 files in total |
| `VALIDATOR.md` | Primary validator operator doc |
| `weights_verify.py`, `wire_compat.py` | Validator-owned root harnesses. See the sorting below |

`scaffold/` modules included: `__init__`, `chain`, `cli`, `contract`, `dimacs`,
`events`, `grading`, `polaris`, `provenance_audit`, `sn39_continuous_authorization`,
`sn39_public_reproduction`, `snapshot_candidates`, `solve_real`, `validator_thin`,
`verify`, `wire`, `wire_vector`, plus `lanes/__init__`, `lanes/sandbox`,
`lanes/solver_arena`.

## Excluded top-level paths

| Path | Reason |
|---|---|
| `game/` | SAT lane. See the back-edge section below |
| `hunt-board/` | Lane tooling, no validator import reaches it |
| `assets/` | Marketing and lane assets, nothing here reads them |
| `arena_runner_verify.py`, `audit_arena_verify.py` | Arena lane harnesses |
| `assigned_lane_verify.py` | SAT lane assignment harness |
| `attest_verify.py`, `tee_gpu_verify.py` | Lane 2 secure-compute harnesses |
| `distillation_verify.py` | Distill lane harness |
| `rc_verify.py` | Imports `scaffold.harness`, `lanes.arena_e2e`, `lanes.encoding`, `lanes.sat_challenge`: all SAT-lane modules not carried here |
| `publisher_verify.py` | See the back-edge section below |
| `live_smoke.py` | Miner-side. Drives the miner write path over HTTP against a **deployed** publisher: picks a challenge off the board, signs as `//SmokeMiner`, fetches the CNF, submits an assignment. It does not decide what goes on chain or verify what does, it exercises the SAT submission path, and it cannot run without a live host |
| `postgres_verify.py` | Storage-layer integration gate. Needs a real PostgreSQL via `DATABASE_URL` and proves the Store's SQLite and Postgres backends agree. One step removed from the chain decision, and a sibling of the already-excluded `publisher_verify.py`, `tee_gpu_verify.py`, and `attest_verify.py` in upstream's `launch-readiness.yml` |
| `launch_readiness_verify.py`, `launch_readiness_report.py` | Launch-program tooling; `scaffold.launch_readiness` is outside the closure |
| `AUDIT_ARENA_V0.md`, `CATHEDRAL_V0_LANES.md`, `DISTILLATION_READINESS.md`, `LANE2_SECURE_COMPUTE_PLAN.md`, `LAUNCH_*.md`, `SOLVER_ATTESTATION_STATUS.md`, `TEE_GPU_CAPACITY.md` | Lane and launch planning docs |
| `README.md` (upstream) | Replaced with a derived-repo README |
| `railway.toml`, `deploy/Dockerfile`, `deploy/railway.toml`, `deploy/entrypoint.sh`, `deploy/requirements.txt` | Upstream deployment packaging; this repo is not a deploy source |
| `deploy/` operator utilities: `check_env_surface.py`, `check_env_template.py`, `export_minimal_state.py`, `import_minimal_state.py`, `railway-split.ps1`, `.env.example` | Environment and state-migration tooling for the upstream deployment. Nothing carried here reads them, and this repo is not a deploy source |
| `deploy/` planning and review docs (26 `.md` files), `deploy/observability`, `deploy/sandbox`, `deploy/canonical-validator-feed`, `deploy/v2-beta-router`, `deploy/weights-failover` | Not read by anything carried here |
| `.github/workflows/*` (upstream) | Upstream CI, including the cross-repo provenance job. Replaced with one workflow |
| `.gitattributes`, `.dockerignore` | Only govern files this repo does not carry |

Excluded `scaffold/` modules, none reachable from any validator or publisher
entry point: `consensus`, `dashboard`, `demo`, `distillation`, `harness`,
`launch_readiness`, `live`, `pinning`, `registry`, `shadow`, `specimen`,
`timing`, `validator` (the pre-thin validator), and `lanes/arena_e2e`,
`lanes/audit_arena`, `lanes/encoding`, `lanes/encoding_real`,
`lanes/sat_challenge`, `lanes/solver_docker`.

Excluded `scripts/`: `ARENA_RUNNER.md`, `bench_solution_manifest_v2.py`,
`cathedral_live_table.py`, `frontier_phase_a_demo.py`,
`generate_v2_bitset_ingress_golden.py`, `v2_bitset_capacity_probe.py`,
`v2_bitset_miner_e2e.py`, `v2_edge_staged_soak.py`, `v2_lean_ingress_e2e.py`,
`v2_miner_e2e.py`, `verify_ephemeral_postgres.sh`. All are miner-lane or
operator probes that no shipped test exercises.

Excluded `docs/`: `FAST_PATH_MINER_GUIDE.md`, `SAT_FAST_10PCT.md`,
`V2_BITSET_READY_FOR_TESTING.md`, `V2_MINER_E2E_GUIDE.md` (miner lane), and
`THIN_SUBNET_FABLE_REVIEW.md`, `VERIFIED_POLICY_FABLE_REVIEW.md`,
`VERIFYML_FABLE_REVIEW.md` (point-in-time review notes).

### Sorting the root `*_verify.py` harnesses

The split plan asks for these to be sorted by lane, with validator-owned ones
kept. Applying the ownership test to all thirteen:

| Harness | Kept | Why |
|---|---|---|
| `weights_verify.py` | yes | Smoke tests `scaffold.publisher.weights`. Weights are exactly what goes on chain. Runs offline against a generated test key |
| `wire_compat.py` | yes | Proves `scaffold/wire.py` still matches what live SN39 validators verify. Offline by default against the shipped `fixtures/live-20260609/` capture, which is why `fixtures/` is carried |
| `publisher_verify.py` | no | Module-scope `game.arena` import, see below |
| `live_smoke.py` | no | Miner write path against a deployed host |
| `postgres_verify.py` | no | Needs a live PostgreSQL; storage layer, not the chain decision |
| `rc_verify.py` | no | Imports four SAT-lane modules not carried here |
| `arena_runner_verify.py`, `audit_arena_verify.py` | no | Arena lane |
| `assigned_lane_verify.py` | no | SAT lane assignment |
| `attest_verify.py`, `tee_gpu_verify.py` | no | Lane 2 secure compute |
| `distillation_verify.py` | no | Distill lane |
| `launch_readiness_verify.py` | no | Launch-program tooling; `scaffold.launch_readiness` is outside the closure |

None of the thirteen is referenced by any shipped test, so this sorting is a
judgement call rather than something the test suite forces. The two kept are the
two that verify chain-facing artifacts and run without external services.

## The `game.arena` back-edge

Upstream, `game/` and `scaffold/` are coupled in both directions:
`game/publisher.py:20-25` imports `scaffold.dimacs`, `scaffold.grading`,
`scaffold.lanes.sandbox`, `scaffold.polaris`, `scaffold.publisher`, and
`scaffold.verify`; and `scaffold/publisher/app.py` imports back into
`game.arena` at `:3764` and `:4211`. That back-edge is the reason a validator
extraction is not simply "copy `scaffold/`".

**Decision: keep `app.py` byte-identical and do not ship `game/`.**

The evidence, in order of strength:

1. **Both imports are function-local.** `:3764` sits inside
   `build_app() > _audit_scanner_module()`; `:4211` sits inside
   `build_app() > audit_scanner_differential()`. Defining a function does not
   execute its body, so importing or building the app never evaluates either
   statement.
2. **They are the only `game.*` edges in the entire shipped tree.** An AST walk
   over the validator entry points, the whole publisher, `cathedral_thin/`, and
   every shipped test finds exactly two `game.*` import sites, both the ones
   above. Every other `game.arena.*` module the plan mentions is reachable only
   *through* those two edges, from inside `game/` itself.
3. **A feature gate refuses ahead of them.** Every audit-scanner route calls
   `_require_audit_scanner_enabled()`, which raises `HTTPException(404)` unless
   `CATHEDRAL_AUDIT_SCANNER_ENABLED` is set. It is unset by default.
4. **No shipped test imports `game`.**

`tests/boundary/test_no_game_dependency.py` holds all four claims to account at
runtime, including a negative control that turns the feature flag on and asserts
the route fails rather than serving. If a future sync makes either import
module-level, or adds a third `game.*` edge anywhere, those tests fail and this
decision has to be revisited.

The audit-scanner endpoints are SAT-lane functionality. They belong with the
lane, which is why the minimal-`game.arena`-subset alternative was not taken.

### Why `publisher_verify.py` is excluded

It is the one validator-owned root harness that does *not* clear the bar above.
Its audit-scanner bridge does `from game.arena import audit_scanner_smoke` at
`:632` at **module scope** (inside a `with` at `:204`, wrapped in a `try` whose
`except Exception` prints and continues). So it would still run here, but its
audit-scanner section would report a soft failure on every invocation, in a
release-verification script whose job is to report pass or fail. A harness that
always half-fails is worse than an absent one. It runs correctly upstream, where
`game/` is present, and that is where it should stay until the back-edge is
broken for real.

## Files that differ from upstream

Two.

| File | Change |
|---|---|
| `pyproject.toml` | Entry points trimmed. See below. Name, version, dependencies, and all three extras including the provenance pin are untouched |
| `README.md` | Rewritten for the derived repo |

Every other carried file is **byte-identical** to its `fd02392d` counterpart:
**249 files**. `.gitignore` was rewritten in an earlier pass and has since been
restored to upstream's exact bytes, because upstream's already covers everything
this repo generates.

**Nine** files have no upstream counterpart. These are additions rather than
divergences: `BOUNDARY.md`, `REVIEW.md`, `MANIFEST.sha256`,
`MANIFEST.origin.tsv`, `.github/workflows/tests.yml`,
`tests/boundary/test_no_game_dependency.py`, `tools/manifest.sh`,
`tools/sync-from-upstream.sh`, `tools/upstream-manifest.txt`.

`MANIFEST.origin.tsv` shows only **seven** of them as `origin=local`, because
the two manifest files are excluded from the manifest: a file cannot contain its
own hash. Nine files, seven rows. 249 + 2 + 9 = 260 tracked files.

## Machine-checkable origin manifest

`MANIFEST.origin.tsv` records, for every tracked file: its path, its sha256, an
origin class (`identical`, `modified`, or `local`), its upstream path at
`fd02392d`, and the upstream file's sha256. `MANIFEST.sha256` is the same hashes
in `sha256sum` format so local integrity can be checked with a standard tool.

The point is that byte-identity is verifiable without trusting this repo: clone
upstream at `fd02392d`, hash it yourself, and compare.

```sh
./tools/manifest.sh verify /path/to/cathedral-upstream
```

Rebuild after any sync with `./tools/manifest.sh build /path/to/cathedral-upstream`.
Both manifest files exclude themselves, since a file cannot contain its own hash.

### `pyproject.toml` diff from upstream

- `[project.scripts]`: dropped `cathedral-game`, `cathedral-arena`,
  `cathedral-arena-audit`, `cathedral-arena-serve`, `cathedral-arena-verify`,
  `cathedral-arena-playthrough`, `cathedral-arena-round-verify`,
  `cathedral-audit-scanner-smoke` (all target `game/`, not carried);
  `cathedral-thin-miner` and `cathedral-thin-contributor` (miner lane);
  `cathedral-verifyml`. Kept `cathedral-validator`,
  `cathedral-candidate-snapshot`, `cathedral-thin-validator`,
  `cathedral-thin-e2e`, `cathedral-thin-preflight`,
  `cathedral-thin-score-report`, `cathedral-verified-policy`.
  The `cathedral_thin` modules behind the dropped entries are still importable,
  because the package is copied whole. Only the console scripts are withheld.
- `[tool.setuptools.packages.find]`: `include` drops `game*`; the
  `exclude = ["game.tests*", "game.arena.tests*"]` line goes with it.
- Everything else is unchanged, including `name`, `version`, the runtime
  dependencies, the `publisher` and `test` extras, and the `provenance` extra
  with its sha256-locked `cathedralconfidential` pin
  (`655c264421a1f5f2e625a372a40f595aa1e114ab`), carried verbatim from
  `fd02392d`.

The distribution name stays `cathedral-scaffold` deliberately: this is the same
package, built from a subset of the same tree, so a future cutover is a remote
change rather than a rename.

## Known deselected test

`scaffold/publisher/tests/test_validator_two_mode.py::test_required_ci_collection_gate_returns_zero`
reads `.github/workflows/two-mode-provenance.yml` and asserts on its text. That
workflow is upstream CI infrastructure: it builds the hash-locked environment
and runs the work repo's tests from a sibling `cathedralconfidential` checkout.
This repo does not carry it, so the guard has nothing to guard and is deselected
in CI. It is the only deselection.

## Verification

Method: run the same suites in this repo and in an upstream checkout at
`fd02392d`, on the same machine, same Python 3.11.14, same resolved package set,
then diff the failure sets. Anything failing here but passing there is an
extraction defect.

**Compare failure SETS, not counts** — but the reason written here was wrong, and
the wrong reason is worth keeping visible.

This section used to say the count was unstable because the failures "are
dominated by tests that need PostgreSQL and outbound network", citing 44, 43 and
once 15 failures on one machine within an hour, "depending on network
conditions". The instability was real. The explanation was not.

A run of this suite produces **zero** psycopg2 or connection errors — measured,
not assumed, and reported independently from a clean Hetzner box before being
reproduced here. The variance came from `ratelimit._state`, a process-wide
limiter keyed on client IP that under `TestClient` is the same `testclient` for
every request in the session: one 120-request, 60-second budget shared by ~1300
tests running in about 60 seconds. The count therefore moved with **machine
speed**, which is exactly the "depending on network conditions" pattern
misdiagnosed above. Three machines measured the same bug as 69, 64 and 62.

Fixed upstream in `cathedral#420`, so **the count is now deterministic**: one
process and one-file-per-process produce the identical set, confirmed on two
machines. Compare sets anyway — a count cannot tell you that a new failure
replaced an old one.

The lesson generalises: an explanation that predicts the wrong *shape* of
variance is wrong even when the variance is real. "Needs a database" does not
predict a number that changes with how the run is split across processes, and
nobody checked.

**Compare failure sets, back to back, same session.** Latest, publisher suite
with the one deselection, control run immediately before:

At the `dabf10b` sync the right control is **this repo before the sync**, not
upstream: upstream fixed tests in those 11 commits that this repo's render divergence
still fails, so an upstream comparison now shows a gap that the sync did not cause.

| Run | Failures |
|---|---|
| Here, **pre-sync** (`873621a`) | 60 |
| Here, **post-sync** (`dabf10b`) | 56 |
| **New failures introduced by the sync** | **0** |
| Failures the sync fixed | 4 |

Against upstream `dabf10b` (38 failures) there are 18 that fail here and pass there.
**All 18 also fail on the pre-sync tree**, so none is a sync defect; they are the
render divergence, recorded above. The `fd02392d` extraction comparison — 43 vs 43,
byte-identical failure sets, 0 either way — still stands as the extraction's own
baseline. The one extraction-induced failure,
`test_required_ci_collection_gate_returns_zero`, is the deselected upstream-CI guard
described above.

`tests/thin` and `tests/boundary` together: **137 passed** (128 and 9). These are
stable; they need no network.

GitHub Actions on the initial commit: Python 3.11 success, Python 3.12 success,
publisher advisory job 35 failed / 1088 passed / 22 skipped / 1 deselected on
ubuntu. The ubuntu failure set is smaller than the macOS one, consistent with
these being environment-dependent. It has not been baselined against upstream on
ubuntu; the like-for-like comparison above was done on macOS.

CLI smoke, run once on 2026-07-27:

```
cathedral-validator serve --config config/validator-mainnet-sn39.toml --offline --once
```

fetched the live signed vector from `https://api.cathedral.computer`, verified
the signature against the pinned `cathedral-weight-policy` key, and passed the
freshness and rollback-fence checks before stopping at the synthetic UID map
that `--offline` substitutes for chain state. `cathedral-validator --help` and
`cathedral-candidate-snapshot --help` both work.

That run was a **read-only HTTPS GET** against a public endpoint: no
`--broadcast`, no chain write, no wallet or key material, no state changed
anywhere. It is recorded here as evidence that the extracted tree verifies
production evidence end to end. It is **not** part of the review procedure, and
`REVIEW.md` does not ask anyone to repeat it. Reviewing this repo requires no
network access beyond cloning upstream and installing packages.

## Console-script name collision with the work repo

Not introduced here, but worth knowing before you install.

Both distributions declare a `cathedral-validator` console script:

| Distribution | Target |
|---|---|
| `cathedral-scaffold` (this repo, and upstream) | `scaffold.cli:main` |
| `cathedral` (from `cathedralconfidential`, pulled by the `provenance` extra) | `cathedral.neuron.validator:main` |

Whichever is installed last wins, and nothing declares which that should be.

**With uv the outcome is not deterministic.** Repeated identical invocations
into a fresh venv resolve differently run to run. Measured on Python 3.11.14,
uv 0.9.9, pip 26.1.2, one clean venv per run:

| Command | Runs | `scaffold.cli:main` (correct) | `cathedral.neuron.validator:main` (**wrong**) |
|---|---|---|---|
| `pip install -e '.[provenance]'` | 3 | 3 | 0 |
| `uv pip install -e '.[provenance]'` | 4 | 2 | 2 |
| `uv pip install -e '.[test,publisher,provenance]'` | 9 | 5 | 4 |

An earlier revision of this document claimed each command had a fixed outcome,
with the all-extras uv form landing on the correct entry point. That was an
artifact of a single observation each. It is wrong: uv's result varies across
identical runs, and the extras set does not determine it. pip put the local
editable project last in every run observed, but three runs is not a guarantee
of ordering either.

Non-determinism is worse than a consistent failure. A one-time check on one
machine proves nothing about the next install, two operators running the same
documented command can end up with different binaries, and an environment that
worked can come back wrong after a rebuild.

`uv pip install -e '.[provenance]'` is the exact command in `VALIDATOR.md:111`
and `docs/PROVENANCE.md:116`. When it loses, `cathedral-validator` is the work
repo's neuron validator and fails with an argparse error about unknown
subcommands, which points nowhere near the real cause.

**Required after every install**, not a fallback:

```sh
grep 'import main' "$(dirname "$(command -v cathedral-validator)")/cathedral-validator"
```

It must print `from scaffold.cli import main`. If it prints
`from cathedral.neuron.validator import main`, reinstall this project last with
`python -m pip install -e . --no-deps` and check again before running anything.

The real fix belongs upstream: the two distributions need distinct console-script
names, or the validator's entry point needs a name the work repo does not also
claim. Until then this check is the only thing standing between an operator and
a silently wrong binary.

## Re-sync procedure

One-way, upstream to here. Never the reverse: nothing in this repo is a source
for `cathedralai/cathedral`.

```sh
git clone https://github.com/cathedralai/cathedral.git /tmp/cathedral-upstream
git -C /tmp/cathedral-upstream checkout <new-sha>

./tools/sync-from-upstream.sh /tmp/cathedral-upstream . tools/upstream-manifest.txt
```

The script deletes each manifest path before recopying, so upstream deletions
propagate. It touches nothing outside the manifest, so `README.md`,
`BOUNDARY.md`, `pyproject.toml`, `.gitignore`, `.github/`, `tests/boundary/`,
and `tools/` survive untouched.

### Two traps the sync script had, and now does not

Both were found by actually running a re-sync at `dabf10b`. Both were silent.

**1. It deleted every local addition inside a synced directory.** Ten manifest
entries are directories, and the script cleared each with `rm -rf` before recopying.
Local files live inside several of them — the whole integration lane is
`cathedral_thin/integration*.py` plus `tests/thin/test_integration_*.py`, none of
which exists upstream. Measured on the real tree: **0 of 22 tracked local files
survived**, and the script exited 0. `BOUNDARY.md` promised only that a re-sync
"touches nothing outside the manifest", which was true and beside the point.

Removals are now driven by `MANIFEST.origin.tsv`: only paths classed `identical` or
`modified` are cleared, so an upstream deletion still propagates while a `local`
addition survives. The script then asserts every `local` path still exists and aborts
if one is missing, and refuses to run at all if the origin manifest is absent rather
than guessing. `tools/sync-from-upstream.sh selftest <upstream>` proves all four
properties.

**2. It overwrote the declared divergences.** They are classed `modified`, so the
clear-and-recopy replaced them with upstream's versions — including the event-log
group split this file says "a re-sync must preserve". `manifest.sh verify` catches it
(`DECLARED DIVERGENCE NOT FOUND AS modified`), so it is loud rather than silent, but
the work of reconciling is manual. The procedure below now says so.

### Three files sit outside the manifest and will silently drift

The sync script cannot see upstream changes to these, because they are not
manifest entries. **Diff all three by hand on every sync.**

| File | Why it is outside | What to do |
|---|---|---|
| `pyproject.toml` | Deliberately divergent (entry points trimmed) | Diff and re-apply upstream's changes by hand. The provenance pin moves with releases, so this is the one that matters most |
| `README.md` | Deliberately divergent (rewritten) | Update the derived-from SHA in the header |
| `.gitignore` | **Byte-identical to upstream, but not a manifest entry** | Diff it. Because it is not carried by the script and not a declared divergence, an upstream change to it produces no signal anywhere. `manifest.sh verify` will still classify it `identical` against the *new* upstream and pass, so nothing catches the drift except this step |

```sh
for f in pyproject.toml README.md .gitignore; do
  echo "--- $f"
  git -C /tmp/cathedral-upstream show HEAD:"$f" | diff - "$f" || true
done
```

`.gitignore` is the trap here. It is currently identical to upstream, so it looks
like a carried file, but it is not in `tools/upstream-manifest.txt`. If upstream
edits it, this repo keeps the old copy indefinitely and every check still passes.
Either diff it each sync, or add it to the manifest and accept that the sync
script will overwrite it.

### After a re-sync

1. Diff the three files above.
1b. **Reconcile the declared divergences.** `manifest.sh verify` lists any that came
   back as `identical`, which means the sync overwrote the local fix. For each, 3-way
   merge base=`<old derived-from>`, ours=pre-sync HEAD, theirs=`<new derived-from>`:

   ```sh
   git -C /tmp/cathedral-upstream show <old-sha>:"$f" > /tmp/base
   git show HEAD:"$f" > /tmp/ours
   git -C /tmp/cathedral-upstream show <new-sha>:"$f" > /tmp/theirs
   cp /tmp/ours "$f" && git merge-file "$f" /tmp/base /tmp/theirs
   ```

   At `dabf10b`, 9 of the 14 in-manifest divergences had upstream changes: 7 merged
   cleanly, 2 conflicted, and 5 turned out to be absorbed upstream and were retired.
   A conflict means upstream changed the same lines the local fix touches — decide
   deliberately, and if the local rule is *narrower* than upstream's, keep it rather
   than letting a sync loosen a control.
2. `./tools/manifest.sh build /tmp/cathedral-upstream` then
   `./tools/manifest.sh verify /tmp/cathedral-upstream`. The build refuses to
   write a manifest containing an undeclared divergence, so a file that changed
   here but not upstream stops the sync rather than being blessed.
3. `./tools/manifest.sh selftest /tmp/cathedral-upstream` to confirm the gate
   still rejects tampering.
4. `pytest tests/boundary`. It fails if the `game.arena` back-edge changed shape.
5. Run the full suite and compare the failure set against the same suite run in
   the upstream checkout. A test that fails here but passes there is an
   extraction defect, normally a data file a test reads by repo-relative path
   that the manifest does not carry yet.
6. Update the derived-from SHA at the top of this file and in `README.md`.
