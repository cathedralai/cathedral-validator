# Boundary

What this repo took from `cathedralai/cathedral`, what it left behind, and why.

## Derived-from

| | |
|---|---|
| Upstream | `cathedralai/cathedral` |
| Extraction started at | `c8028af479861a61072b20fc2f93620b9c599fe7` (#398) |
| **Final derived-from SHA** | **`fd02392dc969bbea09e3107febb64f1f5f748391`** (#399, "Reconcile the producer revision and make the deploy contract migration-safe") |

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

**The absolute failure count is not stable and must not be used as the check.**
The publisher suite's inherited failures are dominated by tests that need
PostgreSQL and outbound network. Across runs on one machine within an hour, the
same suite produced 44, 43, and once 15 failures depending on network conditions.
Comparing a run here against a number written down earlier proves nothing.

**Compare failure sets, back to back, same session.** Latest, publisher suite
with the one deselection, control run immediately before:

| Run | Result |
|---|---|
| Upstream `fd02392d` | 43 failed, 1102 passed, 1 deselected |
| Here | 43 failed, 1102 passed, 1 deselected |
| **Fails here, passes upstream** | **0** |
| Fails upstream, passes here | 0 |
| Failure sets | **byte-identical** |

So the extraction introduces no failures at all in the publisher suite. The one
extraction-induced failure that does exist, `test_required_ci_collection_gate_returns_zero`,
is the deselected upstream-CI guard described above; without the deselection the
counts are 44 here against 43 upstream.

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
