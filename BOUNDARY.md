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
The upstream reproduction locks, release manifests, and public reproduction
paths all still resolve against the paths they already pin, which is the Phase 0
constraint in `REPO-SPLIT-PLAN.md`.

## Selection rule

The split plan's ownership test: *does it decide what goes on chain, or verify
what does?*

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
| `docs/` (13 of 20) | Validator docs |
| `VALIDATOR.md` | Primary validator operator doc |
| `weights_verify.py`, `postgres_verify.py`, `wire_compat.py`, `live_smoke.py` | Validator-owned root harnesses whose closure is satisfied here |

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
| `launch_readiness_verify.py`, `launch_readiness_report.py` | Launch-program tooling; `scaffold.launch_readiness` is outside the closure |
| `AUDIT_ARENA_V0.md`, `CATHEDRAL_V0_LANES.md`, `DISTILLATION_READINESS.md`, `LANE2_SECURE_COMPUTE_PLAN.md`, `LAUNCH_*.md`, `SOLVER_ATTESTATION_STATUS.md`, `TEE_GPU_CAPACITY.md` | Lane and launch planning docs |
| `README.md` (upstream) | Replaced with a derived-repo README |
| `railway.toml`, `deploy/Dockerfile`, `deploy/railway.toml`, `deploy/entrypoint.sh`, `deploy/requirements.txt` | Upstream deployment packaging; this repo is not a deploy source |
| `deploy/` planning docs, `deploy/observability`, `deploy/sandbox`, `deploy/canonical-validator-feed`, `deploy/v2-beta-router`, `deploy/weights-failover` | Not read by anything carried here |
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

## The `game.arena` back-edge

`REPO-SPLIT-PLAN.md` flags a bidirectional coupling: `game/publisher.py` imports
`scaffold.*`, and `scaffold/publisher/app.py` imports back into `game.arena` at
`:3764` and `:4211`.

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

Two, plus files that have no upstream counterpart.

| File | Change |
|---|---|
| `pyproject.toml` | Trimmed. See below |
| `README.md` | Rewritten for the derived repo |

Every other file carried here is **byte-identical** to its `fd02392d`
counterpart, verified with `cmp` across all 234 of them.

New files with no upstream counterpart: `BOUNDARY.md`, `.gitignore`,
`.github/workflows/tests.yml`, `tests/boundary/test_no_game_dependency.py`,
`tools/sync-from-upstream.sh`, `tools/upstream-manifest.txt`.

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

| Run | Result |
|---|---|
| Upstream `fd02392d`, `scaffold/publisher/tests tests/thin` | 44 failed, 1230 passed |
| Here, same suites plus `tests/boundary` | 45 failed, 1238 passed |
| **Fails here, passes upstream** | **1**, the deselected CI-config guard above |
| Fails upstream, passes here | 0 |

So with that one deselection applied, this repo is at failure parity with
upstream. The 44 shared failures are inherited and pre-date the extraction; they
come from running a suite that expects PostgreSQL and outbound network in an
environment with neither.

`tests/thin` alone: 128 passed. `tests/boundary` alone: 9 passed.

GitHub Actions on the initial commit: Python 3.11 success, Python 3.12 success,
publisher advisory job 35 failed / 1088 passed / 22 skipped / 1 deselected on
ubuntu. The ubuntu failure set is smaller than the macOS one, consistent with
these being environment-dependent. It has not been baselined against upstream on
ubuntu; the like-for-like comparison above was done on macOS.

CLI smoke, against the real production API:

```
cathedral-validator serve --config config/validator-mainnet-sn39.toml --offline --once
```

fetches the live signed vector from `https://api.cathedral.computer`, verifies
the signature against the pinned `cathedral-weight-policy` key, and passes the
freshness and rollback-fence checks before stopping at the synthetic UID map
that `--offline` substitutes for chain state. `cathedral-validator --help` and
`cathedral-candidate-snapshot --help` both work.

## Console-script name collision with the work repo

Not introduced here, but worth knowing before you install.

Both distributions declare a `cathedral-validator` console script:

| Distribution | Target |
|---|---|
| `cathedral-scaffold` (this repo, and upstream) | `scaffold.cli:main` |
| `cathedral` (from `cathedralconfidential`, pulled by the `provenance` extra) | `cathedral.neuron.validator:main` |

Whichever is installed last wins, and nothing declares which that should be.
Observed on Python 3.11:

| Command | `cathedral-validator` resolves to |
|---|---|
| `pip install -e '.[provenance]'` | `scaffold.cli:main`, correct |
| `uv pip install -e '.[provenance]'` | `cathedral.neuron.validator:main`, **wrong** |
| `uv pip install -e '.[test,publisher,provenance]'` | `scaffold.cli:main`, correct |

The middle row is the exact command in `VALIDATOR.md:111` and
`docs/PROVENANCE.md:116`, run with uv instead of pip. It produces a
`cathedral-validator` that is the work repo's neuron validator, which fails with
an argparse error about unknown subcommands rather than anything that points at
the real cause.

Check after installing:

```sh
grep 'import main' "$(dirname "$(command -v cathedral-validator)")/cathedral-validator"
```

It should print `from scaffold.cli import main`.

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
`BOUNDARY.md`, `pyproject.toml`, `.github/`, `tests/boundary/`, and `tools/`
survive untouched.

After a re-sync:

1. Re-apply any `pyproject.toml` change upstream made, by hand. The manifest
   deliberately does not carry `pyproject.toml`, so upstream edits to it are
   invisible to the script. Diff it every time:
   `git -C /tmp/cathedral-upstream show <sha>:pyproject.toml | diff - pyproject.toml`.
   The provenance pin in particular moves with releases.
2. Run `pytest tests/boundary`. It fails if the `game.arena` back-edge changed
   shape.
3. Run the full suite and compare the failure set against the same suite run
   in the upstream checkout. A test that fails here but passes there is an
   extraction defect, normally a data file a test reads by repo-relative path
   that the manifest does not carry yet.
4. Update the derived-from SHA at the top of this file and in `README.md`.
