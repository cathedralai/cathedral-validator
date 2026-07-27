# Review packet

What to check to trust this repository, and how to check it without taking
anyone's word for it. Budget about twenty minutes.

## What this repo claims

1. It is a **copy** of the validator part of `cathedralai/cathedral` at
   `fd02392dc969bbea09e3107febb64f1f5f748391`. Upstream was not modified.
2. Every carried file is **byte-identical** to upstream except `pyproject.toml`
   and `README.md`, which are deliberately altered, plus a handful of files that
   have no upstream counterpart.
3. It **does not need the SAT lane** (`game/`) to run, even though the copied
   `scaffold/publisher/app.py` contains two `game.arena` imports.
4. It is **not** the authoritative validator source and nothing is deployed from
   it.

Claims 1 to 3 are mechanically checkable. Claim 4 is a policy statement; the
only thing to verify is that nothing here contradicts it.

## Check 1: byte-identity against upstream

The point of this check is that you do not have to trust the manifest, the
commit history, or this document. You hash upstream yourself.

```sh
git clone https://github.com/cathedralai/cathedral.git /tmp/cathedral-upstream
git -C /tmp/cathedral-upstream checkout fd02392dc969bbea09e3107febb64f1f5f748391

./tools/manifest.sh verify /tmp/cathedral-upstream
```

Expected output, exactly:

```
== local integrity ==
  all tracked files match MANIFEST.sha256
  manifest covers exactly the tracked file set
== upstream byte-identity ==
  manifest records fd02392dc969bbea09e3107febb64f1f5f748391
  checkout is      fd02392dc969bbea09e3107febb64f1f5f748391
  249 files confirmed byte-identical to upstream
```

`MANIFEST.origin.tsv` classifies every tracked file as `identical`, `modified`,
or `local`, and records both hashes. To see the full divergence in one line:

```sh
awk -F'\t' '$3!="identical" && !/^#/ && $1!="path" {print $3, $1}' MANIFEST.origin.tsv
```

Expected, and nothing else (260 tracked files, of which the two manifest files
are excluded from the manifest because a file cannot contain its own hash):

```
local    .github/workflows/tests.yml
local    BOUNDARY.md
modified README.md
local    REVIEW.md
modified pyproject.toml
local    tests/boundary/test_no_game_dependency.py
local    tools/manifest.sh
local    tools/sync-from-upstream.sh
local    tools/upstream-manifest.txt
```

Two modified files, seven additions, 249 untouched.

Then read the two modified files' diffs. They are small:

```sh
diff /tmp/cathedral-upstream/pyproject.toml pyproject.toml
```

Expected: dropped console-script entries pointing at `game/` and the miner lane,
`game*` removed from `packages.find`, and an explanatory comment. **No change to
`name`, `version`, `dependencies`, or any of the three extras.** In particular
the `provenance` extra's sha256-locked `cathedralconfidential` pin
(`655c264421a1f5f2e625a372a40f595aa1e114ab`) must be character-for-character
what upstream has at `fd02392d`.

If that pin differs, stop. Everything downstream of it is unverified.

## Check 2: nothing was taken from the wrong commit

An earlier draft of this extraction was built from `c8028af4`, the commit before
`fd02392d`. That commit had a different provenance pin, different sn39
sysusers/tmpfiles unit names, and no cutover doc.

```sh
grep -c fa39af97e738fdbed5c454f976b61246590b5794 pyproject.toml   # expect 0
ls deploy/sn39/cathedral-sn39-validator.sysusers                  # expect present
ls deploy/sn39/cathedral-sn39.sysusers 2>/dev/null                # expect absent
ls docs/SN39_LAUNCH_CUTOVER_20260726.md                           # expect present
```

Check 1 subsumes this, since a stale file would hash differently. These are the
quick spot-checks if you only do one thing.

## Check 3: the SAT lane really is unnecessary

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[test,publisher]"
python -m pytest -q tests/boundary
```

Expected: 9 passed.

Read `tests/boundary/test_no_game_dependency.py` before trusting it. It asserts,
in order: `game/` is absent from the tree; `game` is not importable; no file in
the repo imports `game` at module level; the set of `game.*` import sites is
**exactly** `{app.py:3764, app.py:4211}`; no shipped test imports `game`; every
console-script target imports cleanly.

The last three tests run in a fresh subprocess with a clean environment. That is
deliberate: the publisher keeps process-global state (rate limiter counters,
warm caches) and an earlier in-process version of this test failed with a 429
that had nothing to do with the boundary. If you see these tests build an app
in-process, you are reading a stale copy.

The negative control matters most. `test_enabling_the_audit_scanner_is_what_would_need_the_sat_lane`
turns the feature flag on and asserts the route fails **and** that `game` is the
missing module. Without it, the other tests are consistent with the routes being
broken for some unrelated reason.

The reasoning behind the decision is in `BOUNDARY.md`, section "The `game.arena`
back-edge". The short version: both imports are function-local, so defining the
enclosing functions never evaluates them, and every audit-scanner route calls
`_require_audit_scanner_enabled()` which 404s before reaching either import.

## Check 4: the tests

```sh
python -m pytest -q tests/thin        # expect 128 passed
python -m pytest -q tests/boundary    # expect 9 passed
```

The publisher suite is the one that needs interpretation:

```sh
python -m pytest -q scaffold/publisher/tests \
  --deselect scaffold/publisher/tests/test_validator_two_mode.py::test_required_ci_collection_gate_returns_zero
```

This suite **fails** in any environment without PostgreSQL and outbound network,
and those failures are inherited from upstream rather than caused by the
extraction. Do not read a red result here as an extraction defect. The way to
tell the difference is to run the same suite in the upstream checkout with the
same interpreter and diff the failure sets:

```sh
# in /tmp/cathedral-upstream, same Python, same extras
python -m pytest -q scaffold/publisher/tests tests/thin
```

At the time of writing, on macOS with Python 3.11.14: upstream 44 failed / 1230
passed, here 45 failed / 1238 passed, and the single extra failure is the
deselected test above. Anything beyond that difference is worth investigating.

The one deselection is `test_required_ci_collection_gate_returns_zero`, which
reads upstream's `.github/workflows/two-mode-provenance.yml` and asserts on its
text. This repo does not carry upstream's CI, so the guard has nothing to guard.

## Check 5: the boundary rationale

`BOUNDARY.md` lists every included and excluded top-level path with a reason. Two
judgement calls are worth a reviewer's attention, because reasonable people could
decide them the other way:

**`publisher_verify.py` is excluded** even though it is validator-owned by the
ownership test, because its audit-scanner bridge imports `game.arena` at module
scope (`:632`, inside a `try` that prints and continues). It would run here but
would report a soft failure on every invocation, in a script whose job is to
report pass or fail.

**`live_smoke.py` and `postgres_verify.py` are excluded.** The first drives the
miner write path over HTTP against a deployed publisher; the second needs a real
PostgreSQL via `DATABASE_URL`. Neither decides what goes on chain nor verifies
what does, and both belong to the same upstream `launch-readiness.yml` harness
group as the already-excluded `publisher_verify.py`, `tee_gpu_verify.py`, and
`attest_verify.py`. `weights_verify.py` and `wire_compat.py` were kept by the
same test: weights are literally what goes on chain, and `wire_compat.py` proves
the wire format live validators verify, offline against shipped fixtures.

The Python selection was not hand-curated. It is the import closure of the
validator entry points plus the publisher, computed from the AST of every import
in the tree. `tools/upstream-manifest.txt` is the resulting file list and doubles
as the re-sync input.

## Check 6: nothing operational leaked in

```sh
grep -rn "BEGIN.*PRIVATE KEY" . --exclude-dir=.git --exclude-dir=.venv
git ls-files | grep -iE '\.env$|\.pem$|id_rsa|\.key$'
```

Expected: no output from either.

`config/` carries **public** key bundles and digests, which is what an
independent validator needs in order to verify Cathedral's signatures. There is
no signing key material here.

## What this repo must not be used for

No deploy, no cutover, no chain writes. The running SN39 validator is built from
`cathedralai/cathedral`, and the reproduction locks and release manifests pin
upstream paths. If someone proposes deploying from here, that is a separate
decision that has not been made.

## Known issue a reviewer should not mistake for an extraction bug

`cathedral-scaffold` and the `cathedral` package pulled by the `provenance`
extra **both** declare a `cathedral-validator` console script. Whichever installs
last wins. With `uv pip install -e '.[provenance]'`, the exact command in
`VALIDATOR.md:111`, the work repo's neuron validator wins and
`cathedral-validator` fails with a confusing argparse error. With `pip`, the
correct one wins. This is inherited from upstream, not introduced here.
`BOUNDARY.md` has the full table. Check with:

```sh
grep 'import main' "$(dirname "$(command -v cathedral-validator)")/cathedral-validator"
# expect: from scaffold.cli import main
```
