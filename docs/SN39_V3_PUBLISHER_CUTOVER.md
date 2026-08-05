# SN39 v3 publisher cutover: the import root is not the pinned directory

The live SN39 publisher cannot compose a v3 vector. Not "is configured for v2" —
cannot. The code it imports has no `_compose_cybergym_lane_v3`, no
`ALLOCATION_CONTRACT_ENV`, and no v3 branch of any kind. Setting
`CATHEDRAL_ALLOCATION_CONTRACT=v3` on the running unit today would change
nothing and report nothing, because no line of the imported tree reads that
name.

This document records what the publisher actually runs, how its import root is
chosen (which is not what the unit file appears to say), the ordered steps to
make it v3-capable, and the exact way this fails if someone flips the
environment variable first.

Nothing here has been applied. No live configuration was changed to produce it;
every observation below came from a read-only command against
`polaris-tdx-7e93d5de`, and each one is reproduced inline so a reviewer can
re-run it rather than trust it.

> [!IMPORTANT]
> The ordering constraint is one-directional. The publisher must be composing
> v3 **before** any validator is re-pinned to `validated_supply_v3`. Doing it in
> the other order takes SN39 weights offline, and the only thing that fails is
> the validator, which reports a problem with the vector rather than with the
> publisher that produced it.

## 1. What the live publisher runs today

`cathedral-scorer-sn39.service` is what composes SN39's live signed vector. It
logs one composition per minute:

```
sudo journalctl -u cathedral-scorer-sn39.service --since '-10 min' | tail -3
# [weights] confidential_primary vector composed: miners=1
```

The unit is a base file plus one drop-in:

| Layer | Setting | Value |
|---|---|---|
| `/etc/systemd/system/cathedral-scorer-sn39.service` | `WorkingDirectory` | `/home/polaris/cathedral-scorer` |
| `/etc/systemd/system/cathedral-scorer-sn39.service.d/contract-v2.conf` | `WorkingDirectory` | `/opt/cathedral-sn39/releases/fd02392dc969bbea09e3107febb64f1f5f748391` |
| both | `ExecStart` interpreter | `/home/polaris/cathedral-scorer/.venv/bin/uvicorn` |
| both | ASGI target | `scaffold.publisher.server:app` |

Three different trees are named across two lines of configuration, and only one
of them is the answer.

### The import root is the working directory, via uvicorn

The venv that supplies the interpreter is `/home/polaris/cathedral-scorer/.venv`.
That venv contains an **editable install** of the package:

```
sudo ls /home/polaris/cathedral-scorer/.venv/lib/python3.12/site-packages | grep editable
# __editable__.cathedral_scaffold-4.0.0rc4.pth
# __editable___cathedral_scaffold_4_0_0rc4_finder.py

sudo grep -n MAPPING /home/polaris/cathedral-scorer/.venv/lib/python3.12/site-packages/__editable___cathedral_scaffold_4_0_0rc4_finder.py
# MAPPING: dict[str, str] = {'game': '/home/polaris/cathedral-scorer/game',
#                            'scaffold': '/home/polaris/cathedral-scorer/scaffold'}
```

That mapping is the obvious reading, and it is wrong. Setuptools **appends** its
finder to `sys.meta_path`:

```
sudo grep -n -A3 '^def install' .../__editable___cathedral_scaffold_4_0_0rc4_finder.py
# 74: def install():
# 75:     if not any(finder == _EditableFinder for finder in sys.meta_path):
# 76:         sys.meta_path.append(_EditableFinder)
```

`append`, not `insert`. The stock `PathFinder` sits ahead of it, so the editable
finder only answers for a module that `sys.path` cannot supply. And `sys.path`
can supply it, because the uvicorn CLI puts the working directory on the front:

```
sudo grep -n -A3 '"--app-dir"' /home/polaris/cathedral-scorer/.venv/lib/python3.12/site-packages/uvicorn/main.py
# 361:     "--app-dir",
# 362:     default="",

sudo grep -n 'sys.path.insert' /home/polaris/cathedral-scorer/.venv/lib/python3.12/site-packages/uvicorn/main.py
# 549:        sys.path.insert(0, app_dir)
```

`--app-dir` defaults to `""`, `run()` inserts it unconditionally, and `""` on
`sys.path` means the process working directory. `WorkingDirectory` therefore is
the import root — not because systemd puts it on the path, but because uvicorn
does.

This was confirmed both directions rather than reasoned about. With the working
directory suppressed (`python -P`), the editable finder answers; with the
working directory present, as uvicorn arranges, the release tree answers:

```
D=/opt/cathedral-sn39/releases/fd02392dc969bbea09e3107febb64f1f5f748391
V=/home/polaris/cathedral-scorer/.venv/bin/python3

sudo sh -c "cd $D && $V -P -c 'import importlib.util; print(importlib.util.find_spec(\"scaffold\").origin)'"
# /home/polaris/cathedral-scorer/scaffold/__init__.py          <- editable finder, NOT what runs

sudo sh -c "cd $D && $V -P -c 'import sys,importlib.util; sys.path.insert(0,\"\"); print(importlib.util.find_spec(\"scaffold.publisher.weights\").origin)'"
# /opt/cathedral-sn39/releases/fd02392.../scaffold/publisher/weights.py   <- what runs
```

And the running process is in fact sitting in that directory:

```
sudo readlink -f /proc/$(systemctl show -p MainPID --value cathedral-scorer-sn39.service)/cwd
# /opt/cathedral-sn39/releases/fd02392dc969bbea09e3107febb64f1f5f748391
```

So:

| Question | Answer |
|---|---|
| Which tree is imported | `/opt/cathedral-sn39/releases/fd02392dc969bbea09e3107febb64f1f5f748391` |
| How it gets on `sys.path` | `uvicorn --app-dir` default `""` → `sys.path.insert(0, "")` → cwd → `WorkingDirectory` |
| Which commit | `fd02392` — "Reconcile the producer revision and make the deploy contract migration-safe (#399)", Jul 27 |
| Which interpreter | `/home/polaris/cathedral-scorer/.venv/bin/python3` (3.12, uvicorn 0.51.0) |
| Which tree is **not** imported | `/home/polaris/cathedral-scorer` @ `990c7a49` (#388) — the editable install, shadowed |

`990c7a49` is a decoy. It is a real checkout, it is a real editable install, it
is what every naive check finds first, and it has not been imported by this
service since the drop-in landed on Jul 27.

### Neither tree can compose v3

Both candidates fail the same way, so the distinction above does not change
today's verdict — only the remedy.

```
sudo grep -rc CATHEDRAL_ALLOCATION_CONTRACT /opt/cathedral-sn39/releases/fd02392.../scaffold
# (no matches; total 0)
sudo find /opt/cathedral-sn39/releases/fd02392.../scaffold -iname '*cybergym*' | wc -l
# 0
sudo grep -n 'contract_version' /opt/cathedral-sn39/releases/fd02392.../scaffold/publisher/weights.py
# 333:        "contract_version": "v2",
```

The imported tree hardcodes `"contract_version": "v2"` as a literal. There is no
switch to throw. `/home/polaris/cathedral-scorer/scaffold` @ `990c7a49` is the
same: zero `cybergym` files, zero mentions of the environment variable.

### What it would need to run

The v3-capable code is already staged on the box and is already what
`releases/current` points at:

```
sudo readlink -f /opt/cathedral-sn39/releases/current
# /opt/cathedral-sn39/releases/4c7b1767ed61748a063db2e5874a44162364d6c8
```

`4c7b1767` is "fix(sn39): public reproduction honors the relay evidence posture
(#63)". Its `scaffold/publisher/weights.py` carries the whole contract, at line
numbers identical to this repository's `main`:

| Symbol | Line |
|---|---|
| `ALLOCATION_CONTRACT_ENV = "CATHEDRAL_ALLOCATION_CONTRACT"` | `weights.py:76` |
| `def allocation_contract()` — fails closed on an unknown value | `weights.py:328` |
| default `"v2"` when unset | `weights.py:334` |
| `def _compose_cybergym_lane_v3(store, *, now)` | `weights.py:2095` |
| `payload["policy_metadata"]["cybergym_lane"] = _compose_cybergym_lane_v3(...)` | `weights.py:2325` |

The gap between what runs and what is needed is therefore **one line of the
drop-in**. The bits are on the host; the `WorkingDirectory` pin is the only
thing holding the publisher on `fd02392`.

### The database is two migrations short

The publisher is Postgres-backed, not SQLite. `CATHEDRAL_DB_PATH` in
`/home/polaris/cathedral/.env.sh` names `/home/polaris/cathedral/data/publisher.db`,
a file that does not exist; `DATABASE_URL` on line 38 of the same file names the
`cathedral` database on `127.0.0.1:5432`, and that is where the eight idle
connections from this service actually go.

```
sudo -u postgres psql -d cathedral -Atc "select id from schema_migrations order by 1 desc limit 1"
# 0047_external_score_audience

sudo -u postgres psql -d cathedral -Atc \
  "select count(*) from information_schema.tables where table_schema='public' and table_name like '%cybergym%'"
# 0
```

Pending, both defined in `scaffold/publisher/store.py` (Postgres list at
`:1444` and `:1485`, SQLite list at `:756` and `:802`):

- **`0048_cybergym_scores`** — creates `cybergym_score_reports` (the signed
  per-epoch producer report: audience, `source_epoch`, `producer_hotkey`,
  `complete`, `report_sha256`, `body_sha256`, `evidence_sha256`, `signature`,
  `report_json`, with a unique index on `(network, netuid, source_epoch)`) and
  `cybergym_scores` (per-miner rows keyed `(report_id, miner_hotkey)`).
- **`0049_cybergym_authenticated_body`** — adds
  `cybergym_score_reports.authenticated_body TEXT NOT NULL DEFAULT ''`.

Both are additive and idempotent (`CREATE TABLE IF NOT EXISTS`,
`ADD COLUMN IF NOT EXISTS`). Neither touches an existing v2 table.

They do not need a separate migration command. `Store.__init__` calls
`self.migrate()` unconditionally (`store.py:1665`) and `build_app()` constructs
the store at import, so **the restart in step 2 applies them**. That is
convenient and it is also why step 2 must be verified rather than assumed: if
the restart fails for an unrelated reason, the migrations silently did not run
either.

## 2. Deploying a v3-capable publisher

Five steps. Each has a verification that must pass before the next one starts.
Steps 1–3 are safe to perform while the subnet is live: they change which code
composes the vector, not which contract it composes. The vector stays v2 and
byte-identical in shape through step 3.

### Step 0 — record the rollback point

```
sudo cp /etc/systemd/system/cathedral-scorer-sn39.service.d/contract-v2.conf \
        /etc/systemd/system/cathedral-scorer-sn39.service.d/contract-v2.conf.pre-v3-$(date -u +%Y%m%dT%H%M%SZ)
```

**Verify.** The copy exists and `sudo diff` against the original is empty. Note
the current import root (`fd02392`) in the change record; it is the value step 5
restores.

> [!NOTE]
> Save the copy **outside** the drop-in directory or with a suffix systemd
> ignores. systemd reads every `*.conf` in a `.d` directory; a backup named
> `*.conf` would be merged as live configuration.

### Step 1 — confirm the target release is intact and its dependencies resolve

```
sudo git -C /opt/cathedral-sn39/releases/4c7b1767ed61748a063db2e5874a44162364d6c8 \
  log -1 --format='%H %s'
sudo grep -c _compose_cybergym_lane_v3 \
  /opt/cathedral-sn39/releases/4c7b1767ed61748a063db2e5874a44162364d6c8/scaffold/publisher/weights.py
```

**Verify.** The commit is `4c7b1767ed61748a063db2e5874a44162364d6c8` and the
grep count is `2` (definition at `:2095`, call site at `:2325`).

> [!WARNING]
> Do **not** switch the interpreter to the matching per-release venv.
> `/opt/cathedral-sn39/venvs/4c7b1767.../bin/python -c 'import psycopg2'` raises
> `ModuleNotFoundError`; that venv cannot reach the publisher database. It also
> has no `scaffold` installed, so it resolves the package from the working
> directory exactly as the current venv does. The interpreter stays
> `/home/polaris/cathedral-scorer/.venv/bin/uvicorn`. This step changes the
> import root and nothing else.

### Step 2 — repoint the import root, still on v2

Edit `contract-v2.conf` so `WorkingDirectory` names the v3-capable release, and
add an explicit `PYTHONPATH` naming the same tree. The `PYTHONPATH` line is
redundant with the uvicorn behavior documented in §1 and that is the point: it
makes the import root a declared fact instead of an emergent one, and it matches
how `cathedral-validator-passive.service` already does it
(`Environment=PYTHONPATH=/opt/cathedral-validator-passive`).

```
[Service]
Environment=PYTHONPATH=/opt/cathedral-sn39/releases/4c7b1767ed61748a063db2e5874a44162364d6c8
WorkingDirectory=/opt/cathedral-sn39/releases/4c7b1767ed61748a063db2e5874a44162364d6c8
```

Leave `ExecStart` exactly as it is. Do **not** add
`CATHEDRAL_ALLOCATION_CONTRACT` in this step.

```
sudo systemctl daemon-reload
sudo systemctl restart cathedral-scorer-sn39.service
```

**Verify**, all four:

```
# a. the process is actually importing the new tree
sudo readlink -f /proc/$(systemctl show -p MainPID --value cathedral-scorer-sn39.service)/cwd
# .../releases/4c7b1767ed61748a063db2e5874a44162364d6c8

# b. the symbol is present in the tree that is sys.path[0]
sudo sh -c 'P=$(systemctl show -p MainPID --value cathedral-scorer-sn39.service); \
  grep -c _compose_cybergym_lane_v3 "$(readlink -f /proc/$P/cwd)/scaffold/publisher/weights.py"'
# 2      (it was 0 before this step)

# c. the migrations ran during startup
sudo -u postgres psql -d cathedral -Atc "select id from schema_migrations order by 1 desc limit 2"
# 0049_cybergym_authenticated_body
# 0048_cybergym_scores

# d. composition never stopped, and the contract is still v2
sudo journalctl -u cathedral-scorer-sn39.service --since '-3 min' | tail -3
sudo -u postgres psql -d cathedral -Atc \
  "select vector_json::json->'policy_metadata'->'validated_supply'->>'contract_version' \
   from signed_weight_vectors where id='latest:finney:39'"
# v2
```

If (c) shows `0047`, stop. The service did not construct a store, which means it
did not start cleanly regardless of what `systemctl status` says.

Let this run for at least two validator ticks (~50 minutes) with the vector
still v2 before continuing. A `v2` vector from `4c7b1767` and a `v2` vector from
`fd02392` are the same wire shape, so this interval is a genuine soak of the new
code against a live consumer with nothing economic riding on it.

### Step 3 — prove v3 is reachable, not merely present

This is the check that distinguishes a real deployment from the failure in §4.
(b) above proves the symbol is on disk in the right tree. It does not prove the
running process can execute it. The proof is the composed vector itself:
`policy_metadata.cybergym_lane` is written by exactly one line — `weights.py:2325`
— so its presence is evidence that `_compose_cybergym_lane_v3` ran inside the
serving process.

Add to the drop-in:

```
Environment=CATHEDRAL_ALLOCATION_CONTRACT=v3
```

then `daemon-reload` and `restart`.

**The one-line check:**

```
sudo -u postgres psql -d cathedral -Atc "select vector_json::json->'policy_metadata'->'validated_supply'->>'contract_version', (vector_json::json->'policy_metadata'->'cybergym_lane') is not null from signed_weight_vectors where id='latest:finney:39'"
```

- Today, and after any silently-inert flip: `v2|f`
- After a real v3 deployment: `v3|t`

Both fields matter. `v3|f` would mean the contract was declared but the lane was
not composed, which is a different and worse bug than either endpoint; treat it
as a stop.

Also confirm the publisher did not fail closed on a malformed value —
`allocation_contract()` at `weights.py:328` raises `VectorError` on anything
that is not `v2` or `v3`, and that error surfaces in the journal rather than in
the query above.

### Step 4 — re-pin the validator

Only now. Change `require_policy` from `validated_supply_v1` to
`validated_supply_v3` in `/etc/cathedral-validator/validator-mainnet-sn39.toml`
and restart `cathedral-validator-passive.service`.

**Verify.**

```
sudo journalctl -u cathedral-validator-passive.service --since '-5 min' | grep -E 'policy|startup'
# policy     validated_supply_v3 · legacy and v3 vectors rejected
# startup    policy=validated_supply_v3
```

> [!NOTE]
> Read the first field, not the suffix. `scaffold/cli.py:470` appends the
> literal `"legacy and v3 vectors rejected"` to whatever the pin is, so a
> validator correctly pinned to v3 prints a banner that appears to say it
> rejects v3. The suffix is a fixed string, not a rendering of `require_policy`.
> `startup policy=validated_supply_v3` is the unambiguous line.

Then watch one full tick and confirm a weight set completed with no
`VectorError`. `validated_supply_v3` is already a member of
`SN39_PINNED_REQUIRE_POLICIES` (`scaffold/validator_thin.py:2913-2916`), so the
trust profile admits it without a code change.

## 3. Rollback

Rollback is steps 4 → 3 → 2, in that order — the reverse of deployment, and the
order is not optional. Un-pinning the validator first is always safe; un-pinning
the publisher first strands a v3-pinned validator against a v2 vector, which is
the §4 outage arrived at from the other direction.

1. **Validator back to `validated_supply_v1`**, restart, confirm the startup
   banner reads `policy=validated_supply_v1` and a tick completes. An unpinned
   or v1-pinned validator accepts the v2 vector immediately.
2. **Remove `Environment=CATHEDRAL_ALLOCATION_CONTRACT=v3`** from the drop-in,
   `daemon-reload`, restart. Verify the one-line check returns `v2|f`.
3. **Restore the saved `contract-v2.conf`** if the new tree is itself suspect —
   `WorkingDirectory` back to `fd02392...`, `PYTHONPATH` line removed. Verify
   `/proc/<pid>/cwd` and that composition resumes.

Step 3 is the last resort, not the first move. Steps 1–2 restore the v2 economy
in full while leaving the newer, better-tested code composing it.

### What must not be rolled back

**Migrations 0048 and 0049.** Do not drop `cybergym_score_reports`,
`cybergym_scores`, or the `authenticated_body` column, under any circumstance
short of rebuilding the database.

- They are forward-only. `schema_migrations` records applied ids and there is no
  down-migration; a manual `DROP TABLE` desynchronizes the ledger from the
  schema, and the next startup would not re-create what the ledger claims is
  already applied.
- `fd02392` does not know these tables exist. Rolling the code back to it is
  fully compatible with leaving them in place — that is precisely why the
  migrations are safe to apply ahead of the contract flip.
- They hold ingested producer reports. Once the CyberGym producer has posted
  signed epoch reports, dropping the tables destroys the only record that those
  epochs were scored, and `authenticated_body` is what makes a stored report
  re-verifiable at all.

Also do not roll back the `PYTHONPATH` line independently of
`WorkingDirectory`. They must name the same tree. Two different trees on those
two settings reintroduces exactly the ambiguity this document exists to remove.

## 4. How this fails silently

This is the sequence if someone sets `CATHEDRAL_ALLOCATION_CONTRACT=v3` without
first repointing the import root.

**1. The flip is accepted.** Adding `Environment=CATHEDRAL_ALLOCATION_CONTRACT=v3`
to the drop-in and restarting produces a clean start. `systemctl status` is
`active (running)`.

**2. Nothing reads it.** The imported tree — `fd02392` — contains zero
occurrences of the string `CATHEDRAL_ALLOCATION_CONTRACT`. There is no
`allocation_contract()` to fail closed, because that function does not exist at
this commit. An unread environment variable is not an error condition in any
language; it is just an environment variable.

**3. The publisher keeps composing v2.** `weights.py:333` in the imported tree
emits `"contract_version": "v2"` as a literal, and `policy_metadata` never gains
a `cybergym_lane` key. The journal keeps printing
`[weights] confidential_primary vector composed: miners=1` once a minute,
unchanged. Every health endpoint stays green. The composed vector is
byte-identical to the day before.

**4. Every ordinary check confirms the flip worked.** This is the trap.
`systemctl show cathedral-scorer-sn39.service -p Environment` shows
`CATHEDRAL_ALLOCATION_CONTRACT=v3` — true. The drop-in on disk says `v3` — true.
`grep -rn _compose_cybergym_lane_v3 /opt/cathedral-sn39/releases/current/` finds
the function on the host — also true, and completely irrelevant, because
`current` is not what this unit imports. Three independent confirmations, none
of which touches the import root.

**5. The validator is re-pinned to `validated_supply_v3`**, on the strength of
step 4.

**6. Every vector is now rejected.** `scaffold/validator_thin.py:3302-3307`:

```python
if require_policy == REQUIRE_POLICY_VALIDATED_SUPPLY_V3:
    if validated_supply is None or supply_version != "v3":
        raise wire.VectorError(
            "validator pinned to validated_supply_v3 but vector carries no v3 "
            "validated_supply policy block"
        )
```

This raises on the first tick and on every tick after. The publisher is
producing a fresh, correctly signed, perfectly valid v2 vector every minute, and
the validator refuses all of them.

**7. The validator goes dark.** No mapping means no weight set. SN39 keeps
whatever weights were last written, vtrust decays against validators that are
still setting, and emissions follow. The subnet does not stop; it drifts, which
takes longer to notice than a crash.

**8. The one thing that fails, blames the wrong component.** The publisher — the
component that is actually misconfigured — emits no error, fails no check, and
degrades no health signal. The only failure is on the consumer, and its message
names the *vector*. An operator reading "vector carries no v3 validated_supply
policy block", holding a publisher config file that plainly says `v3` and a
publisher that is plainly `active (running)`, will conclude the feed is broken
and start debugging the transport. The misconfiguration is two hosts' worth of
indirection away from the message that reports it.

There is no check anywhere in this pipeline that compares "the contract the
publisher was told to use" against "the contract the publisher's imported code
is capable of." The environment variable and the import root are set in the same
file, one line apart, and nothing reconciles them.

### The check that would have caught it

Step 3's one-liner, run against the publisher **before** the validator is
re-pinned. It reads the composed artifact rather than the configuration that was
supposed to produce it, so it cannot be satisfied by an unread environment
variable or by code sitting in a directory nobody imports:

```
sudo -u postgres psql -d cathedral -Atc "select vector_json::json->'policy_metadata'->'validated_supply'->>'contract_version', (vector_json::json->'policy_metadata'->'cybergym_lane') is not null from signed_weight_vectors where id='latest:finney:39'"
```

If that does not return `v3|t`, the validator must not be re-pinned. No
configuration file, no `systemctl show`, and no `grep` over `/opt` is a
substitute for it.

## 5. Summary of verified facts

| Claim | Verified value | How |
|---|---|---|
| Composer of the live SN39 vector | `cathedral-scorer-sn39.service` | journal, one composition per minute |
| Imported tree | `/opt/cathedral-sn39/releases/fd02392...` | `readlink /proc/<pid>/cwd` + `find_spec` replay |
| Mechanism | uvicorn `--app-dir` default `""` → `sys.path.insert(0, "")` | `uvicorn/main.py:361-362, 549` |
| Editable install (shadowed) | `/home/polaris/cathedral-scorer/scaffold` @ `990c7a49` | `_EditableFinder` appended to `sys.meta_path` |
| v3 symbols in imported tree | none | 0 `cybergym` files, 0 env-var mentions, `"v2"` literal at `:333` |
| v3-capable release on host | `4c7b1767...` = `releases/current` | `weights.py:76, 328, 334, 2095, 2325` |
| Publisher DB | Postgres `cathedral` via `DATABASE_URL` | 8 live connections; the SQLite path does not exist |
| Current migration | `0047_external_score_audience` | `schema_migrations`, 48 rows |
| Pending | `0048_cybergym_scores`, `0049_cybergym_authenticated_body` | `store.py:1444, 1485` |
| Applied by | `Store.__init__` → `self.migrate()` on service start | `store.py:1665` |
| Validator pin today | `validated_supply_v1` | `validator-mainnet-sn39.toml:22`, startup banner |
| Rejection on premature re-pin | `VectorError`, every tick | `validator_thin.py:3302-3307` |
