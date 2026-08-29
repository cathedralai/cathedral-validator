# Cathedral Validator

Cathedral Validator is the canonical operator repository for Cathedral SN39.

It has one supported recurring runtime: the shadow relay. It verifies and
submits Cathedral's signed vector while a full-provenance audit checks the
published evidence concurrently.

**Shadow verifies authenticity, not arithmetic.** It proves Cathedral's key
signed exactly these numbers. It does not prove the numbers are right, because
the provenance audit runs concurrently and its verdict lands after the
submission. That is a deliberate trade for a relay that must keep writing, and
it is the honest description of what a shadow validator is: an authenticated
relay.

There is no recurring authority/full operator mode. The old profiles and
`--mode`/`--provenance` switches were removed. Authority-labelled internals
remain only to recover bounded launch journals, including the finalized UID30
launch, without submitting a replacement transaction.

Do not run a validator from another Cathedral repository. This repository owns
the validator command, release bundle, systemd units, runtime policy, dry-run
path, and broadcast gates.

## Launch truth, 2026-08-28

The bounded UID30 launch tool finalized the exact wire vector
`[[124, 65535]]`: all weight to miner UID124 and zero burn. This proves one
finalized UID30 launch transaction. It does not activate the recurring relay,
and SN39 subnet emission was `0`, so it does not prove TAO earnings.

Do not start the shipped recurring relay blindly. Its configured signed-vector
policy is not the consumed UID30 100/0 launch vector. Before any future
`--broadcast`, produce a no-write preview and require the exact intended UID row
and burn allocation. A different preview is a stop condition, not permission to
overwrite the finalized launch vector.

A dedicated second miner is a separate future chain change, not an extension of
the existing UID124 machine. The read-only
[second-miner plan](docs/SN39_SECOND_MINER_PLAN.md) pins the intended hotkey,
checks one finalized snapshot, and derives the exact equal-score row without
loading a wallet or exposing a write path. The separate
`cathedral-second-miner-announce` command is a bounded first-time axon writer.
It has its own hotkey, fixed endpoint, runtime root, preview schema, lock, and
one-attempt journal. It refuses until registration has assigned the second
hotkey a finalized UID. Neither command registers a miner or replaces UID30's
complete row. The full sequence and stop conditions are in the plan.

The separate `cathedral-uid124-axon-generation2` command bounds one replacement
of UID124's consumed generation-1 axon. It pins the exact predecessor preview
and journal digests, reuses their canonical lock and journal, fixes the target
to `35.222.166.235:8081`, requires a new reviewed preview and fresh endpoint
proof, and permits one no-retry generation-2 attempt. It has no UID8, weight,
registration, rent, or daemon path. Shipping the command is not proof that the
replacement announcement ran. See the same plan for its exact pins and live
gates.

## Quickstart

**This section is the canonical operator path.** Follow it top to bottom and
nothing else, [VALIDATOR.md](VALIDATOR.md) and
[VALIDATOR-ONBOARDING.md](VALIDATOR-ONBOARDING.md) both start by pointing back
here, and pick up where this leaves off.

Everything below runs as an ordinary user. No root, no systemd, no chain
write. Use Python 3.11 or 3.12 on Linux x86-64.

> **Shortcuts (optional).** This native path is canonical and auditable. For a one-shot
> native onboarding, `deploy/sn39/wallet-host-quickstart.sh` runs exactly these steps plus
> a validator-candidate check. For a cross-platform Docker option (macOS/Windows/Linux, 3
> commands), see [`deploy/sn39/docker/`](deploy/sn39/docker/README.md). Neither replaces the
> production staged-systemd model in `deploy/sn39/`.

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[provenance]'
cp config/validator-thin-sn39-relay.toml my-validator.toml
```

`config/validator-thin-sn39-relay.toml` is the **third-party relay profile**:
it follows Cathedral's remote signed feed, carries the trust pins verbatim,
and is the profile a validator that is not Cathedral should run. Copy it to
the repository root as shown, the copy's relative provenance key pins resolve
against the directory it sits in.

Edit `my-validator.toml` and set your wallet under `[network]`:
`wallet_name` and `validator_hotkey` are your local bittensor wallet labels.
Change nothing else in the file; the rest is the pinned trust profile and the
validator re-checks it before any broadcast.

### 1. Verify offline

No chain connection, no wallet, no directory to create beforehand:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --state-file "$HOME/.cathedral/thin-state.json" \
  --jsonl "$HOME/.cathedral/validator-events.jsonl" \
  --offline --once
```

The three path flags are the whole reason a preview needs them: the shipped
profile pins the **service-owned** runtime root, state file, and journal under
`/var/lib/cathedral-validator` and `/var/log/cathedral-validator`, which the
release install provisions as root and an ordinary user cannot write. The
flags redirect all three into one owner-only directory the validator creates
for you at mode 0700. A production install keeps the shipped paths and does
not pass these flags.

`$HOME/.cathedral` is a name other Cathedral tooling also uses. If it already
exists the validator reuses it and **tightens it to 0700**, and refuses to
start at all if it is not yours or is group- or world-writable. Give
`--runtime-root` a directory of its own if that tree is shared.

You should see the signed vector fetched, its signature, freshness and
rollback fence pass, a synthetic UID map, and `dry run, nothing written`.

**Expect exit status 1, and read the journal rather than the status.** A
`--once` run reports success only if the concurrent shadow audit *also*
reached the configured minimum assurance in that same run. A relay has no
controlled raw-evidence package, so its audit is `receipts_only` and cannot,
and the run ends with `PROVENANCE_AUDIT_NOT_PROVEN` and
`PROVENANCE_HEALTH_GATE_FAILED` in `$HOME/.cathedral/validator-events.jsonl`.
That is the expected relay outcome, not a misconfiguration, what it tells you
is that the audit ran. A `FileNotFoundError` naming a key bundle, or no
`PROVENANCE_*` record at all, would mean it did not. The exit status is
computed only on the `--once` path; the continuous service does not gate on
it.

### 2. One metagraph-backed dry cycle

Same command with `--dry-run` instead of `--offline`. This one reads live
chain state and writes nothing:

```bash
cathedral-validator serve \
  --config my-validator.toml \
  --runtime-root "$HOME/.cathedral" \
  --state-file "$HOME/.cathedral/thin-state.json" \
  --jsonl "$HOME/.cathedral/validator-events.jsonl" \
  --dry-run --once
```

This is the first step that needs a wallet. `wallet_name` and
`validator_hotkey` are labels for a bittensor wallet **on this host**, and the
shipped profile names `validator` and `default`, so the file the validator
opens is `~/.bittensor/wallets/validator/hotkeys/default`. On a box with no
wallet there, the tick fails before it fetches anything:

```
   ✗ tick failed: KeyFileError: Generic error: Failed to get hotkey: FileNotFound("Keyfile at:
     <path> does not exist.") · in 6s
```

`<path>` is literal: the operator stream and the journal strip absolute paths
and usernames, so the message will not tell you where it looked. The path
above is where. Create or import that hotkey with the Bittensor CLI (`btcli
wallet new_hotkey` or `btcli wallet regen_hotkey`, from the separate
`bittensor-cli` package, this repository does not install it), passing
`--wallet.name validator --wallet.hotkey default` to match the labels, or edit
the two labels to name a wallet you already have. Never put a coldkey or
mnemonic on a validator host.

With the wallet present but that hotkey not registered on SN39, the tick fails
closed with:

```
   ✗ tick failed: VectorError: validator hotkey is not registered on this subnet · in 5s
```

Both failures come from the same preflight, which runs **before** the signed
feed is fetched, so neither one says anything about the feed, the trust pins,
or the miner UID mapping. What the second proves is narrower and still worth
having: this host reached Finney, read the SN39 metagraph, and loaded your
hotkey. Step 1 is what exercises the feed and the pins; a step-2 journal that
fails here holds a `STARTUP` and a `TICK_FAILED` and nothing else. Register the
hotkey and run it again.

### 3. Stop here

`--broadcast` is a mainnet write and is **not** the next step. Run `--offline
--once` and `--dry-run --once` first and read what they print. The full
checklist that must be true before anyone adds `--broadcast` is in
[VALIDATOR.md](VALIDATOR.md#chain-writing-launch-gate).

> [!WARNING]
> Do not set `CATHEDRAL_*` environment variables to configure paths.
> Environment beats the config file, so a leftover
> `export CATHEDRAL_VALIDATOR_STATE=...` in a shell profile silently replaces
> the pinned state file and every later broadcast fails with `differs from the
> immutable trust profile: state_file`, naming no cause. Use the flags above
> for a preview and the shipped config for a service.

A fresh host that has never signed or submitted an SN39 attempt starts with an
absent journal. The systemd `StateDirectory` creates its fixed owner-only
runtime root. No journal initialization or migration helper ships. On an
existing host, keep the canonical journal in place and run the documented
status and recovery checks. Never hand-edit, move, archive, replace, or reset
live submission state.

### Is it working right now?

One command answers that. It reads the event journal and only the journal, no
chain call, no wallet, no publisher fetch, no lock, so it is safe to run
beside a live validator as often as you like, and it still answers when the
thing that broke is the network. **A preview wrote its journal under `$HOME`,
so name it**; a service uses the path in its own config and needs no flag:

```bash
cathedral-validator status --config my-validator.toml \
  --jsonl "$HOME/.cathedral/validator-events.jsonl"
```

What it prints depends on which step you ran last. After step 1 alone, a
completed dry run and nothing since, it looks like this:

```
   SN39 validator status  finney · netuid 39
   ─────────────────────────────────────────────────────────────────────────────────────
   journal    fresh · newest record 0s ago
   tick       WEIGHTS_DRY_RUN 2s ago
   write      WEIGHTS_DRY_RUN 2s ago · 2 uids
   vector     VECTOR_ACCEPTED 2s ago · id 6b798de3-e04 · policy_version 1785969111518
   audit      PROVENANCE_AUDIT_NOT_PROVEN 0s ago
   next tick  ~25m from now

   path       /home/you/.cathedral/validator-events.jsonl

   healthy    ticks are completing and the shadow audit is not alarming
```

Those are the right rows for this quickstart, not a degraded version of some
better ones: nothing was submitted, so the write is a dry run, and a relay's
audit is receipts-only, so `PROVENANCE_AUDIT_NOT_PROVEN` is its permanent
steady state and `PROVENANCE_AUDIT_PASS` never appears (step 1 explains why).
On a broadcasting validator the tick and write rows read `WEIGHTS_SUBMITTED`
instead; the audit row does not change. `policy_version` is the publisher's
epoch-milliseconds counter, so it is a long number and it only ever goes up.

Exit `0` means healthy, `1` names what is wrong, `2` means no journal was
configured for it to read. Point it at the wrong file and it says so rather
than reporting green: without the `--jsonl` above, the shipped config sends it
to `/var/log/cathedral-validator/validator-events.jsonl`, which a preview never
writes, and it exits 1 with `journal cannot be read (No such file or
directory), nothing is being monitored`.

The unattended half of the same five rules is
`deploy/sn39/cathedral-mismatch-check`, a 10-minute systemd timer whose unit
failing is the alert, see
[VALIDATOR.md](VALIDATOR.md#liveness-and-shadow-audit-alert-systemd). Install
it before you broadcast: a validator that quietly stops writing weights costs
you the emission it did not earn, and the journal is the only place that shows
up first.

### And when it stops?

A tick that writes nothing has its own event code for each reason, and every
`FAIL` or `NOT_PROVEN` one carries a `remediation` field saying what a person
has to do, including when the honest answer is "nothing was signed, and the
next tick rebuilds". [What each one means and which ones page a
human](VALIDATOR.md#when-a-tick-does-not-write-alert-on-these); [recovering
from the ones that do](VALIDATOR.md#recovering-from-a-refused-or-fenced-write);
[upgrading and rolling back](VALIDATOR.md#upgrade-and-rollback).

### The two `[launch]` settings a relay depends on

SN39's launch was a one-shot, subnet-level event. A relay cannot perform one,
so an unconditional per-validator launch gate would lock every operator except
Cathedral off the subnet. Two settings in the relay profile handle that, and
they are not interchangeable:

| Setting | Who it is for | What happens without it |
|---|---|---|
| `require_completed_launch_for_broadcast = false` | Every third-party relay. | Defaults to `true`, so broadcast is refused pending a completed launch this validator can never have. |
| `beta_skip_launch_ceremony = true` | A host holding controlled launch material at the release-pinned paths. | The line above is ignored for such a runtime and the ceremony is still required. |

For a pure relay the second setting changes nothing, the obligation it waives
is one the relay does not have. The shipped profile sets it anyway so the
profile stays runnable on a host that once held launch material.

The waiver is narrow. It clears the one-shot ceremony and the recurring-write
authorization derived from it, process controls that make a single mainnet
launch auditable. Every gate that keeps a submission *correct* still runs on
every tick and is not reachable from either setting: feed signature and key
pin, freshness and expiry, the monotonic rollback fence, the
`validated_supply` contract check, burn destination and floor, UID-replacement
safety, and the single-writer guard.

## Supported systemd install (relay)

> [!IMPORTANT]
> **Do this only after the quickstart above.** Steps 1 and 2 prove the feed,
> the pins and your wallet from an ordinary shell, where nothing can be
> written to chain. This section installs the pinned release as root and the
> unit it enables runs with `--broadcast`, so **step 3 still governs**: do not
> `systemctl enable --now` until Cathedral publishes the supported tag, the
> immutable pin bundle and the launch notice. Installing and verifying without
> enabling is safe and is the useful half of this section.

Everything a relay needs to build and verify this install is in the
repository. It was not before: the manifest builder pinned the
controlled-disclosure Intel TDX verifier binary, and the shipped unit
conditioned on root-signed authorization files. A relay needs neither, because
a relay does not originate weights, it relays a vector Cathedral signed, and
its shadow audit is receipts-only by design.

The install is one immutable release: a pristine `git` checkout, a hash-locked
venv, root-owned configs and units, and a root-owned manifest binding every one
of those bytes. `cathedral-sn39-release` re-checks the whole manifest before
it `execve`s the validator, so a service account that is compromised cannot
change what runs.

### Build the release and install its reviewed files

`$release_sha` is any commit of `main` you have reviewed, there are no tags;
`git rev-parse origin/main` is the normal answer. Use `/usr/bin/python3.12`, the
versioned regular file, not the `python3` symlink, because the manifest binds
its digest.

```bash
set -euo pipefail
release_sha="$(git rev-parse origin/main)"
release="/opt/cathedral-sn39/releases/$release_sha"
venv="/opt/cathedral-sn39/venvs/$release_sha"

install -d -o root -g root -m 0755 /opt/cathedral-sn39/releases
git clone https://github.com/cathedralai/cathedral-validator.git "$release"
git -C "$release" checkout --detach "$release_sha"

/usr/bin/python3.12 -m venv "$venv"
"$venv/bin/python" -m pip install \
  --require-hashes -r "$release/requirements/sn39-build.lock"
"$venv/bin/python" -m pip install --no-build-isolation \
  --require-hashes -r "$release/requirements/sn39-reproduction.lock"

install -D -o root -g root -m 0755 \
  "$release/deploy/sn39/cathedral-sn39-release-launcher.py" \
  /usr/local/libexec/cathedral-sn39-release
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-validator-sn39-relay.service" \
  /etc/systemd/system/cathedral-validator-sn39-relay.service
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-sn39-validator.sysusers" \
  /etc/sysusers.d/cathedral-sn39-validator.conf
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-sn39-validator-relay.tmpfiles" \
  /etc/tmpfiles.d/cathedral-sn39-validator-relay.conf
install -d -o root -g root -m 0755 /etc/cathedral-validator/provenance
install -D -o root -g root -m 0644 \
  "$release/config/validator-thin-sn39-relay.toml" \
  /etc/cathedral-validator/validator-thin-sn39-relay.toml
for key in registry report index; do
  install -D -o root -g root -m 0644 \
    "$release/config/provenance/$key-keys.json" \
    "/etc/cathedral-validator/provenance/$key-keys.json"
done

install -D -o root -g root -m 0755 \
  "$release/deploy/sn39/cathedral-mismatch-check" \
  /usr/local/bin/cathedral-mismatch-check
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-mismatch-alert.service" \
  /etc/systemd/system/cathedral-mismatch-alert.service
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-mismatch-alert.timer" \
  /etc/systemd/system/cathedral-mismatch-alert.timer
install -D -o root -g root -m 0644 \
  "$release/deploy/sn39/cathedral-validator.logrotate" \
  /etc/logrotate.d/cathedral-validator

systemd-sysusers /etc/sysusers.d/cathedral-sn39-validator.conf
systemd-tmpfiles --create /etc/tmpfiles.d/cathedral-sn39-validator-relay.conf
systemctl mask --now cathedral-thin-validator.service
systemctl daemon-reload
systemctl enable --now cathedral-mismatch-alert.timer
```

The alert timer is not part of the launch gate and is safe to enable now: it
reads the event journal every 10 minutes and writes nothing to chain. It fails
the `cathedral-mismatch-alert.service` unit, the failed unit **is** the alert,
there is no notification channel, on a `PROVENANCE_VECTOR_MISMATCH` in the
last 30 minutes or a shadow audit that has failed for 90 minutes with no pass.
It does **not** tell you the validator is running, submitting, or reachable: an
absent or stale journal reads as healthy, so watch the unit's state and the
validator unit separately.
[VALIDATOR.md](VALIDATOR.md#shadow-audit-mismatch-alert-systemd) has the rules
in full, including why `PROVENANCE_VECTOR_STALE_EPOCH` deliberately does not
alert.

`/etc/logrotate.d/cathedral-validator` bounds the two append-only streams in
`/var/log/cathedral-validator` at 14 daily generations, or sooner at 64 MB. It
needs no unit of its own, the host's existing logrotate timer picks it up, and `logrotate --debug /etc/logrotate.d/cathedral-validator` shows what it
would do without waiting. It rotates with `copytruncate` because the validator
holds its journal descriptor open, and keeps the newest rotated generation
uncompressed because both the alert and `cathedral-validator status` read it to
stay sighted across the minutes after a rotation when the live journal is
empty. It touches nothing in `/var/lib/cathedral-validator`: the submission
fences and the signed-attempt journal live there and are never rotated.

The two files that differ from Cathedral's own install are the ones a third
party could not otherwise use:

| File | Why the relay gets its own |
|---|---|
| `deploy/sn39/cathedral-validator-sn39-relay.service` | The origin unit has `ConditionPathExists=` on the root-signed recurring-write authorization and `SupplementaryGroups=cathedral-validator-evidence`. Neither is obtainable, and an unmet `Condition=` makes `systemctl start` **report success while starting nothing**. |
| `deploy/sn39/cathedral-sn39-validator-relay.tmpfiles` | The origin contract provisions the evidence producer's published tree, including a directory owned by `polaris`. `systemd-tmpfiles` refuses a line whose user does not resolve, so on a relay host it errors every boot for directories that host never uses. |

Install the shipped `.sysusers` unchanged: it declares only the validator
identities (`cathedral-validator` and `cathedral-validator-log`) and
deliberately restates no producer identity.

**The installed config must be byte-identical to the reviewed one**, the
manifest builder compares them and refuses otherwise. So do not edit
`/etc/cathedral-validator/validator-thin-sn39-relay.toml`. The shipped profile
names `wallet_name = "validator"` and `validator_hotkey = "default"`, and those
are local labels: provision your already-registered SN39 hotkey under the
service account's home as
`/var/lib/cathedral-validator/.bittensor/wallets/validator/hotkeys/default`,
owned by `cathedral-validator`, directories 0700 and files 0600. Never copy a
coldkey, mnemonic or password to this host.

### Build the relay manifest

```bash
manifest_tmp="$(mktemp /etc/cathedral-validator/sn39-release-manifest.json.XXXXXX)"
/usr/bin/python3.12 -I -E -s \
  "$release/scripts/build_sn39_release_manifest.py" \
  --relay --release "$release" --release-sha "$release_sha" >"$manifest_tmp"
chown root:root "$manifest_tmp"
chmod 0644 "$manifest_tmp"
mv "$manifest_tmp" /etc/cathedral-validator/sn39-release-manifest.json
```

`--relay` is what makes this runnable off a Cathedral host. It omits the one
`external_files` entry a relay cannot produce, the controlled-disclosure TDX
verifier binary, along with the producer-side status publisher unit and timer,
which write the producer's evidence tree as the producer's account. It binds a
*superset* of the reviewed source: everything the Cathedral manifest binds plus
the relay unit, its tmpfiles, and the three shadow-audit alert files installed
above. The environment commitment, the pristine checkout proof and the
bootstrap-interpreter binding are unchanged.

Binding the alert is the point of installing it first: the mismatch check is a
relay's only health surface, so the launcher re-verifies its bytes on every
start exactly as it does the unit's. Delete or edit
`/usr/local/bin/cathedral-mismatch-check` and the validator refuses to start
with `SN39 immutable-install check failed:` rather than running unwatched.

`--relay` is refused outright on a host holding SN39 launch material at the
release-pinned paths, so it cannot be used to give the one host that owes SN39
a launch a manifest with no verifier pin. `--verifier`, `--status-unit` and
`--status-timer` are refused with it rather than ignored: silently dropping a
path you named would produce a manifest that does not bind the file you believe
it binds.

### Verify before enabling

The dedicated `verify` mode checks the complete immutable install and exits. It
does not load a wallet, fetch a vector, start the recurring process, or submit a
chain transaction. It exits non-zero, writing
`SN39 immutable-install check failed:` and a cause, if anything above is wrong:

```bash
sudo /usr/local/libexec/cathedral-sn39-release verify
```

The success line names the installed release and manifest digest. Do not use
`systemctl start cathedral-validator-sn39-relay.service` as a verification
command. That unit invokes `continuous --broadcast` after verification and is a
live chain writer. Start or enable it only after the no-write preview, exact
weight target, launch authorization, and chain-writing approval are all
current.

That proof is only readable because the validator's operator stream is
line-buffered: every line reaches the journal as it happens, so a quiet
`journalctl` means nothing has happened yet, not that output is waiting in a
buffer. Do not restart a validator merely because `journalctl -f` has been
quiet, or because the newest line is a tick divider with no outcome under it, ticks are ~25 minutes apart, so both are normal mid-cycle. The authoritative
record of what a tick did is the JSONL journal
(`/var/log/cathedral-validator/validator-events.jsonl`); check it for a
`WEIGHTS_SUBMITTED` before concluding anything is stuck. A needless restart
costs a write cycle and can leave a submitted-but-unconfirmed receipt to
recover.

One host must never run both postures against one hotkey. The relay unit
declares `Conflicts=` on `cathedral-validator-sn39.service`, which systemd
applies in both directions, and re-checks with an `ExecStartPre=` guard because
`Conflicts=` cannot stop a writer somebody launched by hand.

## What it does

On every cycle the validator:

1. fetches the signed weight vector from the publisher feed;
2. enforces the weight-policy signature, freshness, the monotonic
   policy-version fence, and the pinned policy contract;
3. resolves eligible hotkeys against the current SN39 metagraph and refuses
   any UID whose mapping cannot be proven stable;
4. enforces the pinned burn destination and floor;
5. prints and records the exact UID vector it will submit;
6. submits before chain finality advances, the concurrent full-provenance
   audit (TDX attestation and signed score reports re-checked against the
   published evidence chain) runs in the background and never blocks the
   write; its verdicts land in the event journal as `PROVENANCE_AUDIT_*`;
7. stops at dry-run unless the operator explicitly enables broadcast.

If the signed feed is unreachable there is nothing to verify, so there is
nothing to submit: the validator idles and retries rather than inventing a
vector. Alert on `PROVENANCE_VECTOR_MISMATCH` in the event stream, it means
the audit disagreed with a vector that was already accepted for submission;
the write is not blocked, so the alert is the response path. The alert ships
in this repository as `deploy/sn39/cathedral-mismatch-check` and its timer, and
the relay install above enables it.

Do not alert on `PROVENANCE_VECTOR_STALE_EPOCH`. The publisher signs and
caches a vector for up to a minute while the evidence index flips to the next
epoch, so a consumer can hold last epoch's vector beside this epoch's
evidence. When that happens the audit re-verifies the vector IN FULL against
the epoch it names, that epoch's signed manifest, its report body digest,
and its recomputed shares, and reports this event instead. A vector that
cannot be re-verified that way is never reclassified: it stays
`PROVENANCE_VECTOR_MISMATCH`.

The validator always fetches the public HTTPS feed. Publisher services may run
on the same host, but a loopback publisher URL is not a supported validator
profile and is refused by the immutable SN39 trust contract.

## How it verifies

The write path enforces, on every cycle: the ed25519 weight-policy signature
over the canonical vector bytes; vector freshness and network/netuid identity;
the monotonic policy-version fence (no rollback); UID-replacement safety for
every rewarded hotkey; and the pinned burn destination. A vector failing any
check is refused, the validator fails closed and writes nothing.

In shadow mode the full-provenance verifier runs concurrently and re-checks the
published evidence chain (TDX attestation, signed score reports, signed evidence
index) against what was submitted. It labels each epoch `PASS`, `FAIL`, or
`NOT_PROVEN` in the event journal.

Read that carefully, because it is the limit of what shadow proves: the verifier
does not delay the write, so its verdict describes a submission that has already
happened. A `FAIL` is a record, not a refusal. No operator flag changes the
recurring writer into an independent recomputation path.

Compute workers need Intel TDX when their policy requires TDX evidence; the
validator host itself does not.

## Operator documents

The quickstart above is the one path to a running preview. These pick up from
it; none of them restates it.

- [Validator runbook](VALIDATOR.md), what each gate proves, how to read the
  event journal, **what to do when a write is refused or fenced**, the
  shadow-audit mismatch alert the install above enables, the checklist that
  must be true before `--broadcast`, and upgrade, rollback and key rotation.
- [Review gates](VALIDATOR-ONBOARDING.md), the extras a reviewer installs on
  top of the quickstart; [REVIEW.md](REVIEW.md) has the review order and the
  gates a broadcast must prove in one cycle.
- [Provenance contract](docs/PROVENANCE.md), every pin the shadow audit uses.
- [Versioned release sealing](docs/SN39_VERSIONED_RELEASES.md), the read-only
  ceremony preflight, immutable generation paths, and external reproduction.
- [CyberGym pre-launch E2E testing](docs/CYBERGYM_E2E_TESTING.md)
- [SN39 v3 publisher cutover](docs/SN39_V3_PUBLISHER_CUTOVER.md), what the live
  publisher actually imports, the ordered steps to make it v3-capable, and how
  flipping the contract first fails without failing a check.
- [Miner error contract](docs/MINER_ERROR_CONTRACT.md)

## Repository boundary

This repository contains validator-owned code and release assets. Compute
worker software lives in
[`cathedral-compute`](https://github.com/cathedralai/cathedral-compute).
Distill receipt and lane contracts live in
[`cathedral-distill`](https://github.com/cathedralai/cathedral-distill).
The optional dependencies are pinned to immutable reviewed commits.

[BOUNDARY.md](BOUNDARY.md) records the ownership and security boundary. There
is no upstream validator sync. Changes to validator behavior start and finish
in this repository.

## Security

Keep wallet seeds, private keys, bearer tokens, cloud credentials, internal
addresses, and controlled evidence out of Git, issues, and public logs.

Treat `PASS`, `FAIL`, and `NOT_PROVEN` as different outcomes. A local test, a
past receipt, or a historical chain row does not prove current eligibility.
