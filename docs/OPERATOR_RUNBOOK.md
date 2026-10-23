# Validator operator runbook

One path, in order, from a fresh Linux host to a confirmed weight row on SN94.
It links to the canonical instructions instead of repeating them: the
repository [README](../README.md) is the install guide, and
[Validator auto-update](AUTO_UPDATE.md) owns the updater, the journal, and
recovery. Where this page and those two disagree, they win.

Cathedral is Bittensor subnet 94 (SN94). SN39 is legacy and this validator
does not support it. The testnet mirror is netuid 584.

## 1. Prepare the host

- Use Linux/amd64 with systemd, CPython 3.12 at `/usr/bin/python3.12`,
  `python3.12-venv`, and OpenSSL 3. Ubuntu 24.04 LTS is the tested system. The
  installer refuses anything else (`deploy/validator-update/install_updater_bundle.py`,
  its runtime guard).
- Use 2 vCPU, 4 GB RAM, and 20 GB disk. Releases stay on disk; leave room for
  them to accumulate.
- Allow outbound access only to:
  - the finney entrypoint;
  - `github.com` and `raw.githubusercontent.com`;
  - every serving miner's advertised address;
  - `kdsintf.amd.com` (HTTPS 443). The SNP verifier fetches the AMD ARK, ASK,
    and VCEK certificates there;
  - `api.trustedservices.intel.com`. Intel TDX is legacy, but the validator
    still verifies TDX quotes against this collateral service.
- Keep the clock synchronized. Signed release metadata is refused when it is
  not yet valid or has expired, so a drifting clock blocks installs and
  updates. `timedatectl status` should report a synchronized clock.
- Install the packages from
  [Before installation](AUTO_UPDATE.md#before-installation).
- Never place the coldkey file, mnemonic, or coldkey password on this host.

## 2. Prepare the hotkey on chain

From a separate wallet machine, not the validator host:

1. Register the validator hotkey on SN94, for example with Bittensor CLI
   11.1.0:

   ```bash
   btcli --network finney \
     --wallet YOUR_WALLET \
     --wallet-hotkey YOUR_HOTKEY \
     subnet register --netuid 94
   ```

2. Stake enough to hold a validator permit. The chain gives permits to the
   hotkeys with the most stake. Without a permit the validator runs, writes
   nothing, and reports `NO_PERMIT`.
3. Copy only the hotkey file to the validator host. It must be the
   unencrypted keyfile `btcli` writes for hotkeys, mode `0600`, inside a
   directory named `hotkeys`, with a signing secret in it. Setup refuses an
   encrypted, public-only, or coldkey file.

## 3. Check the chain rules

The writer checks the chain's rules at the finalized block before it signs,
and refuses to write, cycle after cycle, if any of these does not hold
(`cathedral_thin/independent_runtime/direct_writer.py`, pre-sign checks):

| Chain setting | Must be |
|---|---|
| Commit-reveal | **On** for SN94. Opt in to timelocked commits (step 7). Without the opt-in the writer refuses every cycle. If the chain turns commit-reveal off while you are opted in, the writer also refuses. |
| `weights_rate_limit` | At least 16 blocks, and the cooldown since your last write elapsed. |
| `WeightsVersionKey` | At most the version the release signs with (`cathedral_thin/independent/constants.py`). |
| Your stake | At least the subnet's weight stake threshold. |
| Weight count | The vector must meet the chain's minimum allowed weights. |

Read the subnet's hyperparameters with your Bittensor CLI before installing.
Mainnet is Finney netuid 94. The testnet mirror is netuid 584; its rehearsal
steps are in
[SN94 cutover](SN94_CUTOVER.md#exact-public-testnet-rehearsal).
Each refusal appears as `NOT_PROVEN` with its reason in the service log, and
the validator retries the next cycle. On SN94, success is `COMMITTED` then
`REVEALED_CONFIRMED`, not a plain `CONFIRMED` write.

The validator also writes nothing while no miner is serving, while no machine
verifies, or while any vendor verification in the round is unresolved. That is
deliberate: a round is written only when every step is proven.

## 4. Install the signed bootstrap

Follow [Install](../README.md#install) exactly: download `install.sh`, check
its digest, and run it with `sudo bash install.sh`. It verifies the bootstrap
signature, digests, and expiry before running anything, installs the updater,
units, and tools, and enables nothing. A `FAILED` digest line means nothing
ran; retry after a few minutes. An expired bootstrap means a new one is due
from the maintainer.

## 5. Write the SNP admission policy

Create the policy from the template in
[Before installation](AUTO_UPDATE.md#before-installation), with only
measurements and TCB floors you reviewed. Use `milan`, `genoa`, or `turin` to
match the machine's EPYC generation. The miner's SNP probe transcript
(in the sandbox repository) records the observed measurement and TCB to review.

The policy admits one-socket machines only. Leave out `require_single_socket`;
it defaults to `true`.

## 6. Run setup

Run `sudo cathedral-validator-setup` with `--hotkey-file`, `--expected-hotkey`
(the hotkey's SS58 address), `--snp-policy`, and `--confirm-direct-write`, as
shown in [Install](../README.md#install). Setup:

- validates the hotkey file and the policy;
- writes `/etc/cathedral-validator/` (mode `0700`): `validator-hotkey`,
  `snp-policy.json`, `identity.env`, `direct.env`, `update.env`, and
  `setup-complete.json`;
- on a first install, runs the signed first-install update, which activates
  the stable release and starts the writer;
- enables the writer and the stable update timer;
- prints `SETUP_COMPLETE: stable direct validator configured`, or
  `SETUP_REFUSED: <reason>` and exits 2.

Setup never overwrites a configuration file that differs from what it would
write. It refuses instead, so do not hand-edit files under
`/etc/cathedral-validator/` and expect a rerun to accept them.

## 7. Opt in to timelocked commits

SN94 has commit-reveal on. Until you opt in, the validator refuses to sign and
writes nothing.

Follow [Commit-reveal subnets](AUTO_UPDATE.md#commit-reveal-subnets). It sets
`CATHEDRAL_VALIDATOR_COMMIT_REVEAL=timelocked-v4-reveal-period-N` in a systemd
drop-in, where N is the subnet's `commit_reveal_period`. Do not put it in
`direct.env`. Reload systemd, then restart the service.

The validator then signs `commit_timelocked_mechanism_weights`. The chain
applies the vector about one epoch later. There is no reveal transaction.

## 8. Watch the first cycles

```bash
sudo journalctl -u cathedral-validator-direct.service -f
```

The service reports ready after startup recovery, then runs one cycle
immediately and one every 1500 seconds. Each cycle prints one JSON line with
`status`, the finalized `anchor`, `raw_scores`, the wire weights, the
`evidence_digest`, and the write `receipt`. The first success prints
`COMMITTED`. `COMMITTED_AWAITING_REVEAL` follows until the chain applies the
vector, then `REVEALED_CONFIRMED`.

## 9. Confirm weights are set

1. Local summary:

   ```bash
   sudo cathedral-validator-status
   ```

   `OPERATING_CONFIRMED` (exit 0) means the timer is active and enabled, the
   channel is stable, no recovery is pending, and a confirmed write or commit
   was recorded within the last hour. Anything else exits 2 and names an
   `action`. The summary does not prove current chain inclusion.
2. On chain: read the subnet's weight rows and find your validator UID's row,
   for example with Bittensor CLI 11.1.0:

   ```bash
   btcli --network finney query uid --netuid 94 --hotkey YOUR_PUBLIC_HOTKEY
   btcli --network finney --json query weights --netuid 94
   ```

   The validator writes mechanism 0. The row changes when the reveal applies,
   about one epoch after the commit. It should match the committed cycle's
   `wire_uids` and `wire_weights`.

## 10. When it stops or writes nothing

| Status | Meaning | Do |
|---|---|---|
| `NOT_REGISTERED`, `NO_PERMIT` | No registration or permit at the finalized block. | Fix it on chain. The validator keeps checking and starts writing on its own. |
| `NOT_PROVEN` | Success is unresolved, or a pre-sign rule refused. | Read the reason in the log. The next cycle resumes recovery first. |
| `EXPIRED_WITHOUT_INCLUSION` | A saved write reached the end of its mortal era. | Nothing. Recovery resolves it and the same cycle continues. |
| `CONTRADICTION_STOPPED` (exit 2) | A deliberate terminal stop. | Inspect the journal and finalized chain state before acting. |
| `REVEAL_NOT_APPLIED` | The chain consumed a commit and did not apply it. The cycle prints `CONTRADICTION_STOPPED`. | Find the cause (permit, stake, version key, drand). Then follow [Commit-reveal subnets](AUTO_UPDATE.md#commit-reveal-subnets). |
| `FINALIZED_FAILED_STOPPED` (exit 3) | A write was included in a finalized block and failed. | Follow [Failed weight write](AUTO_UPDATE.md#failed-weight-write), then start the service. |

The unit does not restart after exit 2 or 3 (`RestartPreventExitStatus=2 3`).
Add an alert with an `OnFailure=` drop-in, as described in
[Failed weight write](AUTO_UPDATE.md#failed-weight-write).

## 11. Updates

The stable timer checks for a signed release 15 minutes after start and then
hourly. A release activates only when the journal is idle and the new release
reports ready; a failed first readiness restores the previous release. Pause
and resume, the journal location, and the recovery rules are in
[Validator auto-update](AUTO_UPDATE.md). There is no manual rollback: never
replace the `current` link by hand.

`sudo cathedral-validator-status` warns five days before the channel metadata
expires. After expiry the validator keeps running, and updates are refused
until the maintainer re-signs the channel.

## Optional: TDX measurement allowlist

Intel TDX is legacy. Use this section only if TDX machines still appear in
your rounds.

A TDX machine passes when its quote is genuine and current; by default any
guest image passes. To pay only guest images you have reviewed, install a
policy:

```json
{"schema": "cathedral_tdx_measurement_policy_v1",
 "mode": "shadow",
 "allowed_measurements": ["tdx-image-sha256:<64 hex>"]}
```

Entries are either `tdx-image-sha256:<64 hex>` (the v2 image identity) or
`tdx-measurement-sha256:<64 hex>` (the v1 launch measurement); a machine
passes when either of its values is listed. The currently pinned TDX verifier
release does not emit the image identity yet, so under that pin only v1
entries match; the cycle summary reports `observed_images` once the pinned
verifier emits it.

Generate it from the owner's signed measurement list with cathedral-sandbox's
`cathedral policy-registry export-measurement-policy` (`--registry`,
`--trusted-keys`, `--trusted-keys-digest`, `--state`, `--mode`, `--scope`,
`--out tdx-measurement-policy.json`; see its `--help` and the sandbox's
docs/MRTD.md). It verifies the signed release and writes the policy plus
`tdx-measurement-policy.json.source.json`, which records the release, its
digest, the policy file's digest and when the release expires. The policy
file takes no other keys; `allowed_measurements` is sorted and unique, and
`shadow` may list none. Install both files, and the env file that names the
policy, so the validator's service user can read them but not change them:

```bash
sudo install -o root -g cathedral-validator -m 0440 \
  tdx-measurement-policy.json /etc/cathedral-validator/tdx-measurement-policy.json
sudo install -o root -g cathedral-validator -m 0440 \
  tdx-measurement-policy.json.source.json \
  /etc/cathedral-validator/tdx-measurement-policy.json.source.json
sudo install -o root -g root -m 0600 \
  deploy/validator-update/direct-tdx-measurement.env.example \
  /etc/cathedral-validator/direct-tdx-measurement.env
```

Signed releases never change the systemd unit, and the unit from bootstrap
sequence 3 does not read that env file. Unless
`systemctl cat cathedral-validator-direct` shows
`EnvironmentFile=-/etc/cathedral-validator/direct-tdx-measurement.env`, add the
drop-in from
[Optional unit settings](AUTO_UPDATE.md#optional-unit-settings) first.
The policy is read once, at start, so restart after installing or editing
either file, including the switch from shadow to enforce:

```bash
sudo systemctl restart cathedral-validator-direct
```

At start the service log shows
`{"tdx_measurement_policy": {"status": "LOADED", "mode": ..., "digest": ...,
"source": "recorded", "registry_release": ..., "registry_digest": ...,
"registry_valid_until": ...}}`: the
signed list release the policy was exported from, read from the
`.source.json` beside it. The record is advisory and never stops the
validator. `"source": "unrecorded"` means there is none (a hand-written
policy); `"unreadable"` means it is malformed, too large or unsafe and is
ignored, with a `warning`. A `warning` also appears when the record's
`policy_digest` is not the loaded policy's `digest` (the two files come from
different exports) or when the release's `registry_valid_until` has passed;
regenerate both files and restart. The check runs once, at start.
`"status": "NOT_LOADED"` means the env file exists but the unit does not read
it, so no policy applies. A policy that doesn't load (missing, unreadable,
malformed, or enforce with an empty list) stops the validator at start with
`TDX measurement policy refused:` and the unit retries every 15 seconds until
it is fixed.

In `"mode": "shadow"` the machines are paid as before, and each cycle's line
carries `evidence_summary.tdx_measurement`: every measurement the policy
judged this cycle, paid or not, with whether it is listed and how many
machines reported it (the 32 most common; `observed_omitted` counts the rest).
Once you have reviewed and listed them, switch to `"enforce"`: a machine whose
measurement is not listed fails with `tdx_measurement_not_allowed` and earns
zero; if it is a miner's primary, that miner's whole fleet is excluded. A
policy that admits no machine at all leaves the cycle with nothing to pay, so
it writes no weights. With a policy set, the evidence digest also binds its
mode and digest. When the source record names the loaded policy,
`evidence_summary.tdx_measurement` also carries `registry_release`; the
evidence digest does not, so it is unchanged with or without a record.

Expect more entries than images. RTMR0 follows the VM shape (vCPUs and
memory), RTMR1 the guest kernel and initrd, and RTMR3 what the guest extends
at runtime. A guest package upgrade that rebuilds the initramfs changes the
measurement while MRTD stays fixed, so under enforce a miner who patches their
guest earns zero until the new value is listed. Without the env file nothing
changes.


## Optional: scoped INFRA handling

- `machine verification round is not fully proven` means a verifier returned
  INFRA (it could not reach a verdict: collateral, a timeout, unreadable
  output), so nothing was written and the last weights stay on chain, rather
  than zeroing machines for what may be a local outage. When the message adds
  that `CATHEDRAL_INFRA_HALT=scoped` would have written the round, the verifier
  passed another machine of that TEE kind in the same round, so it was at least
  partly working. The INFRA may still be a partial outage (Intel collateral is
  per platform, AMD's per chip, and a verifier timeout is INFRA too), or it may
  come from one miner's evidence, which today can stop every miner's weights.

  To write such rounds, opt in with a drop-in (not in `direct.env`, which
  setup compares byte for byte):

  ```
  # /etc/systemd/system/cathedral-validator-direct.service.d/infra-halt.conf
  [Service]
  Environment=CATHEDRAL_INFRA_HALT=scoped
  ```

  then `sudo systemctl daemon-reload` and restart the service. With it, an
  INFRA machine earns zero for that round, and a miner whose own axon machine
  is INFRA earns zero for its whole fleet (its fleet list is never fetched).
  In a partial outage that means honest machines lose that round's share to
  the machines that passed. A round with no PASS of an INFRA kind still halts.


## Never

- Never copy a coldkey, mnemonic, or coldkey password to the host.
- Never delete, replace, or edit the journal to clear an error.
- Never install or enable updater units from a source checkout.
- Never add `--netuid` to the telemetry arguments file.
- Never run the stable and canary timers together.
- Never widen the SNP policy with placeholders, unobserved measurements,
  wildcards, or a lowered TCB floor.
