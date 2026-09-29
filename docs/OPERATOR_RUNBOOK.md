# Validator operator runbook

One path, in order, from a fresh Linux host to a confirmed weight row on chain.
It links to the canonical instructions instead of repeating them: the
repository [README](../README.md) is the install guide, and
[Validator auto-update](AUTO_UPDATE.md) owns the updater, the journal, and
recovery. Where this page and those two disagree, they win.

This page describes `main` after the move to subnet 94. File and line
references are to that tree.

## 0. Check which subnet the published installer targets

The README pins one signed bootstrap sequence. A bootstrap installs the
updater, systemd units, and the setup and status tools, and a runtime release
never replaces them. The subnet move changed files the bootstrap ships (the
status tool's journal path and the updater's journal scope). Until a bootstrap
signed after that change is published, `install.sh` installs tools that watch
the previous subnet's journal. Compare the sequence pinned in `scripts/install.sh`
with the one listed under
[Bootstrap trust](AUTO_UPDATE.md#bootstrap-trust) and its signing date, and ask
the release maintainer before registering if they predate the move.

## 1. Prepare the host

- Linux/amd64 with systemd, CPython 3.12 at `/usr/bin/python3.12`,
  `python3.12-venv`, and OpenSSL 3. Ubuntu 24.04 LTS is the tested system. The
  installer refuses anything else (`deploy/validator-update/install_updater_bundle.py`,
  its runtime guard).
- 2 vCPU, 4 GB RAM, and 20 GB disk are enough (README, "Machine"). Releases are
  retained on disk; leave room for them to accumulate.
- Outbound access only: the finney entrypoint, `github.com` and
  `raw.githubusercontent.com`, every serving miner's advertised address, and
  Intel's collateral service at `api.trustedservices.intel.com` for TDX quote
  verification.
- Keep the clock synchronized. Signed release metadata is refused when it is
  not yet valid or has expired, so a drifting clock blocks installs and
  updates. `timedatectl status` should report a synchronized clock.
- Install the packages from
  [Before installation](AUTO_UPDATE.md#before-installation).
- Never place the coldkey file, mnemonic, or coldkey password on this host.

## 2. Prepare the hotkey on chain

From a separate wallet machine, not the validator host:

1. Register the validator hotkey on the subnet, for example with Bittensor CLI
   11.1.0:

   ```bash
   btcli --network finney \
     --wallet YOUR_WALLET \
     --wallet-hotkey YOUR_HOTKEY \
     subnet register --netuid 94
   ```

2. Stake enough to hold a validator permit. The permit depends on your stake
   relative to other validators and is granted at an epoch. Without it the
   validator runs, writes nothing, and reports `NO_PERMIT`.
3. Copy only the hotkey file to the validator host. It must be the
   unencrypted keyfile `btcli` writes for hotkeys, mode `0600`, inside a
   directory named `hotkeys`, with a signing secret in it. Setup refuses an
   encrypted, public-only, or coldkey file.

## 3. Check the subnet accepts direct writes

The writer checks the chain's rules at the finalized block before it signs,
and refuses to write, cycle after cycle, if any of these does not hold
(`cathedral_thin/independent_runtime/direct_writer.py`, pre-sign checks):

| Chain setting | Must be |
|---|---|
| Commit-reveal | Disabled. The writer has no commit path. |
| `weights_rate_limit` | At least 16 blocks, and the cooldown since your last write elapsed. |
| `WeightsVersionKey` | At most the version the release signs with (`cathedral_thin/independent/constants.py`). |
| Your stake | At least the subnet's weight stake threshold. |
| Weight count | The vector must meet the chain's minimum allowed weights. |

Read the subnet's hyperparameters with your Bittensor CLI before installing.
Each refusal appears as `NOT_PROVEN` with its reason in the service log, and
the validator retries the next cycle.

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
measurements and TCB floors you reviewed. The miner's SNP probe transcript
(in the sandbox repository) records the observed measurement and TCB to review.

Setup accepts exactly the two top-level keys `schema` and `generations`. The
runtime also understands `require_single_socket`, which defaults to `true`, but
setup refuses a policy that contains it, so a dual-socket SNP host cannot be
admitted through setup yet.

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

## 7. Watch the first cycles

```bash
sudo journalctl -u cathedral-validator-direct.service -f
```

The service reports ready after startup recovery, then runs one cycle
immediately and one every 1500 seconds. Each cycle prints one JSON line with
`status`, the finalized `anchor`, `raw_scores`, the wire weights, the
`evidence_digest`, and the write `receipt`. The first success prints
`CONFIRMED`.

## 8. Confirm weights are set

1. Local summary:

   ```bash
   sudo cathedral-validator-status
   ```

   `OPERATING_CONFIRMED` (exit 0) means the timer is active and enabled, the
   channel is stable, no recovery is pending, and a confirmed write was
   recorded within the last hour. Anything else exits 2 and names an `action`.
   The summary does not prove current chain inclusion.
2. On chain: read the subnet's weight rows and find your validator UID's row,
   for example with Bittensor CLI 11.1.0:

   ```bash
   btcli --network finney query uid --netuid 94 --hotkey YOUR_PUBLIC_HOTKEY
   btcli --network finney --json query weights --netuid 94
   ```

   The validator writes mechanism 0. The row should match the latest cycle's
   `wire_uids` and `wire_weights`.

## 9. When it stops or writes nothing

| Status | Meaning | Do |
|---|---|---|
| `NOT_REGISTERED`, `NO_PERMIT` | No registration or permit at the finalized block. | Fix it on chain. The validator keeps checking and starts writing on its own. |
| `NOT_PROVEN` | Success is unresolved, or a pre-sign rule refused. | Read the reason in the log. The next cycle resumes recovery first. |
| `EXPIRED_WITHOUT_INCLUSION` | A saved write reached the end of its mortal era. | Nothing. Recovery resolves it and the same cycle continues. |
| `CONTRADICTION_STOPPED` (exit 2) | A deliberate terminal stop. | Inspect the journal and finalized chain state before acting. |
| `FINALIZED_FAILED_STOPPED` (exit 3) | A write was included in a finalized block and failed. | Follow [Failed weight write](AUTO_UPDATE.md#failed-weight-write), then start the service. |

The unit does not restart after exit 2 or 3 (`RestartPreventExitStatus=2 3`).
Add an alert with an `OnFailure=` drop-in, as described in
[Failed weight write](AUTO_UPDATE.md#failed-weight-write).

## 10. Updates

The stable timer checks for a signed release 15 minutes after start and then
hourly. A release activates only when the journal is idle and the new release
reports ready; a failed first readiness restores the previous release. Pause
and resume, the journal location, and the recovery rules are in
[Validator auto-update](AUTO_UPDATE.md). There is no manual rollback: never
replace the `current` link by hand.

`sudo cathedral-validator-status` warns five days before the channel metadata
expires. After expiry the validator keeps running, and updates are refused
until the maintainer re-signs the channel.

## Never

- Never copy a coldkey, mnemonic, or coldkey password to the host.
- Never delete, replace, or edit the journal to clear an error.
- Never install or enable updater units from a source checkout.
- Never add `--netuid` to the telemetry arguments file.
- Never run the stable and canary timers together.
- Never widen the SNP policy with placeholders, unobserved measurements,
  wildcards, or a lowered TCB floor.
