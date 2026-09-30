# Testnet rehearsal: the SN94 loop on real hardware before Finney

Run the whole loop on Bittensor's public testnet, with real miners on real TDX hardware and the release verifiers: discovery, signed requests, the Intel quote check, SAT, a finalized weight write, and miner incentive. Go to Finney once every check below is green.

Testnet mode (`CATHEDRAL_TESTNET=1`, code in `cathedral_thin/independent_runtime/localnet.py`) changes only where the chain is. It keeps the release QVL, the SNP verifier, and public-address-only dialing, and it refuses Finney:

| Pin | Production | Testnet mode |
|---|---|---|
| `--network` | `finney` only | `test` or `wss://test.finney.opentensor.ai:443` only |
| Genesis | Finney's | Testnet's (`0x8f9c...3105`); a Finney connection is refused |
| `--netuid` | 94 only | Required and explicit, because netuid 94 on testnet is another team's subnet |
| Request network | `finney` | `test` |
| Journal scope | `finney-sn94-...` | `testnet-sn<netuid>-...`, which the updater and status tool never read |
| Telemetry | Optional. Events say `finney` and netuid 94 | Optional. Events say `test` and the `--netuid` the validator runs on |

Localnet and testnet mode cannot both be on.

## What you need

- **A TDX VM with a public IP** for the miner. For example, a GCP c3 confidential VM (TDX) on Ubuntu 24.04. The worker's port must be reachable.
- **A Linux x86-64 host for the validator.** The release TDX verifier and `snpguest` are Linux x86-64 binaries.
- **About τ3 of test TAO** across two testnet-only coldkeys, one for the subnet and validator and one for the miner:
  - the subnet lock costs τ1;
  - testnet's `StakeThreshold` is 0, so a small stake gives the validator its permit;
  - the miner's coldkey needs the registration burn (`btcli subnets burn-cost N --network test`).

  Never use a Finney coldkey on testnet.

## 1. Chain setup (testnet only)

```bash
btcli wallet create --wallet-name cathedral-testnet --network test         # owns the subnet and the validator
btcli wallet create --wallet-name cathedral-testnet-miner --network test   # owns the miner; it must not own the subnet
btcli subnets create --network test --wallet cathedral-testnet   # note the new netuid: N
btcli sudo start --netuid N --network test --wallet cathedral-testnet   # testnet StartCallDelay is 0
btcli sudo set --netuid N --name commit_reveal_weights_enabled --value false --network test --wallet cathedral-testnet
btcli wallet new-hotkey --wallet-name cathedral-testnet --wallet-hotkey validator
btcli wallet new-hotkey --wallet-name cathedral-testnet-miner --wallet-hotkey miner1
btcli subnets register --netuid N --network test --wallet cathedral-testnet --wallet-hotkey validator
btcli subnets register --netuid N --network test --wallet cathedral-testnet-miner --wallet-hotkey miner1
btcli stake add --netuid N --amount-tao 0.5 --network test --wallet cathedral-testnet --wallet-hotkey validator
```

- The direct writer refuses a weights rate limit below 16 blocks. The default of 100 is fine.
- The validator's permit lands at the first epoch after the stake does.
- **Register the miner from a different coldkey than the one that owns the subnet.** The chain pays no miner emission to a hotkey the subnet owner's coldkey holds, or to the subnet owner hotkey: it burns or recycles it (`distribute_dividends_and_incentives` in subtensor's `run_coinbase.rs`). The metagraph still shows the amount under `emission`, so a miner registered with the commands above looks paid and is not. The 2026-09-30 rehearsal lost its first epoch's 147.6 alpha this way.
- **The validator needs a majority of the active stake.** With kappa 0.5 a miner's consensus weight is the stake-weighted median over active validators. The subnet owner hotkey holds the owner's root stake, sets no weights, and counts as active until it has been silent for the activity cutoff (5000 blocks by default). Until then the validator's weights are clipped to zero and miners earn nothing. Either wait, or childkey the owner hotkey to the validator (7200 blocks), or lower the cutoff on the rehearsal subnet:
  ```bash
  btcli sudo set --netuid N --name activity_cutoff_factor --value 2000 --network test --wallet cathedral-testnet   # per-mille of tempo: 2000 is two tempos
  ```
  This is a difference from Finney's subnet. Put it back (`13889` is 5000 blocks at tempo 360) when the rehearsal is over.

## 2. Validator (Linux host)

Use the release-candidate artifacts of the revision under test: the pex, `cathedral-tdx-verifier` and `snpguest`. Download them with `gh run download` from `release-candidate.yml`, then run:

```bash
CATHEDRAL_TESTNET=1 cathedral-validator \
  --network test --netuid N \
  --wallet-name cathedral-testnet --wallet-hotkey validator \
  --expected-hotkey <validator ss58> \
  --qvl runtime/cathedral-tdx-verifier \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --snpguest runtime/snpguest \
  --confirm-direct-write
```

The first line printed is `TESTNET_DEVELOPMENT_MODE`, with the genesis, netuid and verifier digest.

## 3. Miner (TDX VM)

Run the worker the way `localnet/run_miner.sh` does, with two differences:
- no `CATHEDRAL_LOCALNET_STUB_EVIDENCE`, so the quote is real;
- the testnet names.

- **Access snapshot** (refresh it every few minutes). Run it from a cathedral-sandbox checkout:
  ```bash
  python scripts/cathedral_validator_access.py capture --network test --netuid N ...
  ```
- **Announce the axon:**
  ```bash
  btcli axon set --netuid N --network test --wallet cathedral-testnet-miner --wallet-hotkey miner1 --ip <public ip> --port <port>
  ```
- **Worker:**
  ```bash
  python -m cathedral.cli worker serve ... --validator-network test --validator-netuid N --public-endpoint https://<public ip>:<port>
  ```

## 4. Telemetry (optional)

The same two hops as Finney (`docs/PRIVATE_TELEMETRY.md`), with the testnet names. Nothing else changes, so the path that fills the public board is rehearsed too.

- **Validator:** add `--telemetry-spool /absolute/path/events.jsonl --telemetry-reader-group <group>`. Each event says `"network": "test"` and the netuid the validator runs on, and is signed by the validator hotkey like a Finney event.
- **Exporter:** run it in testnet mode and name the same netuid:
  ```bash
  CATHEDRAL_TESTNET=1 PEX_INTERPRETER=1 cathedral-validator \
    -m cathedral_thin.independent_runtime.telemetry_exporter \
    --netuid N --spool /absolute/path/events.jsonl --reader-group <group> \
    --endpoint <collector URL> \
    --ingest-token-file <file> --sites-authorization-file <file>
  ```
- **The modes do not mix.** A Finney exporter refuses a testnet event, and a testnet exporter refuses a Finney one. On Finney the exporter accepts no netuid but 94, so the production unit needs no change.
- **The collector decides separately** whether it accepts `test` events. It checks the validator's permit on chain, so it has to check the chain the event names.
- **With commit-reveal on, a round's event is written one epoch later**, by the cycle that proves the chain revealed the commit (#281). Without that change the validator writes no event at all on a commit-reveal subnet (#280). The board's edge has to allow for the delay too: an event is about one epoch old when it arrives.
- **The exporter needs #283.** Before it, the module this command starts never calls `main()`: the command exits 0 and sends nothing.

## Green checks

| # | Check | Evidence |
|---|---|---|
| 1 | Validator runs in testnet mode | `TESTNET_DEVELOPMENT_MODE`, then `CONFIRMED` cycles |
| 2 | Real TDX quote passes | The cycle's evidence summary shows the miner verified by the release QVL |
| 3 | Miner earns | The epoch block carries `IncentiveAlphaEmittedToMiners` with the miner's amount, **and** the miner hotkey's alpha on the subnet rose by it. Incentive above 0 in the metagraph is not enough: an owner-held key shows it and is paid nothing |
| 4 | Plan B | Commit-reveal on, with `CATHEDRAL_VALIDATOR_COMMIT_REVEAL=timelocked-v4-reveal-period-1` (#272): commits reveal and incentive holds |
| 5 | Recovery | Restart the validator mid-cycle: no double write; the journal recovers |
| 6 | Public board | The spool's latest event names `test` and netuid N, the exporter prints `EXPORTED`, and the board shows the row labelled Testnet |
| 7 | Same file as Finney | The candidate that passed 1-6 is the one signed for Finney |
