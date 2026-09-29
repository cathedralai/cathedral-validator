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
| Telemetry | Optional | Refused, because telemetry events are Finney-only |

Localnet and testnet mode cannot both be on.

## What you need

- **A TDX VM with a public IP** for the miner. For example, a GCP c3 confidential VM (TDX) on Ubuntu 24.04. The worker's port must be reachable.
- **A Linux x86-64 host for the validator.** The release TDX verifier and `snpguest` are Linux x86-64 binaries.
- **About τ3 of test TAO** in a testnet-only coldkey:
  - the subnet lock costs τ1;
  - testnet's `StakeThreshold` is 0, so a small stake gives the validator its permit.

  Never use a Finney coldkey on testnet.

## 1. Chain setup (testnet only)

```bash
btcli wallet create --wallet-name cathedral-testnet --network test
btcli subnets create --network test --wallet cathedral-testnet   # note the new netuid: N
btcli sudo start --netuid N --network test --wallet cathedral-testnet   # testnet StartCallDelay is 0
btcli sudo set --netuid N --name commit_reveal_weights_enabled --value false --network test --wallet cathedral-testnet
btcli wallet new-hotkey --wallet-name cathedral-testnet --wallet-hotkey validator
btcli wallet new-hotkey --wallet-name cathedral-testnet --wallet-hotkey miner1
btcli subnets register --netuid N --network test --wallet cathedral-testnet --wallet-hotkey validator
btcli subnets register --netuid N --network test --wallet cathedral-testnet --wallet-hotkey miner1
btcli stake add --netuid N --amount-tao 0.5 --network test --wallet cathedral-testnet --wallet-hotkey validator
```

- The direct writer refuses a weights rate limit below 16 blocks. The default of 100 is fine.
- The validator's permit lands at the first epoch after the stake does.

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
  btcli axon set --netuid N --network test --wallet cathedral-testnet --wallet-hotkey miner1 --ip <public ip> --port <port>
  ```
- **Worker:**
  ```bash
  python -m cathedral.cli worker serve ... --validator-network test --validator-netuid N --public-endpoint https://<public ip>:<port>
  ```

## Green checks

| # | Check | Evidence |
|---|---|---|
| 1 | Validator runs in testnet mode | `TESTNET_DEVELOPMENT_MODE`, then `CONFIRMED` cycles |
| 2 | Real TDX quote passes | The cycle's evidence summary shows the miner verified by the release QVL |
| 3 | Miner earns | `btcli subnets metagraph N --network test` shows incentive above 0 |
| 4 | Plan B | Commit-reveal on, with `CATHEDRAL_VALIDATOR_COMMIT_REVEAL=timelocked-v4-reveal-period-1` (#272): commits reveal and incentive holds |
| 5 | Recovery | Restart the validator mid-cycle: no double write; the journal recovers |
| 6 | Same file as Finney | The candidate that passed 1-5 is the one signed for Finney |
