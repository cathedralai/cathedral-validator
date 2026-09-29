# Localnet: the SN94 mining loop on one Mac

This directory runs the whole Cathedral SN94 loop against a local subtensor
chain: miners serve, the direct validator scores them, the validator's weights
land on chain, and after an epoch the miners hold incentive and emission.
Nothing here touches Finney, a production host, or a production key.

Development only. Two things a laptop cannot have are stubbed: TDX hardware
evidence, and the pinned Linux x86-64 verifier binaries. Every stub is behind
an explicit environment gate that refuses to start against Finney.

## Quick start

Needs colima, the docker CLI, [uv](https://docs.astral.sh/uv/), and a
`cathedral-sandbox` checkout of branch `feature/localnet-e2e` next to this
repository (or set `CATHEDRAL_SANDBOX_DIR`).

```bash
./localnet/up.sh            # chain container, venvs, netuid 94, wallets, stake
./localnet/run_miner.sh     # 2 miner workers + validator-access snapshot refresher
./localnet/run_validator.sh # direct validator loop, one cycle every 30 s
./localnet/check.sh         # PASS once a miner has incentive and emission > 0
./localnet/down.sh          # stop miners, refresher, validator (--chain: container too)
```

From fresh clones with a warm uv cache the whole sequence took under two
minutes on an M4 (up.sh 51 s, run_miner.sh 21 s, first `CONFIRMED` write 7 s
after run_validator.sh, `check.sh` PASS at block 290). A cold uv cache adds the
Python installs. Logs and state live in `localnet/.run/` (git-ignored):
`logs/validator.log`, `logs/miner<i>.log`, `logs/snapshot-refresher.log`,
`logs/chain-watchdog.log`, `evidence/check-*.json`.

## What runs, and what is real

| Piece | Runs | Real or stub |
|---|---|---|
| Chain | `ghcr.io/opentensor/subtensor-localnet:devnet-ready`, fast blocks, ws://127.0.0.1:9944 | Real subtensor runtime: Yuma consensus, dTAO emission, weights, permits |
| netuid 94 | Created by `setup_chain.py` | Real registration. Placeholder subnets 2..93 exist only so the compiled `NETUID = 94` is untouched |
| Miner | cathedral-sandbox `cathedral worker serve`, the authenticated production TDX posture | Real signed validator access, TLS with channel binding, fleet endpoint, canonical SAT. **Stub: TDX quote** |
| Validator access | cathedral-sandbox `scripts/cathedral_validator_access.py capture`, re-signed every 2 min | Real: Ed25519 snapshot of permit holders read from the finalized local chain |
| Validator | `cathedral-validator` from this checkout | Real discovery, signed requests, HTTPS SPKI pinning, collect, SAT re-derivation, duplicate rules, zero-burn vector, writer gates, journal, finalized confirmation. **Stubs listed below** |

## Stubs and their guards

Validator (`CATHEDRAL_LOCALNET=1`, code in
`cathedral_thin/independent_runtime/localnet.py`). With the variable unset every
pin is exactly what it is on main. With it set, the process refuses
`--network finney` and any endpoint but `ws://127.0.0.1:<port>` or
`ws://localhost:<port>` before any chain access, and refuses to observe the
Finney genesis.

| Stub | Why | Guard |
|---|---|---|
| Genesis pin is `CATHEDRAL_LOCALNET_GENESIS_HASH` | The local chain has its own genesis | Must be canonical hex and must not equal the Finney genesis |
| `--network` accepts a local ws:// endpoint | The release pins `finney` | Only 127.0.0.1 or localhost, explicit port, no path |
| TDX verifier is `localnet/stub_tdx_verifier.py` | No TDX quote exists on a Mac, and the release QVL is a Linux x86-64 binary | Loaded only when its SHA-256 equals `LOCALNET_STUB_QVL_DIGEST`; accepts only the sandbox stub quote and still compares REPORT_DATA exactly |
| Private, CGNAT, and loopback IPv4 miner addresses are dialed | A laptop has no public IP; the chain refuses 127.0.0.1 | Only in localnet mode; unspecified, multicast, and IPv6 private stay refused |
| Validator requests sign network `local` | Workers bind requests to their snapshot's network | `local` is signable only in localnet mode |
| Journal scope `localnet-sn94-mechanism-0` | A local journal must never look like a Finney one | Only in localnet mode; `run_validator.sh` also points HOME at `.run/validator-home` |
| AMD SNP verifier not constructed | Its pinned `snpguest` is a Linux x86-64 binary and the pinned Compute contract is not installed | The SNP policy file is still loaded and validated; SNP evidence would be counted as SNP infrastructure failure |

Sandbox (`CATHEDRAL_LOCALNET_STUB_EVIDENCE=1`, code in
`cathedral/attest/localnet_stub.py`, cathedral-sandbox branch
`feature/localnet-e2e`).

| Stub | Why | Guard |
|---|---|---|
| Evidence collector returns magic + REPORT_DATA + platform bytes instead of a configfs-tsm quote | No TDX guest | Only with `worker serve`, complete signed validator access, and `--validator-network local`; `finney`, `test`, and every other network refuse to start. v2 channel-bound requests only |
| Worker accepts a private IPv4 `--public-endpoint` | A laptop has no public IP | Enabled only after the stub gate passes for `local` |

## Chain settings `setup_chain.py` applies (local chain only, via //Alice sudo)

- Cheap subnet creation: network rate limit 0, lock reduction interval 1, minimum lock 1 TAO.
- netuid 94: commit-reveal off (the direct writer refuses to write with it on), tempo 40,
  weights rate limit 20 (the writer refuses a limit below its 16-block era), immunity 100,
  max validators 1, owner cut off, start_call done.
- The owner's alpha is moved onto the validator hotkey with `move_stake`. A new subnet's
  owner hotkey holds nearly all stake and never sets weights, so Yuma's stake-weighted
  consensus would clip every miner to zero. The pool is too shallow to buy that much
  alpha (`add_stake` fails with InsufficientLiquidity).

## Evidence from the first proof run (2026-09-29)

- Validator cycle 1, anchor block 5821: 2 serving miners, evidence cycle 274 ms,
  `raw_scores [[2,1],[3,1]]`, `wire_uids [2,3]`, `wire_weights [32767,32768]`,
  extrinsic 0x7e1024238e97904c6bcb2855c3f25e57a5467c58555aecf12157d13b81ca11e6
  included in block 5830, `CONFIRMED` at finalized heads 5830..5832.
- Block 5887: validator UID 1 weight row `[[2, 65533], [3, 65535]]`; miner UID 2
  incentive 0.5, emission 9.9998; miner UID 3 incentive 0.5, emission 10.0002;
  validator dividends 1.0.
- Blocks 6795 to 6893: each miner's stake grew by about 20 alpha (two epochs).

## Operating notes

- The three fast-block nodes grow by roughly 15 to 20 MB a minute each.
  - `up.sh` starts the colima VM with `LOCALNET_VM_MEMORY_GIB` (default 6) and the container with `--no-purge`.
  - `chain_watchdog.sh` (started by `up.sh`) restarts the container when a node is gone or node memory passes `LOCALNET_CHAIN_MEMORY_LIMIT_MB` (default 3500).
  - It also stops the chain and the VM, then exits, when the host disk falls below `LOCALNET_MIN_FREE_DISK_GB` (default 8). A full disk broke the VM's docker storage once. Run `up.sh` again once space is back.
  - A restart keeps the chain: a test restart went from block 325 to 429 with netuid 94 intact, and the validator's next cycle confirmed.
  - An older container created without `--no-purge` resets on restart, so the watchdog leaves it alone.
- Keep the VM small relative to the host.
  - In a 6 GiB VM with no watchdog, the OOM killer took two nodes after about 40 minutes and the chain stopped finalizing.
  - A 12 GiB VM on a 24 GiB Mac failed differently. Overnight it pushed macOS into about 11 GB of swap, the disk filled, and the VM's docker storage returned I/O errors until the chain container could not restart.
  - Size the VM and the watchdog limit together, and watch `df -h` and `sysctl vm.swapusage` on the host.
- Never start a second localnet container in the same colima VM. Both chains
  share the genesis and `--discover-local`, so the new nodes join the running
  chain with the same authority keys and finality stalls.

- Fast blocks are about 0.3 s. The writer's 16-block mortal era and its anchor
  freshness window are therefore about 5 s of wall time. They hold here because
  every RPC is local; the first run's full evidence cycle took 274 ms.
- If this Mac's IP changes, rerun `run_miner.sh`; it re-serves each axon at the
  current address. Override with `LOCALNET_HOST_IP`.
- If the chain container is recreated, `up.sh` notices netuid 94 is gone, moves
  the validator journal aside (kept, not deleted), and rebuilds the subnet.
- `check.sh --timeout 300` waits longer; `chain_tool.py check` prints the raw rows.
