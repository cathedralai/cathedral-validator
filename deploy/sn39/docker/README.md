# SN39 validator — Docker (3 commands)

A cross-platform way (macOS / Linux / Windows) to run the relay validator without a
native Python setup. It builds **this repo** into an image and runs the shipped
`cathedral-validator serve`. Same trust profile as the native quickstart — just packaged.

> For the **canonical, auditable wallet-host install**, use the native path in the repo
> README quickstart (or `../wallet-host-quickstart.sh`). Containers are the fast
> cross-platform option; the native path is the one an auditor reads line by line.

## Run it

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator/deploy/sn39/docker

./cathedral config      # 4 prompts: coldkey, validator hotkey, network, broadcast?
./cathedral up          # builds the image the first time, then runs the validator
```

Watch it: `./cathedral logs` · stop it: `./cathedral down`.

## What you need
- **Docker** (Docker Desktop on macOS/Windows; `docker.io` on Linux).
- A Bittensor **coldkey** on this machine (default `~/.bittensor/wallets/`).
- A **registered SN39 validator hotkey** (not your miner hotkey). Check with
  `./cathedral candidate` — it reads the live chain and tells you if a hotkey qualifies.

## Shadow vs on-chain
`./cathedral config` asks *"Broadcast weights on-chain?"*
- **no** (default) → shadow: reads chain, composes, **writes nothing** (`--dry-run`).
- **yes** → sets weights on mainnet. Only with a **registered + staked** validator hotkey
  (an unstaked one's weights are ignored by consensus).

Re-run `./cathedral config` to change it, then `./cathedral up`.

## Notes
- Your wallet is mounted **read-only**; validator state is a **forward-only** volume
  (a rebuild never rewinds a spent submission fence).
- The image installs `.[provenance]`, which version-couples a **pinned** cathedral-compute
  — the image is a coherent release set, not a floating checkout.
- **Production single-host lifecycle** (staged upgrades + rollback) is the systemd model in
  `..` (`deploy/sn39`) + [`#102`](https://github.com/cathedralai/cathedral-validator/pull/102),
  not this container. Use this to stand up + prove; use that to operate 24/7.

## Commands
| | |
|---|---|
| `./cathedral config` | set coldkey / hotkey / network / broadcast → `.env` |
| `./cathedral up` | build (first time) + run |
| `./cathedral candidate` | which hotkey can validate (live chain) |
| `./cathedral logs` \| `status` \| `down` | manage it |
