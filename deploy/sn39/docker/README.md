# SN39 validator no-write preview — Docker

A cross-platform way to inspect the signed-vector relay without a native Python
setup. It builds this repository and runs `cathedral-validator serve` with a
fixed `--dry-run`. The shipped Docker surface exposes no submission selector.

Production has one path: the immutable native systemd release documented in the
root README. Docker is only a no-write evaluation surface.

## Run it

```bash
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator/deploy/sn39/docker

./cathedral config      # wallet, validator hotkey, wallet path, and network
./cathedral up          # builds the image, then starts a no-write preview
```

Watch it: `./cathedral logs` · stop it: `./cathedral down`.

## What you need
- **Docker** (Docker Desktop on macOS/Windows; `docker.io` on Linux).
- A Bittensor **coldkey** on this machine (default `~/.bittensor/wallets/`).
- A **registered SN39 validator hotkey** (not your miner hotkey). Check with
  `./cathedral candidate` — it reads the live chain and tells you if a hotkey qualifies.

## No-write boundary

The entrypoint always passes `--dry-run`, accepts no extra validator arguments,
and refuses the retired `CATHEDRAL_BROADCAST` setting. Re-run
`./cathedral config` once to remove that setting from an older `.env`.

## Notes
- Your wallet is mounted **read-only**; validator state is a **forward-only** volume
  (a rebuild never rewinds a spent submission fence).
- The image installs `.[provenance]`, which version-couples a **pinned** cathedral-compute
  — the image is a coherent release set, not a floating checkout.
- Production chain writes use the root-owned systemd launcher in `deploy/sn39`.
  This container is not a production alternative.

## Commands
| | |
|---|---|
| `./cathedral config` | set wallet, hotkey, wallet path, and network in `.env` |
| `./cathedral up` | build and run the no-write preview |
| `./cathedral candidate` | which hotkey can validate (live chain) |
| `./cathedral logs` \| `status` \| `down` | manage it |
