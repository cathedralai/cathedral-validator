# Run a Cathedral validator

## 1. What it does

Cathedral Validator downloads Cathedral's signed SN39 weight list, rejects it
if its signature, policy, or current hotkey-to-UID mapping is wrong, and submits
the accepted list to Bittensor with your validator hotkey.

It does not mine. It does not need a GPU or confidential-compute hardware.

## 2. What you need

- An x86-64 Linux machine with systemd and `/usr/bin/python3.12`. Ubuntu 24.04
  is the simplest choice.
- A steady internet connection to GitHub, `api.cathedral.computer`, and the
  Bittensor Finney network.
- `sudo` access.
- Your Bittensor validator hotkey file, usable without an interactive password.
  The validator needs it to sign weight submissions. The installer never needs
  your coldkey, seed phrase, or wallet password.

There is no benchmarked hardware minimum. A sensible starting point is 2 CPU
cores, 4 GB RAM, and 20 GB of free disk.

## 3. Install, run, and know it is working

```bash
sudo apt-get update
sudo apt-get install -y git python3.12-venv
git clone https://github.com/cathedralai/cathedral-validator.git
cd cathedral-validator
sudo ./deploy/sn39/install-validator \
  --hotkey "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY"
```

The installer locks the exact Git commit and dependencies, copies only the
hotkey into the validator service account, verifies the installation, and
starts the validator.

Check it with:

```bash
sudo systemctl status cathedral-validator-sn39-relay.service --no-pager
sudo journalctl -u cathedral-validator-sn39-relay.service -f
```

`active (running)` means the process is online. `WEIGHTS_SUBMITTED` means a
cycle reached Bittensor and submitted weights. The first cycle begins when the
service starts. Later checks run about every 25 minutes. If a cycle cannot
submit, the journal states why and the service keeps running for the next one.
