<p align="center"><img src="docs/assets/cathedral-mark.png" alt="Cathedral" width="112"></p>
<h1 align="center">Cathedral Validator</h1>
<p align="center"><em>Run a validator for Bittensor SN94</em></p>
<p align="center"><sub>2 November 2026</sub></p>

Cathedral rewards people who break out of its sealed sandboxes. A verified escape earns SN94 weight, and each one makes the Cathedral runtime harder to break. Cathedral also rewards miners for sealed compute, gated by demand.

Your validator checks escape claims and miner machines (AMD SEV-SNP or Intel TDX evidence plus a test task), rejects duplicate claims and writes the weights to Bittensor SN94 with your hotkey. It does not download a weight vector, use a relay or send your key to Cathedral. Signed updates install themselves.

## System Requirements

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Ubuntu 24.04 LTS, 2 vCPU, 4 GB RAM, 20 GB disk. No GPU, no inbound ports.
- An SN94 hotkey with a validator permit: its unencrypted hotkey file and its
  public SS58 address. Never copy a coldkey, mnemonic, or coldkey password to
  this host.

## Run it

1. Install. The script checks the signed bootstrap and enables nothing.

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo 'b89e806563c70e93c301f2f4ab8d32dfaba6f1961776e3990328d92a63a279f5  install.sh' | sha256sum -c &&
sudo bash install.sh
```

If the digest line prints `FAILED`, nothing runs; retry in five minutes. See
[Bootstrap trust](docs/AUTO_UPDATE.md#bootstrap-trust).

2. Set up with your hotkey.

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --confirm-direct-write
sudo cathedral-validator-status
```

`SETUP_COMPLETE` means the host runs the signed stable release.

3. Watch it.

```bash
sudo journalctl -u cathedral-validator-direct.service -f
```

On SN94 a good cycle shows `COMMITTED`, then `REVEALED_CONFIRMED`.

Before you install, compare the install digest above and the bootstrap signing
key fingerprint `sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013` with an independent source.

## More

- [Operator guide](docs/OPERATOR_GUIDE.md): what it checks, Docker, every
  status code, updates and trust.
- [Operator runbook](docs/OPERATOR_RUNBOOK.md): step by step, with the chain rules.
- [Validator auto-update](docs/AUTO_UPDATE.md): updates, recovery and pause.
