# Cathedral Validator

Cathedral rewards verified compute, not self-reported capacity. Validators
check miner machines, test their work, reject duplicate claims and set weights
on Bittensor subnet 94 (SN94). SN39 is legacy; this validator does not support it.

This repository is for validator operators. The service writes directly with
your hotkey; it does not download a weight vector, use a relay or send your key
to Cathedral. Miners use [Cathedral Sandbox](https://github.com/cathedralai/cathedral-sandbox).

## What it does

Each cycle finds serving miners without validator permits, verifies fresh
AMD SEV-SNP evidence and SAT work, rejects duplicate hardware/endpoints/TLS
keys, and weights the distinct verified machines with zero burn.
It signs the vector and checks the exact result against finalized chain state.

SNP needs your reviewed measurement and TCB policy. Intel TDX is legacy but
still verified; by default it accepts any guest image with a genuine, fresh
quote. See [TDX measurement policy](docs/OPERATOR_RUNBOOK.md#optional-tdx-measurement-allowlist).

## What you need

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Ubuntu 24.04 LTS is tested; 2 vCPU, 4 GB RAM and 20 GB disk are sufficient.
  The host needs no GPU or confidential-computing hardware.
- An SN94 hotkey with a validator permit (the chain gives permits to top-stake
  hotkeys), its unencrypted keyfile and its public SS58 address. Without a
  permit the service keeps checking and writes no weights.
- A reviewed SNP policy for AMD SEV-SNP machines (EPYC Milan, Genoa or Turin,
  one socket). Use the [policy template](docs/AUTO_UPDATE.md#before-installation).
- Outbound access to Finney, GitHub, miner endpoints, `kdsintf.amd.com` (AMD)
  and Intel collateral (legacy TDX). No inbound ports are needed.
- SN94 has commit-reveal on, so you must opt in to timelocked commits. Check all
  [chain rules](docs/OPERATOR_RUNBOOK.md#3-check-the-chain-rules) first.

Never copy a coldkey, mnemonic, or coldkey password to this host. The
service receives only the hotkey file and checks its expected public address.

## Install

Read the [operator runbook](docs/OPERATOR_RUNBOOK.md) first.
Do not install or enable updater services from a source checkout.
The script verifies the signed bootstrap before installing root-owned tools;
it enables nothing. See [Bootstrap trust](docs/AUTO_UPDATE.md#bootstrap-trust).

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo '097c4d2285826860d0ab45fdf64a240a9883b5fec29fe271f57724efed02826f  install.sh' | sha256sum -c &&
sudo bash install.sh
```

If the digest line prints `FAILED`, nothing runs. Retry after five minutes;
if it still fails, stop and [open an issue](https://github.com/cathedralai/cathedral-validator/issues).
An expired bootstrap needs a newly signed publication, not a bypass.

Then configure the hotkey and reviewed SNP policy:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --confirm-direct-write
sudo cathedral-validator-status
```

`SETUP_COMPLETE` means the host is running the signed stable release.
`SETUP_REFUSED` names a failed check; it is not permission to bypass it.
Then opt in to timelocked commits. Until you do, the validator writes nothing.
Follow [Commit-reveal subnets](docs/AUTO_UPDATE.md#commit-reveal-subnets).

## Operate

There is no alternate scoring mode and no non-writing mode.
On SN94 a good cycle prints `COMMITTED`, then `REVEALED_CONFIRMED` about one
epoch later. A plain write prints `CONFIRMED` or `RECOVERED_CONFIRMED`.
Local status is not a substitute for [finalized chain verification](docs/OPERATOR_RUNBOOK.md#9-confirm-weights-are-set).

```bash
sudo cathedral-validator-status
sudo journalctl -u cathedral-validator-direct.service -f
```

- `NOT_PROVEN` means success is unresolved; recovery comes before a new write.
- `EXPIRED_WITHOUT_INCLUSION` means the write expired without finalized inclusion.
- `CONTRADICTION_STOPPED` requires inspecting the journal and finalized chain.
  A `REVEAL_NOT_APPLIED` commit also prints it.
- `FINALIZED_FAILED_STOPPED` means an included write failed on chain. Use
  `cathedral-validator record-failed-write` only as documented under
  [Failed weight write](docs/AUTO_UPDATE.md#failed-weight-write).
- `NOT_REGISTERED` / `NO_PERMIT`: resolve registration/permit on chain.
- Unresolved vendor verification halts the round by default. The optional
  [scoped INFRA policy](docs/OPERATOR_RUNBOOK.md#optional-scoped-infra-handling)
  can zero honest machines during a partial outage; do not enable it blindly.

Never delete or replace the journal to clear an error.
Recovery, pause/resume and diagnostics: [Validator auto-update](docs/AUTO_UPDATE.md).

## Updates

Signed releases update the validator, pinned TDX verifier, and pinned SNP verifier together.
The updater waits for an idle journal and keeps the last healthy release if
verification or startup fails. Public setup follows `stable` only.
Releases never replace the bootstrap updater, systemd units, host Python,
signing keys, hotkey, SNP policy or operator configuration.

## Trust

Compare the install-script digest above and this bootstrap signing-key
fingerprint against an independent source before installing:

```text
sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
```

The script refuses other keys. The signed bootstrap pins the later runtime
release key. The hotkey belongs to the unprivileged validator service, never
the updater or Cathedral.
