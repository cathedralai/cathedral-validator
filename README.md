# Cathedral Validator

Cathedral rewards verified compute, not self-reported capacity. Validators
independently check miner machines, test their work, reject duplicate claims
and submit the resulting weights to Bittensor SN94.

This repository is for validator operators. The service writes directly with
your hotkey; it does not download a weight vector, use a relay or send your key
to Cathedral. Miners use [Cathedral Sandbox](https://github.com/cathedralai/cathedral-sandbox).

## What it does

Each cycle finds serving miners without validator permits, verifies fresh Intel
TDX or AMD SEV-SNP evidence and SAT work, rejects duplicate hardware/endpoints/
TLS keys, and weights the distinct verified machines with zero burn.
It signs the vector and checks the exact result against finalized chain state.

SNP requires your reviewed measurement and TCB policy. By default TDX accepts
any guest image with a genuine, fresh quote: a quote is not an image allowlist.
See [TDX measurement policy](docs/OPERATOR_RUNBOOK.md#optional-tdx-measurement-allowlist).

## What you need

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Ubuntu 24.04 LTS is tested; 2 vCPU, 4 GB RAM and 20 GB disk are sufficient.
  No GPU or confidential-computing hardware is required on the validator host.
- An SN94-registered hotkey with a validator permit, its unencrypted keyfile
  and expected public SS58 address. Without registration/permit the service
  keeps checking but writes no weights.
- A reviewed SNP policy; use the [policy template](docs/AUTO_UPDATE.md#before-installation).
- Outbound access to Finney, GitHub, advertised miner endpoints and vendor
  verification collateral. No inbound ports or public address are needed.
- Subnet commit-reveal must be disabled for this writer. Check all
  [chain rules](docs/OPERATOR_RUNBOOK.md#3-check-the-subnet-accepts-direct-writes) first.

Never copy a coldkey, mnemonic, or coldkey password to this host. The
service receives only the hotkey file and checks its expected public address.

## Install

Read the [operator runbook](docs/OPERATOR_RUNBOOK.md) first, including its
published-bootstrap/subnet check. Do not install or enable updater services from a source checkout.
The script verifies the signed bootstrap before installing root-owned tools;
it enables nothing. See [Bootstrap trust](docs/AUTO_UPDATE.md#bootstrap-trust).

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo '7f4056ba35b4c8d836c30c363f1095d4cdd0ea0edeb3fe229d2638dd905358ef  install.sh' | sha256sum -c &&
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

## Operate

There is no alternate scoring mode and no non-writing mode.
A successful cycle prints `CONFIRMED` or `RECOVERED_CONFIRMED`.
Local status is not a substitute for [finalized chain verification](docs/OPERATOR_RUNBOOK.md#8-confirm-weights-are-set).

```bash
sudo cathedral-validator-status
sudo journalctl -u cathedral-validator-direct.service -f
```

- `NOT_PROVEN` means success is unresolved; recovery comes before a new write.
- `EXPIRED_WITHOUT_INCLUSION` means the write expired without finalized inclusion.
- `CONTRADICTION_STOPPED` requires inspecting the journal and finalized chain.
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
See [updates and recovery](docs/AUTO_UPDATE.md) for the exact trust boundary.

## Trust

Compare the install-script digest above and this bootstrap signing-key
fingerprint against an independent source before installing:

```text
sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
```

The script refuses other keys. The signed bootstrap pins the later runtime
release key. The hotkey belongs to the unprivileged validator service, never
the updater or Cathedral.
