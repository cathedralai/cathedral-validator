# Validator operator guide

The [README](../README.md) has the three commands. This page has the detail: what each check does, Docker, status codes, updates and trust.

Validators independently check miner machines, test their work, reject duplicate claims and submit the resulting weights to Bittensor SN94.

This repository is for validator operators. The service writes directly with
your hotkey; it does not download a weight vector, use a relay or send your key
to Cathedral. Miners use [Cathedral Sandbox](https://github.com/cathedralai/cathedral-sandbox).

## What it does

Each cycle finds serving miners, verifies fresh Intel TDX or AMD SEV-SNP
evidence and SAT work, and rejects duplicate hardware/endpoints/TLS keys. It
then builds one weight vector with a fixed split:

- about 10 percent to the distinct verified machines of owner-approved miner
  hotkeys (the compute lane);
- about 10 percent to verified escape room breaks (the escape lane);
- the rest to the subnet owner hotkey, which the chain burns.

A verified machine on a hotkey that is not on the approved list earns no
compute weight. A lane with no recipient in a cycle is burned too. The list
ships inside the signed release and nothing on this host can change it. See
[Gated compute](GATED_COMPUTE.md).
It signs the vector and checks the exact result against finalized chain state.

SNP checks miners against the reviewed SN94 measurement and TCB policy that
ships in the signed bootstrap. By default TDX verification accepts
any guest image with a genuine, fresh quote: a quote is not an image allowlist.
Verification alone no longer earns weight: the hotkey must also be approved.
See [TDX measurement policy](OPERATOR_RUNBOOK.md#optional-tdx-measurement-allowlist).

## What you need

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Docker on Linux/amd64 is the other supported path. Ubuntu 24.04 LTS is
  tested; 2 vCPU, 4 GB RAM and 20 GB disk are sufficient. No GPU or
  confidential-computing hardware is required on the validator host.
- An SN94-registered hotkey with a validator permit, its unencrypted keyfile
  and expected public SS58 address. Without registration/permit the service
  keeps checking but writes no weights.
- Nothing for SNP: setup uses the reviewed SN94 policy shipped in the signed
  bootstrap. Pass `--snp-policy` only to use your own (see the
  [policy template](AUTO_UPDATE.md#before-installation)).
- Outbound access to Finney, GitHub, advertised miner endpoints and vendor
  verification collateral. No inbound ports or public address are needed.
- Live Finney SN94 has commit-reveal **enabled**. The writer turns on
  timelocked commits by default and reads `RevealPeriodEpochs` from chain.
  Pin `CATHEDRAL_VALIDATOR_COMMIT_REVEAL=timelocked-v4-reveal-period-N` only
  to refuse a mismatch (see
  [Commit-reveal subnets](AUTO_UPDATE.md#commit-reveal-subnets)). Check all
  [chain rules](OPERATOR_RUNBOOK.md#3-check-the-subnet-accepts-direct-writes) first.

Never copy a coldkey, mnemonic, or coldkey password to this host. The
service receives only the hotkey file and checks its expected public address.

## Docker

Pin the image by digest once CI publishes it. Until then the digest below is
a placeholder, not a real pin.

```bash
docker run -d --name cathedral-validator --restart unless-stopped \
  --stop-timeout 150 \
  --read-only --tmpfs /tmp --tmpfs /run --tmpfs /etc/cathedral-validator \
  --security-opt no-new-privileges \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --cap-add DAC_READ_SEARCH \
  -v cathedral-state:/var/lib/cathedral \
  -v ~/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY:/run/secrets/hotkey:ro \
  -v /root/sn94-snp-policy.json:/etc/cathedral/snp-policy.json:ro \
  -e CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=YOUR_PUBLIC_HOTKEY_SS58 \
  ghcr.io/cathedralai/cathedral-validator@sha256:<pinned>
```

Mount only the hotkey file and the SN94 policy, downloaded once with
`curl -fsSL -o /root/sn94-snp-policy.json https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/deploy/validator-update/sn94-snp-policy.json`.
The image refuses to start without the policy. CHOWN, FOWNER, and
DAC_OVERRIDE are required so the signed updater can create the validator-owned
journal. DAC_READ_SEARCH lets PID1 copy the mounted hotkey. Never mount a
coldkey.
Never run this container and a systemd unit against the same hotkey.
Never delete the `cathedral-state` volume. Status and recovery:

```bash
docker exec cathedral-validator cathedral-validator-status
docker logs -f cathedral-validator
docker exec -u cathedral-validator -e HOME=/var/lib/cathedral-validator \
  cathedral-validator cathedral-validator-record-failed-write \
  --network=finney --expected-hotkey=YOUR_PUBLIC_HOTKEY_SS58
```

Moving from a systemd host: [Docker migration](AUTO_UPDATE.md#docker-migration).

## Install

Read the [operator runbook](OPERATOR_RUNBOOK.md) first, including its
published-bootstrap/subnet check. Do not install or enable updater services from a source checkout.
The script verifies the signed bootstrap before installing root-owned tools;
it enables nothing. See [Bootstrap trust](AUTO_UPDATE.md#bootstrap-trust).

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo 'b89e806563c70e93c301f2f4ab8d32dfaba6f1961776e3990328d92a63a279f5  install.sh' | sha256sum -c &&
sudo bash install.sh
```

If the digest line prints `FAILED`, nothing runs. Retry after five minutes;
if it still fails, stop and [open an issue](https://github.com/cathedralai/cathedral-validator/issues).
An expired bootstrap needs a newly signed publication, not a bypass.

Then configure the hotkey:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --confirm-direct-write
sudo cathedral-validator-status
```

`SETUP_COMPLETE` means the host is running the signed stable release.
`SETUP_REFUSED` names a failed check; it is not permission to bypass it.

## Operate

There is no alternate scoring mode and no non-writing mode.
A successful cycle prints `CONFIRMED` or `RECOVERED_CONFIRMED`.
Local status is not a substitute for [finalized chain verification](OPERATOR_RUNBOOK.md#8-confirm-weights-are-set).

```bash
sudo cathedral-validator-status
sudo journalctl -u cathedral-validator-direct.service -f
```

- `NOT_PROVEN` means success is unresolved; recovery comes before a new write.
- `EXPIRED_WITHOUT_INCLUSION` means the write expired without finalized inclusion.
- `CONTRADICTION_STOPPED` requires inspecting the journal and finalized chain.
- `FINALIZED_FAILED_STOPPED` means an included write failed on chain. Use
  `cathedral-validator record-failed-write` only as documented under
  [Failed weight write](AUTO_UPDATE.md#failed-weight-write).
- `NOT_REGISTERED` / `NO_PERMIT`: resolve registration/permit on chain.
- Unresolved vendor verification halts the round by default. The optional
  [scoped INFRA policy](OPERATOR_RUNBOOK.md#optional-scoped-infra-handling)
  can zero honest machines during a partial outage; do not enable it blindly.

Never delete or replace the journal to clear an error.
Recovery, pause/resume and diagnostics: [Validator auto-update](AUTO_UPDATE.md).

## Updates

Signed releases update the validator, pinned TDX verifier, and pinned SNP verifier together.
The updater waits for an idle journal and keeps the last healthy release if
verification or startup fails. Public setup follows `stable` only.
Releases never replace the bootstrap updater, systemd units, host Python,
signing keys, hotkey, SNP policy or operator configuration.
See [updates and recovery](AUTO_UPDATE.md) for the exact trust boundary.

## Trust

Compare the install-script digest above and this bootstrap signing-key
fingerprint against an independent source before installing:

```text
sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
```

The script refuses other keys. The signed bootstrap pins the later runtime
release key. The hotkey belongs to the unprivileged validator service, never
the updater or Cathedral.
