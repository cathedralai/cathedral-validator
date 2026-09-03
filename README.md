# Cathedral Validator

Cathedral Validator scores compute on Bittensor SN39 and writes weights directly
with your validator hotkey. It does not download a weight vector, use a relay,
or send your key to Cathedral.

## What it does

Each cycle, the validator:

1. Reads a finalized SN39 metagraph and finds serving miners.
2. Authenticates to each miner and requests its machine fleet.
3. Verifies Intel TDX or AMD SEV-SNP evidence and the same SAT workload.
4. Removes duplicate endpoints, TLS identities, and physical machines.
5. Gives each UID credit for its distinct verified machines, then converts those
   counts into one weight vector with zero burn.
6. Signs and submits the vector with your hotkey, then checks finalized chain
   state for the exact result.

Invalid, duplicate, or late machines receive no credit. AMD SEV-SNP machines
must match your reviewed local SNP policy. The validator release includes the
pinned TDX and SNP verifier programs.

## What you need

- A Linux/amd64 systemd host with CPython 3.12, `python3.12-venv`, and OpenSSL 3.
  Ubuntu 24.04 LTS is what Cathedral tests on.
- A hotkey registered on SN39 that holds a validator permit. The validator
  refuses to start otherwise, and a permit depends on your stake relative to
  other validators.
- Your Bittensor validator hotkey file and its public SS58 address, the
  `ss58Address` field inside that file. The file must be unencrypted (the
  `btcli` default for hotkeys) and readable only by its owner.
- A reviewed AMD SEV-SNP policy containing only measurements and TCB floors you
  trust. The template is in
  [Validator auto-update](docs/AUTO_UPDATE.md#before-installation).

### Machine

Two virtual CPUs, 4 GB of memory, and 20 GB of disk are enough. The validator
is light: one scoring cycle every 25 minutes, and between cycles it is idle.
Measured on the Cathedral production validator, a 4 vCPU cloud instance:

| Resource | Observed |
|---|---|
| Peak memory of the validator service | 349 MB |
| CPU time per scoring cycle | about 11 seconds |
| Disk used by the installed releases | 211 MB for three retained releases |

No GPU. No confidential-computing hardware on the validator host; the TDX and
SEV-SNP evidence it checks comes from the miners it scores.

### Network

Outbound only. The validator serves nothing and needs no inbound ports or
public address.

- The Bittensor Finney entrypoint, for finalized chain reads and your weight
  submissions.
- `raw.githubusercontent.com` and `github.com`, for the signed release channel
  and the release archives it downloads.
- Each serving SN39 miner, on the address and port it advertises on chain.
  These are arbitrary hosts and ports that change as miners come and go, so
  outbound traffic to them cannot be pinned to a fixed allowlist.

Never copy a coldkey, mnemonic, or coldkey password to the validator host. The
service receives only the hotkey file and checks it against the expected public
address before chain access.

## Install

Do not install or enable updater services from a source checkout. The install
script downloads the signed bootstrap release, verifies it against the
bootstrap signing key pinned inside the script, and installs the updater as
root-owned files. It installs no release and enables nothing. It is short.
Read it first if you want to. The bootstrap it installs, with its issue and
expiry times, is listed under
[Bootstrap trust](docs/AUTO_UPDATE.md#bootstrap-trust).

```bash
curl -fsSL --proto '=https' --tlsv1.2 -o install.sh \
  https://raw.githubusercontent.com/cathedralai/cathedral-validator/main/scripts/install.sh &&
echo '2957ec3487c550adbec9cb08955364d74af14a22140f400a48f5b0c92490cf25  install.sh' | sha256sum -c &&
sudo bash install.sh
```

The last line it prints is one JSON line ending in `"status":"installed"`.
If the digest line prints `FAILED`, nothing runs: the download is cached for
up to five minutes after a change, so retry after five minutes, and if it
still fails, stop and open an issue. If a check inside the script fails it
stops, changes nothing, and names the staging directory it kept for
inspection. `bootstrap manifest has expired` means the bootstrap is past its
expiry and a new one is due, not that anything was tampered with.

Then run the guided setup once with your hotkey file, its public address, and
your reviewed SNP policy, and read the local status:

```bash
sudo cathedral-validator-setup \
  --hotkey-file "$HOME/.bittensor/wallets/YOUR_WALLET/hotkeys/YOUR_HOTKEY" \
  --expected-hotkey YOUR_PUBLIC_HOTKEY_SS58 \
  --snp-policy /absolute/reviewed/amd-sev-snp-policy.json \
  --confirm-direct-write
sudo cathedral-validator-status
```

Setup installs the current signed `stable` release, starts the validator, and
enables the stable update timer. `SETUP_COMPLETE` on the last line means the
host is running. `SETUP_REFUSED` names the exact check that failed and changes
nothing.

## Operate

The validator is one recurring process. There is no alternate scoring mode and
no non-writing mode. A successful cycle prints `CONFIRMED` or
`RECOVERED_CONFIRMED` after the exact row is confirmed at inclusion and two
later finalized heads.

`sudo cathedral-validator-status` is the one local summary: service health,
signed release, update timer, and the latest recorded weight result. It does
not replace finalized chain verification. The service log is
`sudo journalctl -u cathedral-validator-direct.service -f`.

- `NOT_PROVEN` means success is unresolved. The next cycle resumes recovery
  before any new write.
- `EXPIRED_WITHOUT_INCLUSION` means the saved write reached the end of its
  mortal era without finalized inclusion. Recurring operation then moves on.
- `CONTRADICTION_STOPPED` is a deliberate terminal stop. Inspect the journal
  and finalized chain state before taking action.

Never delete or replace the journal to clear an error. The journal location,
pause and resume, and the recovery rules are in
[Validator auto-update](docs/AUTO_UPDATE.md).

## Updates

Signed releases update the validator, pinned TDX verifier, and pinned SNP
verifier together. The updater waits until the scoring cycle and write journal
are idle before it switches, and a release that fails verification or startup
keeps the last healthy one running. Public setup follows `stable` only.
Cathedral runs every release on its own canary host before publishing it to
`stable`.

Releases never replace the bootstrap updater, systemd units, host Python,
signing keys, hotkey, SNP policy, or operator configuration. Those change only
when this page publishes a new bootstrap.

## Trust

The install script pins the bootstrap signing key by fingerprint and refuses
any other key. The signed bootstrap manifest binds the exact bundle and the
runtime release key that every later release must be signed with. Setup and
the updater verify each release against that key before activating it. The
hotkey goes to the unprivileged validator service only, and never to the
updater or to Cathedral.

Two values are worth comparing against a source other than this repository
before you install: the script digest in the install block above, and the
bootstrap signing key fingerprint below. Cathedral publishes both together
with every bootstrap. The fingerprint changes only on key rotation:

```text
sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
```

The full trust boundary and what the updater can and cannot touch are in
[Validator auto-update](docs/AUTO_UPDATE.md).
