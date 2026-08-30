# AMD SEV-SNP development preview

`cathedral-amd-sev-snp-dev-preview` verifies one to 32 AMD SEV-SNP machines
assigned to the same explicit UID and miner hotkey. It produces a local
development artifact. It does not read chain state, sign weights, submit
weights, assign burn, or import a Cathedral chain writer.

This is not production admission. A successful preview reports
`production_eligible: false` and `authorized_for_chain_write: false`.

## What the preview proves

For each configured endpoint, the validator:

1. Opens the configured validator hotkey only. It does not open a coldkey.
2. Signs each protected worker request with that Bittensor hotkey.
   The same TLS-bound worker must accept a valid signed capability request and
   refuse invalidly signed and unsigned capability and evidence requests.
3. Uses HTTPS with the endpoint certificate anchored by `tls_ca_cert`.
4. Requests a fresh report-data-v2 SEV-SNP report bound to the observed TLS
   SPKI and the configured miner hotkey.
5. Runs the exact pinned Compute verifier and pinned `snpguest` binary.
6. Applies the measurement allowlist and Compute's generation-aware,
   componentwise minimum-TCB check.
7. Requires AMD guest `POLICY.SINGLE_SOCKET`, bit 20, before using CHIP_ID as
   a hardware identity.
8. Replaces CHIP_ID with a review-challenge-scoped HMAC pseudonym. Raw CHIP_ID
   and the raw report never enter the output artifact.
9. Sends an unsigned negative probe on the same attested TLS channel. The
   worker must reject it with an authorization error, proving signed validator
   access is required before SAT begins.
10. Sends one canonical 20-unit SAT challenge on the same attested TLS channel
   and independently checks the returned assignment.
11. Applies the existing multi-compute duplicate rules. Every duplicate
    endpoint, TLS key, or hardware pseudonym receives zero units.

AMD certificate-fetch or verifier timeouts remain `NOT_PROVEN` and are labelled
as verifier infrastructure failures, not as miner policy failures.

Distinct passing sockets receive 20 raw development units each. The result is
not a weight vector and is never accepted by a writer.

## Install boundary

The optional `snp-dev` dependency is pinned to an immutable
`cathedral-sandbox` commit:
`8dde6eaca27116eed53386a1fa33ec70b74a01fb`. The command verifies the installed
package's PEP 610 VCS provenance and refuses a different, local, mutable, or
wheel-only tree.

Install only the development extra:

```console
python -m pip install '.[snp-dev]'
```

## Configuration

Copy `config/amd-sev-snp-dev-preview.example.json` to an owner-controlled
mode-0600 file. Replace every illustrative endpoint, certificate path, measurement,
review challenge, scoring window, UID, and hotkey before use.

- `environment` must equal `development`.
- `network` and `netuid` are pinned to `finney` and `39` for signed worker
  request compatibility. The command does not query the chain.
- `validator_hotkey` must equal the public address of
  `validator_wallet.name` plus `validator_wallet.hotkey`.
- `validator_wallet.path` is either `null` for the Bittensor default or an
  absolute wallet root.
- `scoring_window` is a reviewer-chosen lowercase 32-byte scope hash. It is not
  presented as a finalized block proof by this development command.
- `review_challenge_hex` is a new, nonzero 32-byte challenge for this review.
  Reusing it across reviews weakens unlinkability of hardware pseudonyms.
- `snpguest_path` is an absolute path to the executable whose SHA-256 must
  match the Compute pin.
- `processor_generation` is exactly `milan`, `genoa`, or `turin`. The parsed
  report CPUID must map to the configured generation. One preview therefore
  covers one processor generation. Use separate configuration and output files
  for friends with a different generation.
- `allowed_measurements` contains one to 32 sorted, unique 48-byte measurement
  hex strings for the configured processor generation.
- `minimum_reported_tcb` is a nonzero 8-byte lowercase hex value interpreted
  as AMD's little-endian component array, not as one scalar version. Milan and
  Genoa use bytes `[bootloader, tee, 0, 0, 0, 0, snp, microcode]`. The example
  `0x0101000000000101` requires at least 1 for each component. Turin uses
  `[fmc, bootloader, tee, snp, 0, 0, 0, microcode]`. The equivalent all-1 floor
  is `0x0100000001010101`. Reserved bytes must be zero. Compute compares every
  applicable candidate component independently against its configured floor.
- `timeout_seconds` is between 1 and 60 per request.
- `targets` contains one to 32 entries. Every entry must repeat the same UID
  and miner hotkey and provide a canonical public HTTPS origin plus an absolute
  TLS trust-certificate path.

Run the preview once to a new absolute output path:

```console
cathedral-amd-sev-snp-dev-preview \
  --config /etc/cathedral/amd-sev-snp-dev.json \
  --output /var/lib/cathedral-validator/reviews/amd-sev-snp-dev.json
```

The output and detached SHA-256 are created with owner-only permissions. The
command refuses an existing output instead of overwriting it.

## Success condition

`PROVEN_DEVELOPMENT_NO_WRITE` means every configured target passed fresh AMD
verification, the configured generation match, guest-policy `SINGLE_SOCKET`,
signed-access enforcement, same-channel SAT, and global duplicate checks. The
total is exactly 20 multiplied by the number of distinct passing sockets.

Fields ending in `_requirement` describe the checks each target had to pass.
`all_configured_targets_passed` and each machine row report the actual preview
outcome.

It does not mean the miner is registered, the endpoint is on chain, the
validator assigned weight, or subnet emissions exist.
