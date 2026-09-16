# GPU prelaunch qualification

The GPU command performs signed worker requests, admission verification, fixed CUDA work, duplicate rejection, and a local direct weight calculation. It never loads a chain wallet, builds an extrinsic, or submits weights. Existing CPU scoring and dependency pins remain unchanged.

## Current boundaries

- Native Intel TDX plus NVIDIA composite evidence uses the sandbox's signed active GPU profile and production verifier backends. Both components, fresh nonce, worker hotkey, TLS SPKI, exact device set and completion identity must match. A valid output alone is insufficient.
- The first G4 miner offer is eight separate Spot `g4-standard-48` VMs, each with one RTX PRO 6000 Blackwell Server Edition GPU. The physical profile is `gcp-g4-rtx-pro-6000-sev-v1`; the public bundle is `gcp-g4-rtx-pro-6000-8gpu-v1`. It is not one eight-GPU confidential VM or an interconnected GPU pod.
- G4 accounting requires exactly eight distinct verified GPU IDs and provider instance IDs under one hotkey. Incomplete bundles and duplicate claims score zero. AMD SEV is not relabeled TDX or SNP. CPU host attestation remains unverified.
- **Pending authorization:** selecting the distinct G4 operator-trust verifier and configuring approved operator public keys. G4 source accounting does not make that trust model active. The current native verifier cannot qualify G4 evidence.
- **Not proven:** real GPU hardware, authentic vendor-verifier operation, provisioning custody, mining rewards and customer-secret routing. Hardware rental and live reward activation are outside this item.

## Source acceptance

Use the matching reviewed sandbox checkout containing `cathedral/gpu_work.py`. The existing CPU production dependency deliberately remains pinned to its earlier commit. A reviewed GPU packaging decision is still required; do not change a live CPU environment to run this command.

```sh
export PYTHONPATH="$PWD:$SANDBOX_CHECKOUT:$SANDBOX_CHECKOUT/tests"
python -m pytest -q \
  tests/thin/test_gpu_qualification.py \
  tests/thin/test_independent_validator_request.py \
  tests/integration/test_gpu_worker_wire.py
```

The integration test uses the real worker TLS server, sr25519 signed access and validator HTTP transport. CUDA and hardware evidence are explicit synthetic doubles. A passing test establishes wire compatibility, not hardware qualification. The integration test skips if the sandbox test fixture is unavailable, so an acceptance run must report it passing.

## Native composite configuration

`cathedral-gpu-qualify` reads an explicit JSON config with exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `cathedral_gpu_prelaunch_v1` |
| `enabled` | `true` |
| `network`, `netuid` | Explicit target; no inferred testnet |
| `validator_hotkey` | Qualified request-signing SS58 hotkey |
| `units_per_device` | Positive integer for this prelaunch calculation only; use `1` when recording the initial test policy |
| `registry_path` | Absolute signed registry JSON path |
| `trusted_keys_hex` | Explicit registry key ID to Ed25519 public-key hex map |
| `minimum_registry_release` | Positive anti-rollback bootstrap release |
| `registry_state_path` | Absolute durable registry state path |
| `profile_ids` | Enabled signed profile IDs, at most 32 |

Configure the sandbox's genuine pinned TDX and GPU verifier executables. Missing backends, unknown roots, inactive profiles, stale evidence or binding mismatches cannot create positive work scores.

```sh
cathedral-gpu-qualify \
  --config /absolute/path/gpu-prelaunch.json \
  --request-signer-executable /absolute/path/request-signer \
  --expected-genesis-hash "$EXPECTED_GENESIS_HASH" \
  --output /absolute/path/qualification.json \
  --gpu-directory-output /absolute/path/providers.json
```

The request signer receives canonical HTTP authorization JSON on stdin and returns one base64 sr25519 signature on stdout. The wrapper refuses non-GPU HTTP-access payloads. The signer holds only the separately authorized request key; the qualifier neither discovers nor loads wallets.

The command reads a finalized metagraph for registration and validator permit. Output weights are a local prelaunch projection with `chain_write: false`. Exit code `2` means not proven. No flag activates chain submission.

## Public provider listing

The producer writes atomically and strips endpoints, TLS identities, raw hardware evidence and private instance details. Worker rows aggregate into one miner/profile offer. G4 partial bundles show actual declared counts, with verification false until the full verified set exists. Public reward eligibility remains false in this prelaunch producer, even after successful work.

Failed or incomplete scans publish an unavailable document, which the edge projector rejects. They never replace missing evidence with a fresh empty provider inventory. Serve the file as `application/json`; the consumer independently rejects stale data.
