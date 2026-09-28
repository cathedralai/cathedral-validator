# Pool inventory

The direct validator can publish, each proven cycle, one signed document that
lists every machine the round probed and whether it was available and healthy.
It is the tracking view of the supply pool: what is available, what is healthy,
and what is assigned. It is off unless the operator turns it on, and it never
changes a round, its weights, or its receipt.

## The document

`cathedral_pool_inventory_v1`, written by
`cathedral_thin/independent_runtime/pool_inventory.py`:

| Field | Meaning |
|---|---|
| `network`, `netuid` | The subnet the round scored. |
| `anchor` | The finalized block number and hash the round read. |
| `validator` | The validator UID and hotkey that signed it. |
| `generated_at` | UTC time the document was built. |
| `totals` | `miners` scored, `machines` probed, `available`, `healthy`, `assigned`. |
| `assignment_source` | Always `null`: no customer work reaches miner machines yet, so `assigned` is 0. |
| `receipts` | `algorithm` (`rfc6962-sha256`), `leaves`, and the `merkle_root` over one leaf per machine. |
| `machines` | One entry per probed machine, sorted by UID and endpoint. |
| `inventory_id` | `sha256:` of the canonical header: every field except `machines`, `inventory_id` and `signature`. The header commits to the machines through `receipts.merkle_root`. |
| `signature` | sr25519 by the validator hotkey over `cathedral-pool-inventory-v1\0` plus `inventory_id`. |

Each machine carries its `uid`, `miner_hotkey`, `endpoint`, `tee_kind`,
`machine_id`, a `state`, and a `reason` when it is not healthy:

- `healthy`: the machine met the rule the weights pay for this round.
- `unverified`: it answered but failed a check. `reason` names the check,
  truncated to 160 characters.
- `unreachable`: it did not answer this round.

`available` counts `healthy` plus `unverified`. A reader can recompute every
total from `machines`, and the verifier refuses a document whose totals differ.

## Machine receipts

Each machine in the document also has a signed receipt,
`cathedral_machine_receipt_v1`, that verifies on its own. It carries the signed
header, the machine's entry (its leaf), the leaf's index, and an inclusion
proof. A reader recomputes the leaf hash (`SHA-256(0x00 || leaf)` over the
canonical JSON), follows the proof to the root (RFC 9162 section 2.1.3.2, node
hash `SHA-256(0x01 || left || right)`), compares it with
`receipts.merkle_root`, checks the header against `inventory_id`, and checks
the validator's sr25519 signature over `inventory_id`. The receipt proves what
this validator recorded for this machine in this round, paid or not and why,
without the rest of the document.

## Publishing it

Pass `--pool-inventory /absolute/path/pool-inventory.json` to the direct
validator. The directory must exist. The file is replaced atomically, mode
`0644`, after each proven cycle's weight write. The cycle's log line then
carries `pool_inventory` with `PUBLISHED` and the `inventory_id`, or `FAILED`.

The installed unit passes no inventory flag. Adding one through the telemetry
arguments file carries the same hazard as any new flag there: an update
rollback to a runtime older than this option exits with status 2 on the unknown
flag and is not restarted. Enable it only once the updater's rollback target
already includes this option.

## Serving and verifying it

```bash
cathedral-validator pool-inventory serve --inventory /absolute/path/pool-inventory.json --host 127.0.0.1 --port 8094
cathedral-validator pool-inventory verify --inventory /absolute/path/pool-inventory.json
```

The server answers `GET /v1/pool/inventory` with the signed file and
`GET /v1/pool/receipt` (below), `404` for any other path, and `503` while no file is published. It loads no key and
reads nothing else. Put it behind your own HTTPS front end to expose it.

`GET /v1/pool/receipt?uid=N&endpoint=URL` returns one machine's receipt, built
from the published file after verifying it: `400` for a malformed query, `404`
when no machine matches.

```bash
cathedral-validator pool-inventory receipt --inventory /absolute/path/pool-inventory.json --uid 19 --endpoint https://203.0.113.5:8081
cathedral-validator pool-inventory verify-receipt --receipt receipt.json
```

`verify-receipt` needs only the receipt file and prints
`MACHINE_RECEIPT_VALID` with the machine's entry, or `MACHINE_RECEIPT_INVALID`
and exits 1.

`verify` checks the shape, the totals, the identity, and the validator's
signature, and prints `POOL_INVENTORY_VALID` with the totals, or
`POOL_INVENTORY_INVALID` and exits 1.
