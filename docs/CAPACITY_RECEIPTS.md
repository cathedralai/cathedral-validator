# Capacity receipts (shadow)

The SN94 owner's prober probes each registered Cathedral runtime box every round and signs a
receipt of the CPU and memory it verified (cathedral-sandbox `docs/CAPACITY.md`). A validator on
any netuid can score those receipts at market price. This build **only records** the result: it
never changes the weights the validator writes.

## Turn it on

Set `CATHEDRAL_CAPACITY_POLICY` to the absolute path of a policy file, for example in
`/etc/cathedral-validator/direct.env`:

```
CATHEDRAL_CAPACITY_POLICY=/etc/cathedral-validator/capacity-policy.json
```

The file must be a regular file (not a symlink) and not world-writable:

```json
{
  "schema": "cathedral_capacity_policy_v1",
  "mode": "shadow",
  "receipts_url": "https://RECEIPT-FEED/v1/capacity/receipts",
  "prober_keys": {"sn94-prober-1": "<64 hex: raw Ed25519 public key>"},
  "price_keys": {"sn94-owner-1": "<64 hex: raw Ed25519 public key>"},
  "price_table": {"...": "the SN94 owner's signed price table, as published"},
  "recheck_max_mib": 0
}
```

- `prober_keys`: take them only from the SN94 owner's published prober attestation.
- `price_keys` and `price_table`: the owner's price-table key and the signed table. The table is
  verified when the validator starts. To change prices, replace the file and restart.
- `recheck_max_mib` (0 to 64): `0` turns the recheck off. Otherwise the validator recomputes one
  sampled challenge lane per receipt whose lane needs at most this many MiB. It starts no new
  lane after a minute, so a cycle spends at most about a minute plus one lane (a 64 MiB lane takes
  several seconds). The reference implementation is pure Python, so real lanes (gigabytes each)
  are skipped for now.

Without the variable nothing runs. A policy that does not load, for any reason, is reported
once at start (`"capacity_shadow": {"status": "DISABLED"}`) and the validator carries on as
before. It also needs a cathedral-sandbox that includes `cathedral.capacity`; the pinned one
does not yet, so until the pin moves the record says `DISABLED`.

## What each cycle does

After a cycle has written its weights and their telemetry, and released the cycle lock, the
validator:

1. makes a fresh 32-byte nonce and fetches `GET <receipts_url>/<netuid>/<nonce>`. The feed
   answers `{"schema": "cathedral_capacity_receipt_feed_v1", "netuid", "round",
   "validator_nonce", "receipts": [...]}` (at most 1 MiB and 1024 receipts). The prober signs
   each receipt for that nonce, so a validator can't reuse another validator's receipts;
2. verifies every receipt: the prober key, the netuid, the nonce, the round, freshness, and that
   the challenge proves the capacity it pays for;
3. refuses a box that appears twice and hardware claimed under two hotkeys (both earn nothing),
   and counts one box per hardware id for a single hotkey (the more valuable one);
4. refuses hotkeys that aren't serving miners on this netuid, and boxes smaller than every
   consumer profile (for example SN120's or SN81's minimum shape);
5. values each remaining box as `vcpus × vcpu_hour[kind] + memory_gib × gib_hour`, in
   micro-units of the table's currency per hour, and sums the values per UID.

The result is logged as its own line after the cycle's line, `{"anchor_block": ...,
"capacity_shadow": {...}}`. It holds the status, the policy digest, the table's sequence, the
per-reason refusal counts, `units` (`[uid, value]`), and the first 32 receipt rows
(`rows_omitted` counts the rest), so the line stays small. Recovery cycles get no record. An
error becomes `"status": "FAILED"`, never a failed cycle.

## Not yet

- Paying by these values (an `enforce` mode) is a later change, after the shadow records have
  been compared with today's weights.
- The receipt feed and the prober are run by the SN94 owner and are not in this repository.
