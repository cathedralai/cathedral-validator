# Capacity receipts (shadow)

The SN94 owner's prober probes each registered Cathedral runtime box every round and signs a
receipt of the CPU and memory it verified (cathedral-sandbox `docs/CAPACITY.md`). A validator on
any netuid can score those receipts at market price. This build **only records** the result: it
never changes the weights the validator writes.

**TEE boxes first.** Only TEE boxes (Intel TDX or AMD SEV-SNP) earn by default. Bare-metal boxes
are deferred, not removed: their receipts are still verified and shown, but they earn nothing
unless the policy sets `"admit_bare_metal": true`.

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
  "recheck_max_mib": 0,
  "inventory_path": "/var/lib/cathedral-validator/capacity-inventory.json",
  "admit_bare_metal": false,
  "minimum_price_table_sequence": 1,
  "price_table_digest": "<64 hex: the table's digest, optional>"
}
```

`inventory_path`, `admit_bare_metal`, `minimum_price_table_sequence` and `price_table_digest` are
optional; the rest are required.

- `prober_keys`: take them only from the SN94 owner's published prober attestation.
- `price_keys` and `price_table`: the owner's price-table key and the signed table. The table is
  verified when the validator starts. To change prices, replace the file and restart.
- `minimum_price_table_sequence` (an integer of at least 1; default 1) and `price_table_digest`
  (64 lowercase hex; optional): a rollback floor for the table. The signed table lives in this
  local policy file, so nothing but these stops an older signed table from being pasted back in
  by mistake. A table whose `sequence` is below the minimum is refused, and with a digest, a
  table at exactly the minimum sequence must be the table with that digest (a newer sequence is
  accepted). When you move to a new table, raise the minimum to its sequence and pin its digest
  (`cathedral.capacity.pricing.table_digest`). A refused table means the policy does not load.
- `admit_bare_metal` (`true` or `false`; default `false`): whether bare-metal boxes earn. When
  off, a bare-metal receipt that verifies is refused with the reason `bare-metal boxes are not
  admitted (admit_bare_metal is off)`; it still appears in the rows, and in the inventory as
  unhealthy with that reason. When on, bare metal is valued at the table's `bare_metal` rates.
- `recheck_max_mib` (0 to 64): `0` turns the recheck off. Otherwise the validator recomputes one
  sampled challenge lane per receipt whose lane needs at most this many MiB, and marks the rest
  `skipped`. It starts no new lane after a minute, so a cycle spends at most about a minute plus
  one lane. **In practice the recheck is off for now, whatever this is set to.** The library
  refuses any claim with less than a 512 MiB lane per vCPU (`MIN_LANE_BYTES`), so every real lane
  is at least 512 MiB, above the 64 MiB cap, and every receipt is `skipped`. The cap is not
  raised to fit one: the recheck runs the library's pure-Python reference (about 1.5 µs per
  step), and the smallest lane (16.7M blocks, 33.5M steps) takes about a minute, the whole
  budget, holding 512 MiB, and can't be stopped once started. Rechecking real receipts waits for
  a native checker; until then the prober's own sampled check is what verifies the lanes.

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
   the challenge proves the capacity it pays for. Each receipt is handled on its own: if
   verifying or valuing one raises anything at all, that receipt is refused (the reason is the
   error's type name, or the library's message for a receipt it rejects) and the rest of the
   round is scored as usual. One malformed receipt never fails the round;
3. refuses bare-metal boxes unless `admit_bare_metal` is on;
4. refuses a box that appears twice and hardware claimed under two hotkeys (both earn nothing),
   and counts one box per hardware id for a single hotkey (the more valuable one);
5. refuses hotkeys that aren't serving miners on this netuid, and boxes smaller than every
   consumer profile (for example SN120's or SN81's minimum shape);
6. values each remaining box as `vcpus × vcpu_hour[kind] + memory_gib × gib_hour`, in
   micro-units of the table's currency per hour, and sums the values per UID.

The result is logged as its own line after the cycle's line, `{"anchor_block": ...,
"capacity_shadow": {...}}`. It holds the status, the policy digest, the table's sequence, the
per-reason refusal counts, `units` (`[uid, value]`), and the first 32 receipt rows
(`rows_omitted` counts the rest; each verified row carries `kind` and `tee_kind`, which is
`tdx`, `sev_snp`, or `null` for bare metal), so the line stays small. Recovery cycles get no record. An
error becomes `"status": "FAILED"`, never a failed cycle.

## The inventory

With `inventory_path` (optional; an absolute `.json` path the validator can write, normally in
its state directory `/var/lib/cathedral-validator`), each cycle also updates a local inventory
of every box this validator has seen:

- `healthy`: its receipt this cycle verified and was accepted. `streak` counts consecutive
  healthy cycles;
- `unhealthy`: its receipt verified but was refused, with the `reason` (including bare metal
  while `admit_bare_metal` is off);
- `missing`: seen before but absent this cycle. It is dropped after 24 quiet cycles.

Each box records its hotkey, UID, kind, TEE kind, hardware id, capacity, value, and first and last seen.
A receipt that does not verify names no box anyone can trust, so it never appears. The file is
replaced atomically (mode 600). A file that can't be read, or that is for another netuid, starts
a new inventory. A write failure shows as `"inventory": {"status": "FAILED"}` in the shadow
record and changes nothing else.

The shadow record carries the inventory's `aggregate`: box counts by status, and healthy boxes,
vCPUs, memory and value by kind. It names no box, hotkey or hardware, so it can be published. To
read the file:

```
sudo python -m cathedral_thin.independent_runtime.capacity_inventory \
  /var/lib/cathedral-validator/capacity-inventory.json [--aggregate]
```

(or with the release's interpreter). Which sandboxes are assigned to a box is known only to the
control plane that routes them, so the inventory has no such field. The control plane's
`GET /v1/pool` combines this kind of health view with its own assignments.

## Not yet

- Bare-metal boxes earn only with `admit_bare_metal`; admitting them by default waits until
  the TEE path is established.
- Paying by these values (an `enforce` mode) is a later change, after the shadow records have
  been compared with today's weights.
- The receipt feed and the prober are run by the SN94 owner and are not in this repository.
