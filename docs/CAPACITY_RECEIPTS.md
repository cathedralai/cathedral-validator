# Capacity receipts (shadow)

The SN94 owner's prober probes each registered Cathedral runtime box every round and signs a
receipt of the CPU and memory it verified (cathedral-sandbox `docs/CAPACITY.md`). A validator on
any netuid can score those receipts at market price. This build **only records** the result: it
never changes the weights the validator writes.

**TEE boxes first.** Only TEE boxes (Intel TDX or AMD SEV-SNP) earn by default. Bare-metal boxes
are deferred, not removed: their receipts are still verified and shown, but they earn nothing
unless the policy sets `"admit_bare_metal": true`.

**Receipt v2.** Receipts use cathedral-sandbox's schema `cathedral_capacity_receipt_v2`. A TEE
box's receipt carries the `evidence` the prober verified before it took the box's hardware id;
a bare-metal receipt carries `"evidence": null`, and the prober signs one only when told to
(`sign_receipt(..., allow_bare_metal=True)`). A v1 receipt, or a TEE receipt without well-formed
evidence, does not verify and is refused on its own. The evidence is:

| field | what it is |
| --- | --- |
| `evidence_kind` | the box's TEE kind, `tdx` or `sev_snp` |
| `evidence_sha256` | SHA-256 of the raw quote or report the prober verified |
| `measurement` | the launch measurement: `tdx-measurement-sha256:<64 hex>`, or SEV-SNP's 96 hex |
| `verifier_digest` | `sha256:<64 hex>` of the verifier that checked it |
| `tls_spki_sha256` | SHA-256 of the SPKI of the TLS key the quote's REPORT_DATA binds |
| `attestation_nonce` | 64 hex: the prober's 32-byte nonce the quote's REPORT_DATA was made over |
| `attested_at` | `YYYY-MM-DDTHH:MM:SSZ`, no later than the receipt's `issued_at`: when the prober verified the quote |

The prober gets it from the library's admission (`cathedral.capacity.admission.admit`), which
takes the pinned verifier's own verdict and the raw quote, refuses a partial verification, and
reads REPORT_DATA and the measurement from the quote itself. The quote's REPORT_DATA must bind the prober's nonce, the miner hotkey and the TLS key it saw on the
sandbox API connection (`report_data_v2`), and a host already admitted as another box is
refused, so no evidence exists for it and no receipt can be signed. So is a box whose
measurement a shadow-mode admission policy does not list: it is recorded but never gets
evidence. A validator cannot re-verify the quote from the receipt; `evidence_sha256` lets it
audit one later against the prober's archive, and the library's
`receipt.expected_report_data` gives the REPORT_DATA that quote must carry.

The evidence is the attestation from the box's admission, or from its last relaunch between
customers, and is reused for every round's receipt until the next one. An idle box is not
relaunched, so its evidence can be of any age while the box stays healthy. By default the
validator therefore sets no age bound, as the library's `verify_receipt` does not. With
`max_evidence_age_seconds` set, it refuses a TEE receipt whose `attested_at` is more than that
before now (`verify_receipt(..., max_evidence_age=)`), with the library's reason `the receipt's
evidence is older than max_evidence_age`.

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
  "price_table_digest": "<64 hex: the table's digest, optional>",
  "measurement_policies": ["/etc/cathedral-validator/tdx-measurement-policy.json"]
}
```

`inventory_path`, `admit_bare_metal`, `minimum_price_table_sequence`, `price_table_digest`,
`measurement_policies` and `max_evidence_age_seconds` are optional; the rest are required.

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
  With the defaults (1, no digest) any validly signed table is accepted, so the validator logs
  `{"capacity_shadow": {"status": "LOADED", "warning": "price_table_digest is not pinned: ..."}}`
  once at start until you pin one.
- `admit_bare_metal` (`true` or `false`; default `false`): whether bare-metal boxes earn. When
  off, a bare-metal receipt that verifies is refused with the reason `bare-metal boxes are not
  admitted (admit_bare_metal is off)`; it still appears in the rows, and in the inventory as
  unhealthy with that reason. When on, bare metal is valued at the table's `bare_metal` rates.
- `measurement_policies` (optional; one or two absolute paths): measurement allowlists for the
  TEE evidence, at most one per TEE kind. Each file is the direct validator's TDX measurement
  policy (#256), `{"schema": "cathedral_tdx_measurement_policy_v1", "mode": "shadow" | "enforce",
  "allowed_measurements": [...]}`, so the same file can serve both, or the SEV-SNP variant
  `cathedral_snp_measurement_policy_v1` with 96-hex measurements. Files are read like this policy
  (a regular file, not a symlink, not world-writable) and parsed by the library's
  `admission.parse_policy`, so they need a cathedral-sandbox with `cathedral.capacity.admission`.
  In `enforce`, a TEE receipt whose measurement is not listed is refused with the reason `the TEE
  evidence measurement is not on the enforced measurement allowlist`; in `shadow` it is accepted
  and only recorded (`measurement_allowed: false`). A kind with no policy is recorded, never
  checked. Without the key nothing is checked. Each file's mode and digest appear in the record
  as `measurement_policies`, since this policy's own digest covers only the paths.
- `max_evidence_age_seconds` (optional; an integer from 1 to 604800, seven days): the oldest
  TEE evidence a receipt may rest on, measured from its `attested_at` to the validator's clock.
  Without it there is no bound. The prober attests a box at admission and again after each
  relaunch between customers, so an idle box's evidence can be arbitrarily old. Set this only
  if your prober re-attests on a known cadence, and leave room for a late re-attestation plus
  the time until your cycle reads the receipt; otherwise every TEE receipt is refused once its
  evidence ages past the bound.
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
2. verifies every receipt: the prober key, the netuid, the nonce, the round, freshness, the age
   of a TEE receipt's evidence (only with `max_evidence_age_seconds`), and that the challenge proves the
   capacity it pays for. Each receipt is handled on its own: if
   verifying or valuing one raises any `Exception`, that receipt is refused (the reason is the
   error's type name and message, cut to 200 characters, or the library's message for a receipt
   it rejects) and the rest of the round is scored as usual. One malformed receipt never fails
   the round; `KeyboardInterrupt` and `SystemExit` still stop the validator;
3. refuses bare-metal boxes unless `admit_bare_metal` is on, and, with an enforced measurement
   policy, TEE boxes whose evidence measurement is not listed. A box refused for either takes
   no part in the next step, so it can't knock out an admitted box sharing its box id or hardware;
4. refuses a box that appears twice and hardware claimed under two hotkeys (both earn nothing),
   and counts one box per hardware id for a single hotkey (the more valuable one). The hardware
   id kind is fixed by the box: `tdx_platform` for TDX (derived from the digest in the strict
   verifier's `stable_platform_id`, `tdx-platform-sha256:<64 lowercase hex>`), `chip_id` for SEV-SNP,
   and `probe_fingerprint` for bare metal. The library rejects any other kind, `ppid` included;
5. refuses hotkeys that aren't serving miners on this netuid, and boxes smaller than every
   consumer profile (for example SN120's or SN81's minimum shape);
6. values each remaining box as `vcpus × vcpu_hour[kind] + memory_gib × gib_hour`, in
   micro-units of the table's currency per hour, and sums the values per UID.

The result is logged as its own line after the cycle's line, `{"anchor_block": ...,
"capacity_shadow": {...}}`. It holds the status, the policy digest, the table's sequence, and,
each capped so the line stays one journal line:

- `refused`: receipt counts for the 16 most common refusal reasons (`refused_omitted` counts the
  receipts refused for any other reason). A reason is at most 200 characters of printable
  ASCII;
- `units` (`[uid, value]`): the 64 UIDs with the highest value (`units_omitted` counts the rest,
  and `units_total` sums every UID);
- `rows`: the first 24 receipt rows (`rows_omitted` counts the rest).

The line therefore stays under 40,000 bytes in the worst case (the longest fields in every row,
thousands of UIDs and reasons; a test builds it), with margin below journald's default 48 KiB
line limit. The inventory file keeps every box. Each verified row carries `kind` and
`tee_kind` (`tdx`, `sev_snp`, or `null` for bare metal), its `evidence` (the seven fields above;
`null` for bare metal), and `measurement_allowed` (`true` or `false` against the policy for its
TEE kind, `null` when there is none). Recovery cycles get no record. An
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

Each box records its hotkey, UID, kind, TEE kind, hardware id, capacity, value, the `evidence` and
`measurement_allowed` of its latest receipt (kept while the box is missing, so it shows what the
box last ran), and first and last seen.
When the feed carries one box id in several rows, the inventory keeps an accepted row, else a
row refused for any reason but the box not being admitted (bare metal while it is off, or an
unlisted measurement under enforce), else the first row; so a not-admitted receipt reusing a
box's id never hides that box or its reason.
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

- The validator records the evidence but cannot re-verify a quote from a receipt; auditing
  `evidence_sha256` against the prober's quote archive is a later step.

- Bare-metal boxes earn only with `admit_bare_metal`; admitting them by default waits until
  the TEE path is established.
- Paying by these values (an `enforce` mode) is a later change, after the shadow records have
  been compared with today's weights.
- The receipt feed and the prober are run by the SN94 owner and are not in this repository.
