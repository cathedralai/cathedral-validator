# Escape room payout rollout (SN94)

Escape receipts are off until an operator sets both a feed source and a
positive weight fraction. A fraction of 0 leaves the signed vector identical to
the machine-only path. This page is the enable sequence. It does not change
live config by itself.

The intended share on mainnet is 5 percent (`0.05` / `1/20`). Do not raise
that until a staged break on public testnet netuid 584 has been confirmed.

## Required environment

Edit `/etc/cathedral-validator/direct.env` (see
`deploy/validator-update/direct.env.example`). Both of the first two lines must
be set to turn the path on:

| Variable | Mainnet value | Notes |
|---|---|---|
| `CATHEDRAL_ESCAPE_RECEIPTS_SOURCE` | HTTPS URL of the control-plane receipt feed (no userinfo, query, or fragment) or an absolute path to a JSON file | File form is a JSON list, or `{"receipts": [...]}`. HTTPS is GET only, 10s timeout, no redirects, 4 MiB / 10_000 receipt caps. |
| `CATHEDRAL_ESCAPE_WEIGHT_FRACTION` | `0.05` | Must be in `[0, 1/2]`. `0` is off. Values at or above `0.51` refuse to start. |
| `CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS` | `604800` (7 days) or omit | Optional. Must be in `(0, 7776000]` (90 days). Measured from signed `planted_at`. |

The validator verifies every receipt against the pinned contest signer set
(`config/escape/contest-signers.json`, sha256 pin in
`cathedral_thin/independent_runtime/escape_receipts.py`). A receipt is accepted
only if it is signed by a key in that set that was valid at the signed
`planted_at` time and is not revoked. The legacy one-line public key file
(`config/escape/contest-signer.ed25519.pub`) still parses as a one-key set.
Each accepted receipt must name `claim.breaker_hotkey` (SS58). The breaker must
be registered on the subnet at the cycle's finalized anchor. Unregistered
hotkeys get nothing. This validator's own UID cannot win.

Restart after editing:

```bash
sudo systemctl restart cathedral-validator-direct
```

At start the service log should show
`{"escape_receipts": {"status": "ENABLED", "source": "...", "fraction": "1/20", "window_seconds": 604800}}`.
A mistyped fraction or URL prints `escape receipt source refused:` and the unit
retries. It does not silently run with the feature off.

## API / feed side (separate repo)

This validator does not publish the feed. The control plane must:

1. Require and sign `claim.breaker_hotkey` on every receipt. Receipts without
   that field are refused here.
2. Set `key_id` on every new receipt to the id of the key that produced `sig`
   (today `contest-2026-10`). `key_id` is a selector, not part of the signed
   canonical body, so existing receipts without it still verify against every
   non-revoked key that covers `planted_at`. An unknown `key_id` is refused.
3. Turn on the public read-only feed flag. While the flag is off the URL
   returns 404. A 404 is `SOURCE_UNAVAILABLE`: miners still get paid, breakers
   get nothing that cycle.
4. Serve uncompressed JSON at a plain `https://` path (no query string).
5. Publish one signed receipt per `(window_id, room_id)` for the reward window.

Until those are true, leave the fraction at 0.

## Testnet 584 staged break

Do this before any mainnet fraction change.

1. Run the validator in testnet rehearsal (`CATHEDRAL_TESTNET=1`,
   `--network test`, `--netuid 584`). Use a testnet copy of `direct.env` with
   the feed URL and `CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0.05`.
2. Confirm start-up `ENABLED` and that cycles print `escape_receipts`.
3. With the feed still 404, status must be `SOURCE_UNAVAILABLE` and the wire
   vector must match the machine-only vector (miners keep 100 percent).
4. Turn the feed flag on. Plant and break one room on the testnet contest.
   The breaker hotkey must be registered on netuid 584.
5. On the next cycle, `escape_receipts.status` must be `APPLIED`, `accepted`
   at least 1, and `units_by_uid` must name the breaker's UID. `refused`
   should not contain that breaker's hotkey.
6. Read the published weights. The breaker UID's share must be about 5 percent
   of 65535 (3276 or 3277 if they are the only break). Serving miners must
   keep the rest. Sum must be 65535.
7. Confirm a recycled UID (hotkey changed between anchor and sign) refuses the
   write rather than paying the new holder. The cycle event names
   `an escape receipt UID changed hotkey before direct signing`.

Do not continue to mainnet if step 5 or 6 fails, or if a 404 stops miner
weights.

## Mainnet switch (netuid 94)

Only after the testnet staged break is confirmed:

1. Keep the fraction at `0` until the mainnet feed flag is on and a cycle on
   the production validator shows `SOURCE_UNAVAILABLE` with `HTTP 404`
   gone (status `NO_BREAKS` or `APPLIED` with a real feed body).
2. Set `CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0.05` in
   `/etc/cathedral-validator/direct.env`. Do not change live chain config,
   wallets, or the contest key.
3. Restart `cathedral-validator-direct`.
4. Confirm start-up `ENABLED` with `fraction` `1/20`.

## Verify weights after the switch

1. `sudo journalctl -u cathedral-validator-direct.service -f`
   Each cycle JSON line includes `escape_receipts`:
   - `APPLIED`: breakers were blended. `accepted`, `units_by_uid`,
     `uid_hotkeys`, and `refused` are the audit.
   - `NO_BREAKS`: feed was readable but no in-window registered break. Miners
     keep 100 percent. The 5 percent is not burned.
   - `SOURCE_UNAVAILABLE`: feed 404, timeout, redirect, or malformed JSON.
     Miners keep 100 percent. `error` names the reason (`HTTP 404`,
     `cycle deadline`, `too large`, ...).
   - `SCORING_UNAVAILABLE`: a receipt scored then failed to blend. Miners keep
     100 percent. Treat this as a bug and roll back.
2. `wire_uids` / `wire_weights` on the same line must sum to 65535. With one
   breaker and `1/20`, that UID is 3276 or 3277.
3. On chain, read this validator's weight row on netuid 94 and check the
   breaker UID against the cycle event.

## One-step rollback

Set the fraction back to 0 and restart:

```bash
# in /etc/cathedral-validator/direct.env
CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0
sudo systemctl restart cathedral-validator-direct
```

Unsetting `CATHEDRAL_ESCAPE_RECEIPTS_SOURCE` is equivalent. The next cycle
writes the machine-only vector. No journal migration. Plans without escape
units keep the old identity.


## Contest signer key rotation

The validator does not trust a key file on the host. It trusts a key set
vendored in the release and pinned by sha256. Editing a file under `/etc` does
nothing. Rotation is a validator software update that changes the pinned set,
plus a matching change on the control plane that signs receipts.

The current key id is `contest-2026-10`. Its public key is
`config/escape/contest-signer.ed25519.pub`. The set is
`config/escape/contest-signers.json`. The pin is `PINNED_CONTEST_SIGNERS_SHA256`
in `escape_receipts.py`. The pin and the file must change together or the
validator refuses to import the module.

A receipt pays only if:

- it is signed by a public key in the pinned set
- that key is not revoked
- the signed `planted_at` time is inside the key's window (`not_before` through
  optional `not_after`, inclusive)

Receipts without `key_id` still work: the validator tries every non-revoked key
that covers `planted_at`. Receipts with an unknown `key_id` are refused.

### Add a new key

1. Generate a new Ed25519 key pair on the control plane. Do not commit the
   private key. Add only the public key to this repo.
2. Append a key object to `config/escape/contest-signers.json` with a new `id`,
   `pubkey_b64`, and `not_before` set to the unix time it may start signing.
   Leave `not_after` off. Do not set `revoked`. Keep the compact canonical JSON
   (sorted keys, no spaces) plus one trailing newline.
3. Recompute the file sha256 and update `PINNED_CONTEST_SIGNERS_SHA256` and
   `PINNED_CONTEST_SIGNERS_DOCUMENT` in `escape_receipts.py` so they match those
   bytes.
4. Ship a validator release. Operators update. Until they do, they still only
   trust the previous set.
5. On the control plane, start signing new receipts with the new key and set
   `key_id` to the new id. Keep the old key available for receipts whose
   `planted_at` is still in the old window.

### Overlap window

Set the new key's `not_before` before the old key's `not_after`. During the
overlap, receipts signed by either key are accepted if `planted_at` is in that
key's window. Choose an overlap at least as long as the reward window (7 days)
plus time for every validator to update.

### Retire the old key

After the overlap, and after the old key's last planted window plus the reward
window has passed:

1. Set the old key's `not_after` to the last time it was allowed to sign.
   Receipts planted at or before that time still pay for the rest of their
   reward window. Receipts planted after it are refused.
2. Update the pin and ship a release.
3. Stop signing with the old private key on the control plane. Destroy it.
4. A later release may drop the old key object once no in-window receipt still
   needs it.

### Emergency revoke

If the old private key leaks:

1. Set `"revoked": true` on that key. Do not wait for `not_after`.
2. Update the pin and ship an emergency validator release. Operators must
   update. A revoked key's receipts are refused from that point on, including
   receipts that were still inside the reward window.
3. Start signing only with a new, non-revoked key.
4. Treat every receipt from the leaked key as tainted. The validator cannot
   tell honest ones from forged ones.

### Rollback

Revert the validator to the previous release (the previous pinned set). The
control plane must sign with a key that release still trusts. Setting
`CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0` is the payout rollback: it does not change
the trusted keys, it only stops blending breakers.
