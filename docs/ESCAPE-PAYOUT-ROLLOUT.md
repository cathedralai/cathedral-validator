# Escape room payout rollout (SN94)

**The escape lane is on by default** (AB#830). A validator with no escape
lines in `direct.env` reads the public receipt feed
`https://api.polaris.computer/v1/escape/receipts/published` and pays verified
breakers. Before this release only Cathedral's own validator (UID 0) scored
breaks, so consensus clipped a break to about zero; now every validator on the
default scores them. An operator can still opt out with
`CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0`. This page covers the defaults, opt-out,
verification and rollback.

Since the gated split of 12 Nov 2026 ([Gated compute](GATED_COMPUTE.md)) the
escape lane's share is fixed in the release at 10 percent of the vector. The
configured fraction is only the switch: any positive value turns the lane on
and breakers then share the fixed 10 percent, whatever the value says. While
the lane is off, or on with no verified break, or its feed is unreadable, that
10 percent is burned. It never goes to miners.

## Environment

Nothing to set: the defaults turn the lane on. Each line in
`/etc/cathedral-validator/direct.env` (see
`deploy/validator-update/direct.env.example`) overrides its default when it is
present, and is validated exactly as before:

| Variable | Default (unset) | Notes |
|---|---|---|
| `CATHEDRAL_ESCAPE_RECEIPTS_SOURCE` | `https://api.polaris.computer/v1/escape/receipts/published` | `off` or an empty value turns the lane off. Otherwise an HTTPS URL of the control-plane receipt feed (no userinfo, query, or fragment) or an absolute path to a JSON file | File form is a JSON list, or `{"receipts": [...]}`. HTTPS is GET only and paged: the validator adds `limit=200`, `since` (start of the reward window less 5 minutes) and, after page 1, `cursor`, and follows `next_cursor` until it is null. A body that is a list, or has no `next_cursor`, is the whole feed (a server that does not page). Each page: 10s wall-clock (connect, reads, and parse), 4 MiB cap; all pages: 30s, capped by the cycle time left. At most 25 pages (under the feed's 30 a minute limit); if page 25 has `next_cursor`, the read fails rather than scoring an incomplete feed. The 10_000-receipt cap keeps the oldest, as before paging. Any failed page fails the whole read. No redirects. A file is one document: 4 MiB / 10_000 receipt caps. |
| `CATHEDRAL_ESCAPE_WEIGHT_FRACTION` | `1/10` | Must be in `[0, 1/10]`. `0` (or an empty value) is off: the opt-out. Any positive value turns the lane on at the fixed 10 percent; an existing `0.05` keeps working. Values at or above `0.11` refuse to start. |
| `CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS` | `604800` (7 days) | Optional. Must be in `(0, 7776000]` (90 days). Measured from signed `planted_at`. |

The validator verifies every receipt against the pinned contest signer set
(`config/escape/contest-signers.json`, sha256 pin in
`cathedral_thin/independent_runtime/escape_receipts.py`). A receipt is accepted
only if it is signed by a key in that set that was valid at the signed
`planted_at` time and is not revoked. The legacy one-line public key file
(`config/escape/contest-signer.ed25519.pub`) still parses as a one-key set.
Each accepted receipt must name `claim.breaker_hotkey` (SS58). The breaker must
be registered on the subnet at the cycle's finalized anchor. Unregistered
hotkeys get nothing. This validator's own UID cannot win.

Off is decided first: with the fraction at `0` or the source `off`, the other
two lines are not validated, as before. With the lane on (including by
default), a mistyped source or window refuses to start, and the updater then
keeps the previous release. Fix or remove the line.

Restart after editing:

```bash
sudo systemctl restart cathedral-validator-direct
```

At start the service log should show
`{"escape_receipts": {"status": "ENABLED", "source": "...", "source_origin": "release_default", "fraction": "1/10", "window_seconds": 604800}}`.
`source_origin` is `operator` when `direct.env` sets the source.
`fraction` is the fixed share, not the configured value. An opted-out host
prints no `escape_receipts` start line, as before.

### Feed down

An unreadable feed never stops the write and never crashes the validator. The
cycle burns the escape share (no breaker UID in the vector), the compute lane
is unchanged, the cycle event says `SOURCE_UNAVAILABLE`, and one extra line is
printed:
`{"level": "WARN", "escape_receipts": {"status": "SOURCE_UNAVAILABLE", "error": "...", "warning": "..."}}`.
A scoring failure does the same with `SCORING_UNAVAILABLE`. The read keeps 40
seconds of the cycle for the writer: if less than that is left, it is skipped
(`cycle deadline`) rather than risk the weight set.
A mistyped fraction or URL prints `escape receipt source refused:` and the unit
retries. It does not silently run with the feature off.

## API / feed side (separate repo)

This validator does not publish the feed. The control plane must:

1. Require and sign `claim.breaker_hotkey` on every receipt. Receipts without
   that field are refused here.
2. Set `key_id` on every new receipt to the id of the key that produced `sig`
   (today `contest-2026-11b`). `key_id` is a selector, not part of the signed
   canonical body, so existing receipts without it still verify against every
   non-revoked key that covers `planted_at`. An unknown `key_id` is refused.
3. Turn on the public read-only feed flag. While the flag is off the URL
   returns 404. A 404 is `SOURCE_UNAVAILABLE`: the cycle still writes, approved
   miners keep the compute lane, and the escape share is burned that cycle.
4. Serve uncompressed JSON at a plain `https://` path. Configure the URL with no query string; the validator adds `limit`, `since` and `cursor` itself. Because `since` comes from the reward window, a window longer than the feed's 7-day default is now read in full.
5. Publish one signed receipt per `(window_id, room_id)` for the reward window.

The public feed has been live since the mainnet switch on Cathedral's own
validator; while it is down every validator burns the escape share.

## Testnet 584 staged break

Use this to rehearse a change to the receipt format or scoring. The default
feed names mainnet hotkeys, so on netuid 584 it scores `NO_BREAKS`; point a
testnet host at a testnet feed to rehearse a break.

1. Run the validator in testnet rehearsal (`CATHEDRAL_TESTNET=1`,
   `--network test`, `--netuid 584`). Use a testnet copy of `direct.env` with
   the feed URL and `CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0.1`.
2. Confirm start-up `ENABLED` and that cycles print `escape_receipts`.
3. With the feed still 404, status must be `SOURCE_UNAVAILABLE` and the wire
   vector must carry no breaker UID (the escape share is burned).
4. Turn the feed flag on. Plant and break one room on the testnet contest.
   The breaker hotkey must be registered on netuid 584.
5. On the next cycle, `escape_receipts.status` must be `APPLIED`, `accepted`
   at least 1, and `units_by_uid` must name the breaker's UID. `refused`
   should not contain that breaker's hotkey.
6. Read the published weights. The breaker UID's share must be 10 percent of
   65535, floored (6553 if they are the only break). Approved miners with a
   verified machine share another 6553, and the subnet owner UID holds the
   rest. Sum must be 65535.
7. Confirm a recycled UID (hotkey changed between anchor and sign) refuses the
   write rather than paying the new holder. The cycle event names
   `an escape receipt UID changed hotkey before direct signing`.

Do not ship the change if step 5 or 6 fails, or if a 404 stops miner
weights.

## Mainnet (netuid 94)

On by default from the release that carries AB#830; auto-update installs it
with no operator step. Confirm start-up `ENABLED` with `fraction` `1/10` and
`source_origin` `release_default` (or `operator` if `direct.env` sets the
source). Hosts that already set both lines, like Cathedral's UID 0, keep their
values.

## Verify weights after the switch

1. `sudo journalctl -u cathedral-validator-direct.service -f`
   Each cycle JSON line includes `escape_receipts`:
   - `APPLIED`: breakers were paid the escape share. `accepted`,
     `units_by_uid`, `uid_hotkeys`, and `refused` are the audit.
   - `NO_BREAKS`: feed was readable but no in-window registered break. The
     escape share is burned.
   - `SOURCE_UNAVAILABLE`: feed 404, timeout, redirect, or malformed JSON.
     The escape share is burned. `error` names the reason (`HTTP 404`,
     `cycle deadline`, `too large`, ...).
   - `SCORING_UNAVAILABLE`: a receipt scored then failed to apply. The escape
     share is burned. Treat this as a bug and roll back.
   In every case the compute lane is unchanged.
2. `wire_uids` / `wire_weights` on the same line must sum to 65535. With one
   breaker that UID is 6553.
3. On chain, read this validator's weight row on netuid 94 and check the
   breaker UID against the cycle event.

## Opt out, or one-step rollback

Set the fraction to 0 and restart:

```bash
# in /etc/cathedral-validator/direct.env
CATHEDRAL_ESCAPE_WEIGHT_FRACTION=0
sudo systemctl restart cathedral-validator-direct
```

`CATHEDRAL_ESCAPE_RECEIPTS_SOURCE=off` is equivalent. Unsetting a line no
longer turns the lane off: it brings back the default. The next cycle
pays no breaker and burns the escape share. No journal migration.


## Contest signer key rotation

The validator does not trust a key file on the host. It trusts a key set
vendored in the release and pinned by sha256. Editing a file under `/etc` does
nothing. Rotation is a validator software update that changes the pinned set,
plus a matching change on the control plane that signs receipts.

The current key id is `contest-2026-11b`. Its public key is
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
