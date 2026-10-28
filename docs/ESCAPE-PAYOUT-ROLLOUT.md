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
| `CATHEDRAL_ESCAPE_RECEIPTS_SOURCE` | HTTPS URL of the control-plane receipt feed (no userinfo, query, or fragment) or an absolute path to a JSON file | File form is a JSON list, or `{"receipts": [...]}`. HTTPS is GET only, 10s total wall-clock timeout (connect, reads, and parse), no redirects, 4 MiB / 10_000 receipt caps. |
| `CATHEDRAL_ESCAPE_WEIGHT_FRACTION` | `0.05` | Must be in `[0, 1/10]`. `0` is off. Values at or above `0.11` refuse to start. |
| `CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS` | `604800` (7 days) or omit | Optional. Must be in `(0, 7776000]` (90 days). Measured from signed `planted_at`. |

The validator verifies every receipt against the vendored contest public key
(`config/escape/contest-signer.ed25519.pub`). Any other key is refused. Each
accepted receipt must name `claim.breaker_hotkey` (SS58). The breaker must be
registered on the subnet at the cycle's finalized anchor. Unregistered hotkeys
get nothing. This validator's own UID cannot win.

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
2. Turn on the public read-only feed flag. While the flag is off the URL
   returns 404. A 404 is `SOURCE_UNAVAILABLE`: miners still get paid, breakers
   get nothing that cycle.
3. Serve uncompressed JSON at a plain `https://` path (no query string).
4. Publish one signed receipt per `(window_id, room_id)` for the reward window.

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
