# Provenance catch-up: re-anchoring a tip that aged out

The audit fails every tick with:

```
ProvenanceAuditError: recorded chain tip (epoch <N>) has aged out of the signed
index's recent window (oldest retained epoch <M>); the export chain back to the
tip can no longer be walked
```

This procedure is the only exit. It is a deliberate, evidence-forfeiting
operator action, which is why it is not automatic.

## What has actually happened

Each successful audit records where it got to:

- `provenance_last_source_epoch`
- `provenance_last_report_id`

both in the validator state file (`/var/lib/cathedral-validator/thin-state.json`
in the SN39 deployment).

When a newer report arrives that does not chain directly from the recorded one,
the audit walks the signed index's `recent` window to bridge the gap. The
window is bounded. If the recorded tip falls off the back of it, the bridge can
no longer prove continuity, so it fails closed.

**That failure is a deadlock, not a delay.** The tip only advances when an audit
succeeds, and the audit cannot succeed while the tip is behind the window. It
does not recover on its own, and the gap only widens. Nothing else in the system
notices, because in `provenance.mode = "shadow"` a failed audit records a bad
write rather than preventing one.

The state is also append-only in this direction by design: `_write_state`
rejects a tip that moves backwards, and `_assert_anchor_not_rewound` rejects a
rewound anchor. So there is no in-band way to move the tip to a reachable epoch.
Clearing the two keys is the only exit, and it must be done off-line.

## What it costs

Re-anchoring **forfeits proof of continuity across the gap**. Reports published
during the gap are never audited and never will be. That is unavoidable once the
tip is outside the retention window: the evidence needed to bridge it is gone.

So this is a real loss, not a formality. Record the epoch range being skipped.

## Procedure

The validator writes this state file while it runs. Editing it under a live
process risks losing a fence write, and the same file holds the weight rollback
fences. Stop first.

1. **Pick a window.** The validator stops writing weights for the duration.
   Not within 60 blocks of an epoch boundary.

2. **Record what is being skipped**, for the audit trail:

   ```bash
   sudo python3 -c "import json; d=json.load(open('/var/lib/cathedral-validator/thin-state.json')); print(d.get('provenance_last_source_epoch'), d.get('provenance_last_report_id'))"
   ```

3. **Stop the writer that is actually running.** Confirm first. The
   catch-up edits `thin-state.json`; doing that under a live process risks
   a fence write.

   ```bash
   systemctl is-active cathedral-validator-sn39.service \
     cathedral-validator-sn39-relay.service \
     cathedral-validator-passive.service
   sudo systemctl stop cathedral-validator-sn39.service \
     cathedral-validator-sn39-relay.service \
     cathedral-validator-passive.service
   ```

   On a Docker relay, stop the compose service instead of systemd.

4. **Back up, then clear both keys.** Clear both. Clearing only the epoch leaves
   `provenance_last_report_id` set, and the bridge still triggers on it:

   ```bash
   sudo cp -a /var/lib/cathedral-validator/thin-state.json \
              /var/lib/cathedral-validator/thin-state.json.pre-catchup-$(date -u +%Y%m%dT%H%M%SZ)
   sudo python3 - <<'PY'
   import json, pathlib
   p = pathlib.Path('/var/lib/cathedral-validator/thin-state.json')
   d = json.loads(p.read_text())
   for key in ('provenance_last_source_epoch', 'provenance_last_report_id'):
       d.pop(key, None)
   p.write_text(json.dumps(d, indent=2, sort_keys=True))
   PY
   ```

   Touch nothing else. The weight fences and submission journals in this file
   are what stop a double write; rewinding them is a far worse failure than the
   one being repaired.

5. **Start the same unit you stopped:**

   ```bash
   sudo systemctl start cathedral-validator-sn39.service
   # or cathedral-validator-sn39-relay.service
   # or cathedral-validator-passive.service on a host that still uses that name
   ```

6. **Verify it actually recovered.** A restart proves nothing on its own:

   ```bash
   sudo journalctl -u cathedral-validator-sn39.service -f | grep -i provenance
   ```

   Expect `PROVENANCE_AUDIT_PASS` within a couple of ticks, and confirm the tip
   is advancing rather than merely being set once:

   ```bash
   sudo python3 -c "import json; print(json.load(open('/var/lib/cathedral-validator/thin-state.json')).get('provenance_last_source_epoch'))"
   ```

   Run it again a few ticks later. **If the number does not change, the
   re-anchor did not take** and the audit is failing for a different reason.
   This is the step that was skipped on 2026-08-14: the anchor was cleared
   during an incident, appeared to recover, and had silently aged out again by
   the next day because nobody confirmed it was advancing.

## Do not

- Do not restore this file from an old snapshot to "fix" the tip. It rewinds the
  weight fences with it, which is how a double write happens.
- Do not clear the keys with the validator running.
- Do not treat a single `PROVENANCE_AUDIT_PASS` as success. Confirm advancement.

## The gap this procedure does not close

An audit that has been dead for a day should not be discoverable only by reading
tick output. Shadow mode is the right posture while the controlled evidence tree
is not externally reachable, but "the audit is failing" needs to reach the
allowlisted public status projection so it is visible without an operator
looking for it. Tracked in #125.
