# Standing reference-miner loop (launch gate 1)

The honest-path canary for [#108](https://github.com/cathedralai/cathedral-validator/issues/108).
A reference CyberGym miner mines every epoch against the live scoring path; each
epoch is asserted, journalled as one line, and a red state fails a systemd unit
where an operator sees it. Green/red here is the launch readiness signal, and
after launch it is the regression tripwire.

Deployed on `cathedral-catminer-cpu-20260723` (GCP `polaris-tdx-attest`,
`us-central1-a`). Tailscale peers are offline; reach it with
`gcloud compute ssh --tunnel-through-iap`.

## Pieces

| File | Role |
|---|---|
| `cathedral-catminer-reference.service` | the standing miner: one dispatched batch per epoch, attestation client active |
| `cathedral-catminer-startup-record` | writes `MINER_STARTUP` so the alert's grace window is dated from a real restart |
| `cathedral-catminer-assert` | asks the oracle what the miner earned, decides GREEN/RED, appends one `EPOCH_STATUS` |
| `cathedral-catminer-alert-check` | the alert of last resort: non-zero exit is the notification |
| `*.timer` | assert once per epoch, alert every 10 minutes |
| `test-catminer-alert.sh` | 23 cases over both scripts, both directions |

## The journal

Append-only JSONL at `CATMINER_JOURNAL`, bounded to `CATMINER_JOURNAL_MAX_LINES`
(default 20000) with one rotated generation kept beside it. The alert reads
`.1` as well, because straight after a truncation the live file is empty and
reading only it would report a healthy loop as blind.

One line per epoch, carrying exactly what the issue asks for: earned, gates
passed, receipt verified, lane composition.

```json
{"ts":"2026-08-06T21:05:34.000Z","event":"EPOCH_STATUS","verdict":"GREEN","epoch":41,
 "miner":"5RefMiner","earned":3.5,"receipt_verified":true,
 "gates":{"attestation":"ok","contributing":"true","verified":"true"},
 "lane":{"burned":0.0,"compute":0.7,"cybergym":0.3}}
```

## The oracle

`CATMINER_ORACLE_CMD` must print one JSON object with `earned`, `gates`,
`receipt_verified`, and optionally `epoch` and `lane`. It is a command rather
than a baked-in HTTP call because the credited score lives in the validator's
own composition path, and #108's non-goal is explicit: this rig is not a second
validator implementation, it consumes the real one.

The intended implementation reshapes
`mechanism_cybergym_adapter.cybergym_score_snapshot(store, epoch, now)` —
its `(vec, meta, info)` already carries the credited score, the gate reasons
(`info["attestation"]`, `info["verified"]`, `info["contributing"]`) and the lane
composition. Run it where the publisher store is.

**An unset or failing oracle is RED, never green.** A canary that reports
healthy when it cannot see the thing it watches is worse than no canary.

## GREEN requires all of

- the oracle answered and its answer parsed
- credited score **> 0** (an `earned == 0` epoch is the regression this gate exists to catch)
- every gate in `CATMINER_EXPECTED_GATES` present **and** equal to its expected verdict
- the representative attestation receipt verified

A gate that simply stopped being reported is RED, not a pass: silent removal is
how a gate stops protecting anything.

## The alert

Modelled on `deploy/sn39/cathedral-mismatch-check`, including the reason its
rules 1-3 exist: rules 4 and 5 there were green for a validator that no longer
existed, because both greps returned zero matches for a journal that was gone,
and zero matches read as "nothing wrong". Six rules, any one fires:

1. journal missing, not a regular file, unreadable, empty with no rotated generation, or holding no parseable record
2. the miner unit is not active (the direct detector for "killed mid-epoch")
3. newest record older than 3 epoch intervals
4. no `EPOCH_STATUS` in 4 epoch intervals, grace dated from the **first** startup since the last completed epoch so a crash loop cannot renew its own grace
5. any RED epoch in the last 30 minutes
6. two consecutive RED epochs in 90 minutes with no GREEN since

Rule 2 is checked before the journal rules because a killed miner is the failure
this gate must catch inside the epoch, and the journal rules cannot see it until
a window expires.

## Configuration

`/etc/cathedral/catminer-reference.env`:

```
CATMINER_JOURNAL=/var/log/cathedral-catminer/catminer-events.jsonl
CATMINER_JOURNAL_MAX_LINES=20000
CATMINER_EPOCH_SECS=1500
CATMINER_UNIT=cathedral-catminer-reference.service
CATMINER_MINER_HOTKEY=<registered SN39 hotkey>
CATMINER_EXPECTED_GATES=attestation=ok,verified=true,contributing=true
CATMINER_DISPATCH_URL=<CyberGym producer base URL>
CATMINER_ORACLE_CMD=<command printing one JSON object>
```

## Current state, and what blocks green

Installed on the box, timers **disabled**. Not an oversight: no CyberGym
producer is deployed anywhere, so `cybergym_score_reports` has never received a
row, there is no dispatch URL for the agent, and there is no credited score to
read. The loop is known-red for a reason already tracked on #108, and enabling a
permanently firing alert is how operators learn to ignore alerts.

`cathedral-catminer-reference.service` carries a clearly labelled
`99-standin.conf` drop-in that holds the unit up without mining, so the alerting
wiring could be installed and proven now. **Delete that drop-in** when the
producer exists.

To finish the gate: deploy the CyberGym producer, set `CATMINER_DISPATCH_URL`
and `CATMINER_ORACLE_CMD`, register a miner hotkey, install a container runtime
and a hosted model endpoint on the box, remove the drop-in, then
`systemctl enable --now cathedral-catminer-assert.timer cathedral-catminer-alert.timer`.

## Tests

```bash
cd deploy/catminer && ./test-catminer-alert.sh
```

23 cases, and both directions are pinned: an alert that never clears is as
useless as one that never fires. Needs GNU `date -d`, so run it on the Linux
host rather than macOS.

The red path from the issue's acceptance list, run on the box:

```
1. miner up, one scoring epoch     GREEN: epoch 41 earned 3.5, receipt verified
2. miner ACTIVE                    alert exit 0, silent
3. SIGKILL the miner mid-epoch     unit inactive
4. SAME journal, SAME green epoch  alert FIRED: "miner unit is 'inactive', not active"
5. restart the miner               alert exit 0, cleared
```

Step 4 changes nothing but the miner's liveness, which is what makes it a proof
of rule 2 rather than a coincidence, and step 5 proves the alert can clear.
