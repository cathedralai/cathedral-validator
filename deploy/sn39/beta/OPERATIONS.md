# SN39 beta validator — operations

The sole SN39 mainnet weight writer, running full-provenance authority with
the launch ceremony waived. Host: `polaris-tdx-7e93d5de` (project
`polaris-tdx-attest`, zone `us-central1-b`).

## What it does, in one paragraph

Every 25 minutes it independently recomputes the reward allocation from raw
Intel TDX evidence (never trusting the signed feed's numbers), proves every
paid hotkey was raw-replayed and everything unreplayed carries exactly zero,
proves the target UIDs cannot be reassigned mid-transaction, and writes the
weights on chain. The signed feed is comparison input only. If the audit
cannot reach the configured assurance, it writes nothing and says why.

## Watch it

- `sn39` on the workstation — validator + evidence in one stream.
- On host: `journalctl -u cathedral-validator-sn39-beta.service -f -o cat`
- Raw journal (machine record): `/var/log/cathedral-validator/validator-events.jsonl` (0600)
- Sanitized projection: `/var/log/cathedral-validator/validator-status.jsonl` (0640)

## Normal lines that are not problems

- `✗ waiting out the chain's write cooldown` — the chain refuses writes more
  than once per ~20 min. The validator is pacing itself to the chain's rule.
- `✗ the chain moved while preparing; rebuilding from a fresh head` — the
  pre-sign head-equality check lost a race; it retries within the tick.
- `⚠ outcome unproven` then a restart then `⚠ recovered a pending attempt` —
  the RPC could not prove a receipt in time; the validator refuses to assume,
  exits, and re-proves the exact signed transaction on restart. The write
  always either landed once or not at all; never twice.

## Update / rollback

```
# on the workstation
git -C ~/Documents/PROJECTS/cathedral-validator bundle create /tmp/rel-<sha>.bundle HEAD
gcloud compute scp /tmp/rel-<sha>.bundle polaris-tdx-7e93d5de:/tmp/ --project polaris-tdx-attest --zone us-central1-b --tunnel-through-iap
# on the host
sudo /opt/cathedral-sn39/releases/current/deploy/sn39/beta/install.sh /tmp/rel-<sha>.bundle <sha>
# rollback = same command with the previous sha
```

## Mode and levers (config: /etc/cathedral-validator/validator-mainnet-sn39.toml)

| Key | Live value | Meaning |
|---|---|---|
| `mode` | `authority` (full) | independent recomputation submits; `shadow` (thin) follows the signed feed |
| `min_assurance` | `rewarded_set_proven` | `full_over_epoch` restores never-submits-on-a-populated-subnet |
| `max_anchor_lag_blocks` | 600 | staleness ceiling on the producer-chosen audit anchor |
| `max_submissions` | 0 | no lifetime ceiling; the chain rate limit, attempt journal and single-writer guard are the fences |

## The waiver, exactly

Waived: launch canary, signed write authorization, account-nonce window.
Enforced: signature, freshness, policy-version fence, contract, burn
destination and floor, UID replacement safety, single writer.
Caveat: fences compare against `/var/lib/cathedral-validator/thin-state.json`;
restoring that file from a snapshot rewinds them. Do not restore it; if a
restore is ever unavoidable, do not let the validator broadcast until the
feed's policy_version has advanced past the snapshot's.

## Launch-scoped, deliberately parked

- Public status publisher (`cathedral-sn39-public-status.*`): disabled while
  its manifest re-seal is pending; re-enable with
  `systemctl enable --now cathedral-sn39-public-status.timer` after re-sealing.
- Waiver exit: the reconcile/launch tooling still checks superseded era-4
  rules; rework it when the ceremony returns.
- Account-nonce window: returns with the signed write authorization.
- Miner incentive on chain stays 0 until other validators stop burning; that
  is the launch lever, not a defect.
