# Private validator telemetry

The direct validator writes one sanitized snapshot only after a finalized weight submission. A separate timer sends the latest snapshot to Cathedral's private collector. Export failure never affects scoring or chain writes.

The exported snapshot contains the validator UID and hotkey, finalized block,
miner UID and hotkey, distinct verified compute count, TDX and SEV-SNP counts,
SAT units, validator verification-time summary, and finalized weight. It does
not claim customer request latency.

It never contains IP addresses, TLS identities, machine identifiers, quotes, certificates, credentials, request bodies, stack traces, or raw errors.

The validator signs each event with its own local sr25519 hotkey after the
weight result is finalized. The collector receives the signature and public
hotkey, never the wallet or private key. UID30 and every future independent
validator therefore keep separate chain keys. The ingest credential permits a
network request but does not establish event identity. The collector verifies
the hotkey signature and on-chain permit itself.

Telemetry is opt-in. Install the isolated exporter after the validator's
`cathedral-validator` operating-system user and executable already exist:

```bash
sudo install -o root -g root -m 0644 \
  deploy/validator-telemetry/cathedral-validator-telemetry.sysusers \
  /etc/sysusers.d/cathedral-validator-telemetry.conf
sudo systemd-sysusers \
  /etc/sysusers.d/cathedral-validator-telemetry.conf

sudo install -o root -g root -m 0644 \
  deploy/validator-telemetry/cathedral-validator-telemetry.tmpfiles \
  /etc/tmpfiles.d/cathedral-validator-telemetry.conf
sudo systemd-tmpfiles --create \
  /etc/tmpfiles.d/cathedral-validator-telemetry.conf

sudo install -o root -g root -m 0644 \
  deploy/validator-telemetry/cathedral-validator-telemetry.service \
  /etc/systemd/system/cathedral-validator-telemetry.service
sudo install -o root -g root -m 0644 \
  deploy/validator-telemetry/cathedral-validator-telemetry.timer \
  /etc/systemd/system/cathedral-validator-telemetry.timer
sudo install -d -o root -g cathedral-telemetry -m 0750 \
  /etc/cathedral-validator-telemetry
sudo install -o root -g cathedral-telemetry -m 0640 \
  deploy/validator-telemetry/telemetry-export.env.example \
  /etc/cathedral-validator-telemetry/export.env
```

The definitions create a separate `cathedral-telemetry` network identity and
one shared directory. Add these fixed arguments to the direct validator
service:

```text
--telemetry-spool /var/lib/cathedral-validator-telemetry/events.jsonl
--telemetry-reader-group cathedral-telemetry
```

Edit `/etc/cathedral-validator-telemetry/export.env` and set the exact private
collector URL. Install each issued token from a root-only staging path:

```bash
sudo install -o cathedral-telemetry -g cathedral-telemetry -m 0600 \
  /secure/staging/telemetry-ingest.token \
  /etc/cathedral-validator-telemetry/ingest.token
sudo install -o cathedral-telemetry -g cathedral-telemetry -m 0600 \
  /secure/staging/sites-authorization.token \
  /etc/cathedral-validator-telemetry/sites-authorization.token
```

The exporter reads the sanitized spool and those two token files. The two
tokens must be distinct. Its unit makes `/var/lib/cathedral-validator` and
`/etc/cathedral-validator` inaccessible, so it cannot read the wallet, hotkey,
writer journal, raw evidence, or validator configuration.

After restarting the validator with the two telemetry arguments, enable the
exporter:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cathedral-validator.service
sudo systemctl enable --now cathedral-validator-telemetry.timer
sudo systemctl start cathedral-validator-telemetry.service
sudo systemctl status cathedral-validator-telemetry.service --no-pager
```

Use the validator service name installed on your host if it differs from
`cathedral-validator.service`. Enable the timer only after the private
collector URL and both credentials exist. Repeated delivery is safe because
the collector deduplicates by event ID.
