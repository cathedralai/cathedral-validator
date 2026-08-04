# Self-composing publisher role (deploy/publisher)

These assets let **cathedral-validator** run the compose/publish role itself,
so the validator becomes the single self-composing service that both **publishes
the signed weight vector** and **validates + broadcasts** it. The compose/publish
Python is already 100% vendored in this repo (`scaffold.publisher.server:app`,
`scaffold.mechanism_router`, `scaffold.external_scores`, `scaffold.publisher`'s
`weights.py` — byte-identical to the hub's); only these launch assets were
missing.

At cutover these **REPLACE the hub-hosted publisher trio** that currently runs
the live loop (`cathedral-scorer-sn39`, `cathedral-publisher`,
`cathedral-weight-feed-publish`, all serving `scaffold.publisher.server:app`).
Once they run validator-sourced code, the cathedral hub is out of the live loop
and becomes archivable.

## Module path

Every role serves the same ASGI app:

```
uvicorn scaffold.publisher.server:app --host 127.0.0.1 --port <PORT> --workers <N> --no-access-log
```

A console-script convenience wrapper is also installed by `.[publisher]`:
`cathedral-publisher-serve` (calls `scaffold.publisher.server:_serve_cli`,
reading `PORT` / `WEB_CONCURRENCY` / `CATHEDRAL_PUBLISHER_HOST` from the env).

## Venv

The units run `/opt/cathedral-publisher/venv/bin/uvicorn`. Provision that venv
from THIS repository (validator-sourced), Python 3.12, with the pinned serving
lock:

```
python3.12 -m venv /opt/cathedral-publisher/venv
/opt/cathedral-publisher/venv/bin/pip install -r deploy/publisher/requirements.txt
/opt/cathedral-publisher/venv/bin/pip install --no-deps .   # installs scaffold + console scripts
```

`deploy/publisher/requirements.txt` is the reproducible serving lock (ported from
the hub's `deploy/requirements.txt`); it is kept in lockstep with the pinned
`[project.optional-dependencies].publisher` extra in `pyproject.toml`.

## The 3-role env matrix

Each unit reads a per-role `EnvironmentFile` under `/etc/cathedral-publisher/`.
Install each from its `*.env.example`, **mode 0600, owner `cathedral-publisher`**,
and **commit no secrets** (`CATHEDRAL_EVAL_SIGNING_KEY`, any `DATABASE_URL` /
bucket credentials are provisioned out of band).

| Role unit                          | Default port | Notes |
|------------------------------------|:------------:|-------|
| `cathedral-scorer-sn39.service`    | 8012         | `NETUID=39`, `CATHEDRAL_WEIGHT_POLICY_NETWORK=finney` |
| `cathedral-publisher.service`      | 8010         | Thin publisher — serves the signed vector the validator fetches from its **local** `[publisher] url` |
| `cathedral-weight-feed-publish.service` | 8011    | Weight-feed publish surface |

The consolidated validator's `config/validator-selfcompose-sn39.toml` points its
`[publisher] url` at `http://127.0.0.1:8010` (the `cathedral-publisher.service`
bind address).

## Install

```
install -m0644 deploy/publisher/cathedral-publisher.sysusers  /etc/sysusers.d/cathedral-publisher.conf
install -m0644 deploy/publisher/cathedral-publisher.tmpfiles  /etc/tmpfiles.d/cathedral-publisher.conf
systemd-sysusers && systemd-tmpfiles --create
install -m0644 deploy/publisher/*.service /etc/systemd/system/
# then install the three EnvironmentFiles 0600 under /etc/cathedral-publisher/
systemctl daemon-reload
```

The units carry `Conflicts=` + an `ExecStartPre` single-writer guard against
each other; run them on distinct ports as above.

## Allocation contract

v2 (90% TDX / 10% burn) is the byte-identical default — leave
`CATHEDRAL_ALLOCATION_CONTRACT` unset. v3 (70% TDX / 30% CyberGym / 0% burn) is
enabled only in the coordinated Phase 5 cutover and only after CyberGym is
confirmed healthy. See the cutover runbook and `../../config/`.

## Clean-journal startup (attestation-verified requires a CLEAN journal)

`init-clean-journal.sh` provisions the validator's runtime root and guarantees
the submission journal starts CLEAN (absent / `{}` / the 4-key identity doc). It
**refuses to run against an existing journal** — a previously-authority host is
migrated by *archiving* the old journal, never by hand-editing it:

```
mv /var/lib/cathedral-validator/thin-state.json \
   /var/lib/cathedral-validator/thin-state.authority.$(date +%s).bak
deploy/publisher/init-clean-journal.sh --mode absent
```
