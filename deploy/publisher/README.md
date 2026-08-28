# SN39 origin publisher (deploy/publisher)

There is one supported origin service:
`cathedral-scorer-sn39.service`. It composes and signs the SN39 vector through
`scaffold.publisher.server:app`. The recurring validator remains a separate
process. It fetches the public HTTPS feed through
`config/validator-thin-sn39-relay.toml`.

The old `cathedral-publisher.service` and
`cathedral-weight-feed-publish.service` names are not alternate roles or
fallback modes. Their deployment assets were removed. The supported unit still
conflicts with either legacy unit if one remains installed on an older host, so
two origin processes cannot share the database or signing identity.

## Module path

The service runs the one ASGI app on loopback:

```
uvicorn scaffold.publisher.server:app --host 127.0.0.1 --port 8012 --workers 1 --no-access-log
```

A console-script convenience wrapper is also installed by `.[publisher]`.
`cathedral-publisher-serve` calls `scaffold.publisher.server:_serve_cli` and
reads `PORT` and `CATHEDRAL_PUBLISHER_HOST` from the environment. Every shipped
entrypoint fixes the worker count at one. SQLite does not provide a
cross-process singleton lock for the in-memory signed-vector cache, so a
multi-worker origin is unsupported.

## Venv

The unit runs `/opt/cathedral-publisher/venv/bin/uvicorn`. Provision that venv
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

## Configuration

The unit reads
`/etc/cathedral-publisher/cathedral-scorer-sn39.env`. Start from
`cathedral-scorer-sn39.env.example`. Install it with mode 0600 and owner
`cathedral-publisher`. Commit no signing key, database credential, or bucket
credential.

The loopback endpoint is not a supported validator source. The immutable SN39
runtime requires `https://api.cathedral.computer`.

## Retire legacy unit names

On an upgraded host, stop and disable both old unit names before installing the
canonical service. If either local unit file exists, move that exact file to the
recovery directory. Then mask both names so a reboot or manual start cannot
select a legacy origin:

```bash
sudo install -d -m0700 /etc/cathedral-publisher/retired-units
for unit in cathedral-publisher.service cathedral-weight-feed-publish.service; do
  unit_path="/etc/systemd/system/$unit"
  saved_path="/etc/cathedral-publisher/retired-units/$unit"
  if [ -L "$unit_path" ] && [ "$(readlink "$unit_path")" = /dev/null ]; then
    continue
  fi
  if systemctl cat "$unit" >/dev/null 2>&1; then
    sudo systemctl disable --now "$unit"
  fi
  if [ -e "$unit_path" ] || [ -L "$unit_path" ]; then
    if [ -e "$saved_path" ] || [ -L "$saved_path" ]; then
      echo "REFUSING: recovery copy already exists at $saved_path" >&2
      exit 1
    fi
    sudo mv -- "$unit_path" "$saved_path"
  fi
  sudo systemctl mask "$unit"
done
sudo systemctl daemon-reload
```

Do not proceed until both names are inactive and masked:

```bash
for unit in cathedral-publisher.service cathedral-weight-feed-publish.service; do
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  [ "$active" = inactive ] && [ "$enabled" = masked ] || exit 1
done
```

## Install

```
install -m0644 deploy/publisher/cathedral-publisher.sysusers  /etc/sysusers.d/cathedral-publisher.conf
install -m0644 deploy/publisher/cathedral-publisher.tmpfiles  /etc/tmpfiles.d/cathedral-publisher.conf
systemd-sysusers && systemd-tmpfiles --create
install -m0644 deploy/publisher/cathedral-scorer-sn39.service /etc/systemd/system/
install -d -m0750 -o root -g cathedral-publisher /etc/cathedral-publisher
install -m0600 -o cathedral-publisher -g cathedral-publisher \
  deploy/publisher/cathedral-scorer-sn39.env.example \
  /etc/cathedral-publisher/cathedral-scorer-sn39.env
# Replace every placeholder in the installed EnvironmentFile out of band.
systemctl daemon-reload
```

Do not start the unit until its signing identity, database, public-feed export,
and allocation contract have passed the cutover checks. After explicit cutover
approval, `systemctl enable --now cathedral-scorer-sn39.service` starts the one
origin process. The unit refuses to start while either legacy origin unit is
active.

## Allocation contract

v2 (90% TDX / 10% burn) is the byte-identical default — leave
`CATHEDRAL_ALLOCATION_CONTRACT` unset. v3 (70% TDX / 30% CyberGym / 0% burn) is
enabled only in the coordinated Phase 5 cutover and only after CyberGym is
confirmed healthy. See the cutover runbook and `../../config/`.

## Validator journal boundary

Publisher installation does not initialize, archive, or rewrite the validator
journal. Preserve every active and historical launch journal. Recovery is
read-only until the exact finalized attempt is proven.
