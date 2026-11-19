# Cathedral Validator

The public installation and operating guide is on the [repository home page](README.md).

## Use your own subtensor node

By default the validator connects to the public Finney entrypoint. If you run
many validators from one IP and hit its rate limits, point it at your own
subtensor node instead. Only the connection moves: the validator still checks
that the node serves Finney (the pinned genesis hash) at start and before any
recovery, and refuses any other chain. Weights are signed for Finney's genesis,
so they can never land on another chain.

This needs a validator release that has the setting (AB#820). An older
release ignores it and keeps using the public entrypoint; the `"chain"` log
line below is how you know yours has it.

Settings, highest priority first:

| Setting | Example |
|---|---|
| `--subtensor.chain_endpoint` | `--subtensor.chain_endpoint ws://127.0.0.1:9944` |
| `SUBTENSOR_CHAIN_ENDPOINT` | `SUBTENSOR_CHAIN_ENDPOINT=ws://127.0.0.1:9944` |
| `CATHEDRAL_CHAIN_ENDPOINT` | older name, still read |

`--subtensor.network` (or `--network`, or `SUBTENSOR_NETWORK`) names the chain
and stays `finney`. A `ws://` or `wss://` URL there is taken as the endpoint;
any other value than `finney` refuses to start. Use `ws://` for a node on this
host, a private or Tailscale IP address, or a Docker service name, and `wss://`
for anything else.

### systemd host (the README install)

1. Put this one line in `/etc/cathedral-validator/direct-subtensor.env`:

```bash
SUBTENSOR_CHAIN_ENDPOINT=ws://127.0.0.1:9944
```

2. Run this once. It writes the file above, tells the unit to read it, and
   restarts the validator:

```bash
echo 'SUBTENSOR_CHAIN_ENDPOINT=ws://127.0.0.1:9944' | sudo install -o root -g root -m 0600 /dev/stdin /etc/cathedral-validator/direct-subtensor.env && sudo install -d -o root -g root -m 0755 /etc/systemd/system/cathedral-validator-direct.service.d && printf '[Service]\nEnvironmentFile=-/etc/cathedral-validator/direct-subtensor.env\n' | sudo tee /etc/systemd/system/cathedral-validator-direct.service.d/subtensor.conf >/dev/null && sudo systemctl daemon-reload && sudo systemctl restart cathedral-validator-direct.service
```

Updates keep the setting: no release or setup rerun touches
`direct-subtensor.env` or the drop-in. Hosts installed from a later bootstrap
already read the file, so for them step 1 and a restart are enough; the
drop-in is then redundant and harmless.

3. Check the log:

```bash
sudo journalctl -u cathedral-validator-direct.service | grep '"chain"'
```

A good start prints one line with the Finney genesis:
`{"chain": {"endpoint": "ws://127.0.0.1:9944", "endpoint_source": "SUBTENSOR_CHAIN_ENDPOINT", "genesis": "0x2f0555cc...", "network": "finney"}}`.
No `"chain"` line means the setting is not in effect: the host still runs an
older release, or the drop-in is missing.
Only scheme, host and port are logged, never a path or query (where a
provider key may sit).

A node on another chain (testnet, a local dev chain) stops the start with
`chain endpoint ws://127.0.0.1:9944 refused: observed genesis 0x... is not the pinned Finney genesis`,
before anything is signed. A node that is down stops it with `could not connect`, and one that answers
but cannot serve block 0 with `could not read genesis hash`. systemd retries every 15 seconds; fix the node
or remove the line and restart.

To go back to the public entrypoint, delete the line (or the file) and run
`sudo systemctl restart cathedral-validator-direct.service`.

`record-failed-write` runs outside the unit, so it does not read this file.
To use your node there too, add `--subtensor.chain_endpoint=ws://127.0.0.1:9944`
to that command. Its `--archive-endpoint` still wins when given.

### Docker

Add one line to the `docker run` command in the
[operator guide](docs/OPERATOR_GUIDE.md#docker):

```bash
  -e SUBTENSOR_CHAIN_ENDPOINT=ws://127.0.0.1:9944 \
```

Inside a container `127.0.0.1` is the container itself: run it with
`--network host`, or use `ws://host.docker.internal:9944` (add
`--add-host=host.docker.internal:host-gateway` on Linux), the node's private
address, or its Docker service name (`ws://subtensor:9944`).

### Your node

Run a Finney node and keep it synced. A lite (pruning) node keeps state as
long as the public entrypoint does, so recovery behaves the same as today;
`record-failed-write` may need `--archive-endpoint` for older history.
