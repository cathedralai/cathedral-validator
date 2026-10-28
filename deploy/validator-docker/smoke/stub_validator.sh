#!/bin/sh
# Smoke-only validator child. Never talks to chain or a wallet.
set -eu

marker="${HOME:-/var/lib/cathedral-validator}/smoke-validator.txt"
mkdir -p "$(dirname "$marker")"
printf 'CATHEDRAL_VALIDATOR_SMOKE_EXEC uid=%s\n' "$(id -u)"
printf 'uid=%s\n' "$(id -u)" >"$marker"

code="${CATHEDRAL_VALIDATOR_SMOKE_EXIT:-0}"
if [ "$code" != "0" ]; then
  exit "$code"
fi

trap 'exit 0' TERM INT
while true; do
  sleep 1
done
