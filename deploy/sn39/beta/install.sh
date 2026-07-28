#!/usr/bin/env bash
# Install or update the SN39 beta validator from a git bundle, atomically.
#
#   sudo ./install.sh /tmp/rel-<sha>.bundle <sha>
#
# The unit always runs /opt/cathedral-sn39/releases/current; this script
# checks the release out at its content-addressed path, flips the `current`
# symlink, and restarts. Rollback is the same command with the previous sha.
# Nothing here deletes or overwrites an existing release tree.
set -euo pipefail

BUNDLE=${1:?usage: install.sh <bundle> <sha>}
SHA=${2:?usage: install.sh <bundle> <sha>}
RELEASES=/opt/cathedral-sn39/releases
VENVS=/opt/cathedral-sn39/venvs
UNIT=cathedral-validator-sn39-beta.service
HERE=$(cd "$(dirname "$0")" && pwd)

REL="$RELEASES/$SHA"
install -d -m 0755 "$REL"
git -C "$REL" init -q 2>/dev/null || true
git -C "$REL" fetch -q "$BUNDLE" HEAD
git -C "$REL" checkout -q -f FETCH_HEAD
test "$(git -C "$REL" rev-parse HEAD)" = "$SHA" || {
  echo "bundle HEAD does not match the requested sha" >&2
  exit 1
}
chown -R root:root "$REL"
chmod -R a+rX "$REL"

# The hash-locked venv changes rarely and is installed separately; `current`
# names whichever one the operator last blessed.
test -x "$VENVS/current/bin/python" || {
  echo "no blessed venv at $VENVS/current; symlink one first" >&2
  exit 1
}

install -D -m 0644 "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
ln -sfn "$REL" "$RELEASES/current"
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1 || true
systemctl restart "$UNIT"
sleep 20
systemctl is-active --quiet "$UNIT" && echo "ACTIVE at $SHA" || {
  echo "unit failed to start; current still points at $SHA (roll back by" \
    "re-running with the previous sha)" >&2
  journalctl -u "$UNIT" --no-pager -o cat -n 20 >&2
  exit 1
}
