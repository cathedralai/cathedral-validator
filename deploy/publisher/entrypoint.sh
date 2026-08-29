#!/bin/sh
# Production uses the required Postgres store. The container starts as root
# only long enough to drop to the unprivileged runtime user and exec the CMD.
set -e

export HOME=/home/cathedral
exec setpriv --reuid=cathedral --regid=cathedral --init-groups "$@"
