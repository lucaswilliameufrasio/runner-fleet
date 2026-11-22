#!/bin/sh
set -eu
if [ "$(id -u)" -eq 0 ]; then
    echo "Usage: unprivileged user: sh $0" >&2
    exit 2
fi
exec unshare --user --map-root-user --mount --net --fork -- \
    python3 tests/lab-public-egress-vm-isolated.py --cleanup
