#!/bin/sh
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
exec unshare --user --map-root-user --mount --net -- \
    python3 tests/lab-dns-tcp-egress-isolated.py
