#!/bin/sh
# No host network changes: all devices and firewall rules live in new namespaces.
set -eu
if [ "$#" -ne 1 ] || [ "$(id -u)" -eq 0 ] || [ ! -f "$1" ]; then
    echo "Usage: unprivileged user: sh $0 VERIFIED_QCOW2" >&2
    exit 2
fi
image=$(realpath -- "$1")
exec unshare --user --map-root-user --mount --net -- \
    python3 tests/lab-vm-network-isolated.py "$image"
