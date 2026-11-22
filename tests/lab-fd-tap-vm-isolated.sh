#!/bin/sh
set -eu
if [ "$#" -ne 2 ] || [ "$(id -u)" -eq 0 ] || [ ! -f "$1" ]; then
    echo "Usage: unprivileged user: sh $0 VERIFIED_QCOW2 guard-loss|owner-death" >&2
    exit 2
fi
case "$2" in
    guard-loss|owner-death) ;;
    *) echo "Invalid fixed test scenario." >&2; exit 2 ;;
esac
image=$(realpath -- "$1")
exec unshare --user --map-root-user --mount --net -- \
    python3 tests/lab-fd-tap-vm-isolated.py "$image" "$2"
