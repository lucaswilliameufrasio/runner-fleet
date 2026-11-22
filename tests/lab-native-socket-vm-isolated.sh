#!/bin/sh
set -eu
if { [ "$#" -ne 1 ] && [ "$#" -ne 2 ]; } || [ "$(id -u)" -eq 0 ] || [ ! -f "$1" ]; then
    echo "Usage: unprivileged user: sh $0 VERIFIED_QCOW2 [guard-loss]" >&2
    exit 2
fi
mode=${2:-normal}
case "$mode" in
    normal|guard-loss) ;;
    *) echo "Invalid test scenario." >&2; exit 2 ;;
esac
image=$(realpath -- "$1")
exec unshare --user --map-root-user --mount --net -- \
    python3 tests/lab-native-socket-vm-isolated.py "$image" "$mode"
