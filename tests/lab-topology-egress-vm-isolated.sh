#!/bin/sh
set -eu
if { [ "$#" -ne 1 ] && [ "$#" -ne 2 ]; } || [ "$(id -u)" -eq 0 ] || [ ! -f "$1" ]; then
    echo "Usage: unprivileged user: sh $0 VERIFIED_QCOW2 [router|router-fence|router-lan]" >&2
    exit 2
fi
mode=${2:-direct}
case "$mode" in
    direct|router|router-fence|router-lan) ;;
    *) echo "Invalid test scenario." >&2; exit 2 ;;
esac
image=$(realpath -- "$1")
exec unshare --user --map-root-user --mount --net -- \
    python3 tests/lab-topology-egress-vm-isolated.py "$image" "$mode"
