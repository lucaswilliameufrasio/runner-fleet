#!/bin/sh
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
unshare --user --map-root-user --mount --net -- /bin/sh -eu -s <<'TEST'
mount -t tmpfs -o size=2m tmpfs /run
ops=tests/lab-network-operations.py
/usr/sbin/nft add table inet unrelated_fixture
ip link add name rflabctl0 type dummy
if python3 "$ops" create; then
    echo "Interface collision unexpectedly accepted." >&2
    exit 1
fi
ip link show dev rflabctl0 >/dev/null
ip link delete dev rflabctl0
ip link add name rfguest0 type dummy
if python3 "$ops" create; then
    echo "Peer collision unexpectedly accepted." >&2
    exit 1
fi
ip link show dev rfguest0 >/dev/null
python3 "$ops" remove
ip link show dev rfguest0 >/dev/null
ip link delete dev rfguest0
/usr/sbin/nft add table inet runner_fleet_lab_ops
if python3 "$ops" create; then
    echo "Table collision unexpectedly accepted." >&2
    exit 1
fi
/usr/sbin/nft list table inet runner_fleet_lab_ops >/dev/null
/usr/sbin/nft delete table inet runner_fleet_lab_ops
echo "Interface and table collisions preserved."
if python3 "$ops" create --inject-failure; then
    echo "Injected partial failure unexpectedly succeeded." >&2
    exit 1
fi
/usr/sbin/nft list table inet runner_fleet_lab_ops >/dev/null
python3 "$ops" remove
echo "Closed partial state recovered."
python3 "$ops" create
ip link set rflabctl0 up
/usr/sbin/nft 'add element inet runner_fleet_lab_ops permits { 192.0.2.2 timeout 3s }'
/usr/sbin/nft add rule inet runner_fleet_lab_ops forward_guard counter
if python3 "$ops" remove; then
    echo "Changed policy unexpectedly removed." >&2
    exit 1
fi
ip -brief link show dev rflabctl0 | grep 'DOWN' >/dev/null
/usr/sbin/nft list table inet runner_fleet_lab_ops >/dev/null
echo "Changed policy retained and owned interface isolated."
# Remove the tampered rule in the disposable namespace only; then normal
# ownership checks must match the original policy before cleanup.
handle=$(/usr/sbin/nft -a list chain inet runner_fleet_lab_ops forward_guard | sed -n 's/.*counter packets .* handle \([0-9][0-9]*\)$/\1/p' | tail -1)
test -n "$handle"
/usr/sbin/nft delete rule inet runner_fleet_lab_ops forward_guard handle "$handle"
python3 "$ops" remove
python3 "$ops" create
ip link set dev rflabctl0 alias unknown-owner
if python3 "$ops" remove; then
    echo "Changed interface identity unexpectedly removed." >&2
    exit 1
fi
ip link show dev rflabctl0 >/dev/null
/usr/sbin/nft list table inet runner_fleet_lab_ops >/dev/null
ip link set dev rflabctl0 alias runner-fleet-namespace-experiment
python3 "$ops" remove
echo "Changed interface identity refused; no foreign resource removed."
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
if ip link show dev rflabctl0 >/dev/null 2>&1; then
    echo "Owned interface was not removed." >&2
    exit 1
fi
echo "Owned resources removed; unrelated table preserved."
TEST
