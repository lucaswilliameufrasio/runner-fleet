#!/bin/sh
# Creates and tests the lifecycle only in fresh user/mount/network namespaces.
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
unshare --user --map-root-user --mount --net -- /bin/sh -eu -s <<'TEST'
mount -t tmpfs -o size=2m tmpfs /run
mkdir -p /run/netns
ip netns add guest
ip netns add target
/usr/sbin/nft add table inet unrelated_fixture
python3 tests/lab-network-operations.py create
ip link set rfguest0 netns guest
ip link add rftarget0 type veth peer name target0
ip link set target0 netns target
ip link set lo up
ip link set rflabctl0 up
ip link set rftarget0 up
ip addr add 192.0.2.1/24 dev rflabctl0
ip addr add 198.51.100.1/24 dev rftarget0
ip netns exec guest ip link set lo up
ip netns exec guest ip link set rfguest0 up
ip netns exec guest ip addr add 192.0.2.2/24 dev rfguest0
ip netns exec guest ip route add default via 192.0.2.1
ip netns exec target ip link set lo up
ip netns exec target ip link set target0 up
ip netns exec target ip addr add 198.51.100.2/24 dev target0
ip netns exec target ip addr add 198.51.100.3/24 dev target0
ip netns exec target ip route add default via 198.51.100.1
/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1
if ip netns exec guest ping -4 192.0.2.1 -c 1 -W 1 >/dev/null 2>&1; then
    echo "Host unexpectedly reachable." >&2
    exit 1
fi
if ip netns exec guest ping -4 198.51.100.2 -c 1 -W 1 >/dev/null 2>&1; then
    echo "Unleased egress unexpectedly reachable." >&2
    exit 1
fi
echo "Guest isolated from host and target before lease."
python3 tests/lab-network-lease-fixture.py --lifecycle
if ip netns exec guest ping -4 198.51.100.2 -c 1 -W 1 >/dev/null 2>&1; then
    echo "Expired lease unexpectedly permits egress." >&2
    exit 1
fi
python3 tests/lab-network-operations.py remove
if ip link show dev rflabctl0 >/dev/null 2>&1; then
    echo "Owned host interface remains." >&2
    exit 1
fi
if ip netns exec guest ip link show dev rfguest0 >/dev/null 2>&1; then
    echo "Owned guest interface remains." >&2
    exit 1
fi
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
echo "Lifecycle removed both veth ends; unrelated table preserved."
TEST
