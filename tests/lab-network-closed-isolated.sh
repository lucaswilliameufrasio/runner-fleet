#!/bin/sh
# The test changes network and firewall state only in fresh namespaces.
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
ip link add rflab0 type veth peer name guest0
ip link set guest0 netns guest
ip link add rftarget0 type veth peer name target0
ip link set target0 netns target
ip link set lo up
ip link set rflab0 up
ip link set rftarget0 up
ip addr add 192.0.2.1/24 dev rflab0
ip addr add 198.51.100.1/24 dev rftarget0
ip -6 addr add 2001:db8:1::1/64 dev rflab0 nodad
ip -6 addr add 2001:db8:2::1/64 dev rftarget0 nodad
ip netns exec guest ip link set lo up
ip netns exec guest ip link set guest0 up
ip netns exec guest ip addr add 192.0.2.2/24 dev guest0
ip netns exec guest ip addr add 192.0.2.3/24 dev guest0
ip netns exec guest ip -6 addr add 2001:db8:1::2/64 dev guest0 nodad
ip netns exec guest ip route add default via 192.0.2.1
ip netns exec guest ip -6 route add default via 2001:db8:1::1
ip netns exec target ip link set lo up
ip netns exec target ip link set target0 up
ip netns exec target ip addr add 198.51.100.2/24 dev target0
ip netns exec target ip addr add 198.51.100.3/24 dev target0
ip netns exec target ip -6 addr add 2001:db8:2::2/64 dev target0 nodad
ip netns exec target ip route add default via 198.51.100.1
ip netns exec target ip -6 route add default via 2001:db8:2::1
/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1
/usr/sbin/sysctl -q -w net.ipv6.conf.all.forwarding=1

probe() {
    ip netns exec guest ping "$@" -c 1 -W 1 >/dev/null 2>&1
}
expect_reachable() {
    if ! probe "$@"; then
        echo "Expected reachable: $*" >&2
        ip netns exec guest ping "$@" -c 1 -W 1 >&2 || true
        exit 1
    fi
}
expect_blocked() {
    if probe "$@"; then
        echo "Expected blocked: $*" >&2
        exit 1
    fi
}
check_reachable() {
    expect_reachable -4 192.0.2.1
    expect_reachable -4 198.51.100.2
    expect_reachable -6 2001:db8:1::1
    expect_reachable -6 2001:db8:2::2
}
check_blocked() {
    expect_blocked -4 192.0.2.1
    expect_blocked -4 198.51.100.2
    expect_blocked -6 2001:db8:1::1
    expect_blocked -6 2001:db8:2::2
}

/usr/sbin/nft add table inet unrelated_fixture
ip netns exec target ping -6 2001:db8:2::1 -c 1 -W 2 >/dev/null
check_reachable
echo "Baseline: host and forwarded IPv4/IPv6 targets reachable."
/usr/sbin/nft -f scripts/lab-network-closed.nft
check_blocked
echo "Closed policy: host and forwarded IPv4/IPv6 targets blocked."
# A transaction containing an invalid operation must not partially flush the
# closed rule. The failure is deliberately confined to this network namespace.
if printf '%s\n' \
    'flush chain inet runner_fleet_lab_closed forward_guard' \
    'add rule inet runner_fleet_lab_closed missing_chain counter drop' \
    | /usr/sbin/nft -f - >/dev/null 2>&1; then
    echo "Invalid transaction unexpectedly succeeded." >&2
    exit 1
fi
check_blocked
echo "Invalid opening transaction: closed policy preserved."
/usr/sbin/nft -f scripts/lab-network-synthetic-egress.nft
expect_reachable -4 198.51.100.2
expect_blocked -4 192.0.2.1
expect_blocked -4 198.51.100.3
expect_blocked -4 -I 192.0.2.3 198.51.100.2
expect_blocked -6 2001:db8:1::1
expect_blocked -6 2001:db8:2::2
echo "Synthetic egress: approved IPv4 target reachable; alternate source and target blocked."
/usr/sbin/nft list chain inet runner_fleet_lab_closed postrouting
/usr/sbin/nft -f scripts/lab-network-lease-guard.nft
expect_blocked -4 198.51.100.2
if /usr/sbin/nft -f scripts/lab-network-lease-guard.nft >/dev/null 2>&1; then
    echo "Existing lease guard unexpectedly adopted." >&2
    exit 1
fi
python3 tests/lab-network-lease-fixture.py
expect_blocked -4 198.51.100.2
ip link set rflab0 down
/usr/sbin/nft -f scripts/lab-network-synthetic-close.nft
/usr/sbin/nft delete table inet runner_fleet_lab_lease
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
ip link set rflab0 up
ip -6 addr replace 2001:db8:1::1/64 dev rflab0 nodad
/usr/sbin/nft -f scripts/lab-network-synthetic-egress.nft
expect_reachable -4 198.51.100.2
echo "Lease guard removed in isolated namespace with interface down; unrelated table preserved."
python3 tests/lab-network-supervision-fixture.py
ip link set rflab0 up
ip -6 addr replace 2001:db8:1::1/64 dev rflab0 nodad
/usr/sbin/nft -f scripts/lab-network-synthetic-close.nft
check_blocked
echo "Explicit close: host and forwarded IPv4/IPv6 targets blocked again."
if /usr/sbin/nft -f scripts/lab-network-closed.nft >/dev/null 2>&1; then
    echo "Existing table unexpectedly adopted." >&2
    exit 1
fi
check_blocked
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
echo "Collision rejected; unrelated table preserved."
/usr/sbin/nft delete table inet runner_fleet_lab_closed
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
check_reachable
echo "Isolated cleanup removed only the test table; connectivity restored."
TEST
