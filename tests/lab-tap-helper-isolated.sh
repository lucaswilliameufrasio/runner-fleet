#!/bin/sh
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
unshare --user --map-root-user --mount --net -- /bin/sh -eu -s <<'TEST'
mount -t tmpfs -o size=2m tmpfs /run
mkdir -p /run/netns
ip netns add target
ip link add rftarget0 type veth peer name target0
ip link set target0 netns target
ip link set rftarget0 up
ip addr add 198.51.100.1/24 dev rftarget0
ip netns exec target ip link set lo up
ip netns exec target ip link set target0 up
ip netns exec target ip addr add 198.51.100.2/24 dev target0
ip netns exec target ip route add default via 198.51.100.1
/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1
ping -4 -c 1 -W 1 198.51.100.2 >/dev/null
helper=tests/lab-tap-helper.py
/usr/sbin/nft add table inet unrelated_fixture
/usr/sbin/nft 'add chain inet unrelated_fixture input { type filter hook input priority 100; policy accept; }'
/usr/sbin/nft 'add chain inet unrelated_fixture forward { type filter hook forward priority 100; policy accept; }'
/usr/sbin/nft add rule inet unrelated_fixture forward counter
/usr/sbin/nft -s list table inet unrelated_fixture > /run/unrelated.before
if python3 "$helper" create arbitrary; then
    echo "Unexpected arguments accepted." >&2
    exit 1
fi
ip link add name rflabvm0 type dummy
if python3 "$helper" create; then
    echo "Interface collision accepted." >&2
    exit 1
fi
ip link show dev rflabvm0 >/dev/null
ip link delete dev rflabvm0
/usr/sbin/nft add table inet runner_fleet_tap_guard
if python3 "$helper" create; then
    echo "Table collision accepted." >&2
    exit 1
fi
/usr/sbin/nft list table inet runner_fleet_tap_guard >/dev/null
/usr/sbin/nft delete table inet runner_fleet_tap_guard
if python3 "$helper" create-fail-test; then
    echo "Injected partial failure accepted." >&2
    exit 1
fi
ip tuntap add dev rflabvm0 mode tap
if python3 "$helper" remove; then
    echo "Unknown partial TAP unexpectedly removed." >&2
    exit 1
fi
ip link show dev rflabvm0 >/dev/null
ip tuntap del dev rflabvm0 mode tap
python3 "$helper" remove
echo "Collisions preserved; unknown partial TAP retained; partial policy recovered."
python3 "$helper" create
ip link set rflabvm0 up
ip addr add 192.0.2.1/24 dev rflabvm0
python3 tests/lab-tap-packet-fixture.py denied
python3 tests/lab-tap-packet-fixture.py denied-forward
if /usr/sbin/capsh --drop=cap_net_admin -- -c "python3 $helper isolate"; then
    echo "Isolation without capability unexpectedly succeeded." >&2
    exit 1
fi
python3 -c 'import json,subprocess; x=json.loads(subprocess.check_output(["ip","-j","link","show","dev","rflabvm0"]))[0]; assert "UP" in x["flags"]; print("Failed isolation retained TAP and journal.")'
/usr/sbin/nft add rule inet runner_fleet_tap_guard forward_guard counter
if python3 "$helper" remove; then
    echo "Modified policy unexpectedly removed." >&2
    exit 1
fi
ip -brief link show dev rflabvm0 | grep 'DOWN' >/dev/null
test -f /run/runner-fleet-tap-helper.json
handle=$(/usr/sbin/nft -a list chain inet runner_fleet_tap_guard forward_guard | sed -n 's/.*counter packets .* handle \([0-9][0-9]*\)$/\1/p' | tail -1)
test -n "$handle"
/usr/sbin/nft delete rule inet runner_fleet_tap_guard forward_guard handle "$handle"
ip link set dev rflabvm0 alias unknown-owner
if python3 "$helper" remove; then
    echo "Foreign interface identity unexpectedly removed." >&2
    exit 1
fi
ip link set dev rflabvm0 alias runner-fleet-tap-namespace-experiment
python3 "$helper" remove
/usr/sbin/nft -s list table inet unrelated_fixture > /run/unrelated.after
cmp /run/unrelated.before /run/unrelated.after
echo "Modified policy refused; owned TAP removed; unrelated table unchanged."
ip tuntap add dev rflabvm0 mode tap
ip link set rflabvm0 up
ip addr add 192.0.2.1/24 dev rflabvm0
python3 tests/lab-tap-packet-fixture.py allowed
python3 tests/lab-tap-packet-fixture.py allowed-forward
ip tuntap del dev rflabvm0 mode tap
python3 "$helper" create > /run/create-a.log 2>&1 &
first=$!
python3 "$helper" create > /run/create-b.log 2>&1 &
second=$!
ok=0
if wait "$first"; then ok=$((ok + 1)); fi
if wait "$second"; then ok=$((ok + 1)); fi
if [ "$ok" -ne 1 ]; then
    echo "Expected one concurrent creation, got $ok." >&2
    exit 1
fi
python3 "$helper" remove
echo "Exactly one concurrent creation succeeded; cleanup verified."
python3 "$helper" create
ip link set rflabvm0 up
/usr/sbin/nft -s list table inet runner_fleet_tap_guard > /run/guard.saved
/usr/sbin/nft delete table inet runner_fleet_tap_guard
python3 "$helper" isolate
if python3 "$helper" remove; then
    echo "Missing policy unexpectedly accepted for removal." >&2
    exit 1
fi
ip -brief link show dev rflabvm0 | grep 'DOWN' >/dev/null
test -f /run/runner-fleet-tap-helper.json
/usr/sbin/nft -f /run/guard.saved
python3 "$helper" remove
echo "Missing policy kept the TAP isolated and journal retained until test recovery."
TEST
