#!/bin/sh
# SQLite and all networking are confined to disposable namespaces.
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
unshare --user --map-root-user --mount --net -- /bin/sh -eu -s <<'TEST'
mount -t tmpfs -o size=4m tmpfs /run
controller=tests/lab-slot-controller.py
/usr/sbin/nft add table inet unrelated_fixture
python3 "$controller" init
python3 "$controller" start
ip link set rflabctl0 up
if /usr/sbin/capsh --drop=cap_net_admin -- -c 'ip link set rflabctl0 down'; then
    echo "Capability fault injection unexpectedly succeeded." >&2
    exit 1
fi
echo "Isolation fault confirmed: CAP_NET_ADMIN unavailable."
if /usr/sbin/capsh --drop=cap_net_admin -- -c "python3 $controller cleanup"; then
    echo "Cleanup without network capability unexpectedly succeeded." >&2
    exit 1
fi
python3 "$controller" status | grep '^SLOT UNKNOWN$'
if python3 "$controller" start; then
    echo "Admission after failed isolation unexpectedly succeeded." >&2
    exit 1
fi
python3 -c 'import json,subprocess; x=json.loads(subprocess.check_output(["ip","-j","link","show","dev","rflabctl0"]))[0]; assert "UP" in x["flags"]; print("Failed isolation left interface up; slot remains blocked.")'
python3 "$controller" cleanup
python3 "$controller" status | grep '^SLOT EMPTY$'
if python3 "$controller" start --inject-failure; then
    echo "Injected partial create unexpectedly succeeded." >&2
    exit 1
fi
python3 "$controller" status | grep '^SLOT UNKNOWN$'
if python3 "$controller" start; then
    echo "Admission after partial create unexpectedly succeeded." >&2
    exit 1
fi
python3 "$controller" cleanup
if python3 "$controller" start --crash-after-reserve; then
    echo "Injected controller crash unexpectedly succeeded." >&2
    exit 1
fi
python3 "$controller" status | grep '^SLOT UNKNOWN$'
if python3 "$controller" start; then
    echo "Admission after controller crash unexpectedly succeeded." >&2
    exit 1
fi
python3 "$controller" cleanup
python3 "$controller" start > /run/start-a.log 2>&1 &
first=$!
python3 "$controller" start > /run/start-b.log 2>&1 &
second=$!
ok=0
if wait "$first"; then ok=$((ok + 1)); fi
if wait "$second"; then ok=$((ok + 1)); fi
if [ "$ok" -ne 1 ]; then
    echo "Expected exactly one concurrent admission, got $ok." >&2
    exit 1
fi
echo "Concurrent admissions: exactly one succeeded."
python3 "$controller" cleanup
/usr/sbin/nft list table inet unrelated_fixture >/dev/null
printf 'corrupted test database\n' > /run/runner-fleet-slot.sqlite3
if python3 "$controller" start; then
    echo "Admission with corrupted state unexpectedly succeeded." >&2
    exit 1
fi
echo "Corrupted state: admission blocked."
echo "Recovery tests passed; unrelated table preserved."
TEST
