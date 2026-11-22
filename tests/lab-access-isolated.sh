#!/bin/sh
# Test only inside new user, mount and network namespaces.
set -eu
if [ "$#" -ne 0 ] || [ "$(id -u)" -eq 0 ]; then
    echo "Run without arguments as an unprivileged user." >&2
    exit 2
fi
user=$(id -un)
unshare --user --map-root-user --mount --net -- /bin/sh -eu -s -- "$user" <<'TEST'
user=$1
mount -t tmpfs -o size=1m tmpfs /etc/sudoers.d
mount -t tmpfs -o size=1m tmpfs /usr/local/sbin
sh scripts/lab-access-create "$user"
/usr/sbin/visudo -cf /etc/sudoers.d/runner-fleet-lab-inspect
if sh scripts/lab-access-create "$user"; then
    echo "Repeated installation unexpectedly succeeded." >&2
    exit 1
fi
if /usr/local/sbin/runner-fleet-lab-firewall-inspect extra; then
    echo "Helper unexpectedly accepted an argument." >&2
    exit 1
fi
printf '# modified\n' >> /etc/sudoers.d/runner-fleet-lab-inspect
if sh scripts/lab-access-remove "$user" --confirm; then
    echo "Modified rule was unexpectedly removed." >&2
    exit 1
fi
printf '%s ALL=(root) NOPASSWD: %s ""\n' "$user" \
    /usr/local/sbin/runner-fleet-lab-firewall-inspect \
    > /etc/sudoers.d/runner-fleet-lab-inspect
printf '# modified\n' >> /usr/local/sbin/runner-fleet-lab-firewall-inspect
if sh scripts/lab-access-remove "$user" --confirm; then
    echo "Modified helper was unexpectedly removed." >&2
    exit 1
fi
cp scripts/lab-firewall-inspect /usr/local/sbin/runner-fleet-lab-firewall-inspect
sh scripts/lab-access-remove "$user" --confirm
test ! -e /etc/sudoers.d/runner-fleet-lab-inspect
test ! -e /usr/local/sbin/runner-fleet-lab-firewall-inspect
echo "Isolated lab-access tests passed."
TEST
