#!/bin/sh
# Kill the lab supervisor while its VM is running. The killer stays outside
# the disposable pid namespace. This does not change the host firewall.
set -eu
if [ "$#" -ne 1 ] || [ "$(id -u)" -eq 0 ] || [ ! -f "$1" ]; then
    echo "Usage: unprivileged user: sh $0 VERIFIED_QCOW2" >&2
    exit 2
fi
image=$(realpath -- "$1")
log=$(mktemp)
unshare --user --map-root-user --mount --pid --fork --mount-proc -- \
    python3 tests/lab-public-egress-vm-isolated.py --hold "$image" >"$log" 2>&1 &
parent=$!
deadline=$(( $(date +%s) + 90 ))
while ! grep -q '^HOLD_READY$' "$log" 2>/dev/null; do
    if ! kill -0 "$parent" 2>/dev/null; then
        echo "BLOCKED: hold supervisor exited before the VM was ready" >&2
        cat "$log" >&2
        rm -f "$log"
        exit 1
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "BLOCKED: hold supervisor did not become ready" >&2
        kill -9 "$parent" 2>/dev/null || true
        wait "$parent" 2>/dev/null || true
        rm -f "$log"
        exit 1
    fi
    sleep 0.2
done
child=$(ps -o pid= --ppid "$parent" | awk 'NR==1 { print $1 }')
if ! python3 - "$child" << 'PY'
import os, sys, time
root = int(sys.argv[1])
deadline = time.time() + 20
while time.time() < deadline:
    seen = []
    pending = [root]
    while pending:
        pid = pending.pop()
        path = f"/proc/{pid}/task/{pid}/children"
        try:
            text = open(path, encoding="ascii").read().split()
        except FileNotFoundError:
            continue
        for item in text:
            child = int(item)
            seen.append(child)
            pending.append(child)
    for pid in seen:
        try:
            command = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\x00", b" ").decode()
        except FileNotFoundError:
            continue
        if "qemu-system-x86_64" in command:
            raise SystemExit(0)
    time.sleep(0.2)
raise SystemExit(1)
PY
then
    echo "BLOCKED: QEMU did not appear under the supervisor" >&2
    kill -9 "$child" 2>/dev/null || true
    wait "$parent" 2>/dev/null || true
    rm -f "$log"
    exit 1
fi
kill -9 "$child"
wait "$parent" 2>/dev/null || true
python3 - "$log" << 'PY'
import os, sqlite3, subprocess, sys
log = open(sys.argv[1], encoding="utf-8", errors="replace").read()
evidence = ""
for line in log.splitlines():
    if line.startswith("EVIDENCE_DIR="):
        evidence = line.split("=", 1)[1]
if not evidence or not os.path.isdir(evidence):
    raise SystemExit("BLOCKED: missing evidence directory")
qemu = subprocess.run(["pgrep", "-a", "qemu-system-x86_64"], capture_output=True, text=True)
if qemu.returncode == 0:
    raise SystemExit("BLOCKED: QEMU still running after supervisor SIGKILL")
slirp = subprocess.run(["pgrep", "-a", "slirp4netns"], capture_output=True, text=True)
for line in slirp.stdout.splitlines():
    if "rfegress0" in line:
        raise SystemExit("BLOCKED: lab slirp survived the supervisor")
links = subprocess.run(["/usr/sbin/ip", "-j", "link", "show"], capture_output=True, text=True, check=True)
if any(name in links.stdout for name in ('"rflab0"', '"rfegress0"', '"rfpeer0"')):
    raise SystemExit("BLOCKED: lab interface remains on the host")
routes = subprocess.run(["/usr/sbin/ip", "-4", "route"], capture_output=True, text=True, check=True)
if len(routes.stdout.splitlines()) != 2:
    raise SystemExit("BLOCKED: host IPv4 route count changed")
slot_path = os.path.join(evidence, "slot.sqlite3")
state = sqlite3.connect(slot_path).execute("select state from slot").fetchone()[0]
print(f"SUPERVISOR KILLED: qemu and lab slirp gone; slot left {state}; host routes unchanged.")
if state == "EMPTY":
    raise SystemExit("BLOCKED: crash marked the slot empty")
PY
status=$?
if [ "$status" -eq 0 ]; then
    evidence=$(sed -n 's/^EVIDENCE_DIR=//p' "$log" | head -1)
    if [ -n "$evidence" ] && [ -d "$evidence" ]; then
        rm -rf -- "$evidence"
        echo "HARNESS REMOVED LEFTOVER LAB FILES"
    fi
fi
rm -f "$log"
exit "$status"
