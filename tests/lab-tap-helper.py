#!/usr/bin/python3
"""Restricted TAP lifecycle experiment, exclusively for disposable namespaces."""
import fcntl
import json
import os
import subprocess
import sys

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
NAME = "rflabvm0"
ALIAS = "runner-fleet-tap-namespace-experiment"
TABLE = "runner_fleet_tap_guard"
STATE = "/run/runner-fleet-tap-helper.json"
LOCK = "/run/runner-fleet-tap-helper.lock"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
POLICY = f"""
create table inet {TABLE}
add chain inet {TABLE} input_guard {{ type filter hook input priority -310; policy accept; }}
add chain inet {TABLE} forward_guard {{ type filter hook forward priority -310; policy accept; }}
add rule inet {TABLE} input_guard iifname "{NAME}" counter drop
add rule inet {TABLE} forward_guard iifname "{NAME}" counter drop
"""


def run(args, data=None):
    return subprocess.run(args, input=data, capture_output=True, text=True,
                          env=ENV, check=True, timeout=5).stdout


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a disposable mapped-root namespace")


def all_links():
    return json.loads(run([IP, "-j", "-d", "link", "show"]))


def lookup():
    for entry in all_links():
        if entry["ifname"] == NAME:
            return entry
    return None


def table_exists():
    entries = json.loads(run([NFT, "-j", "list", "tables"]))
    for entry in entries["nftables"]:
        table = entry.get("table", {})
        if table.get("family") == "inet" and table.get("name") == TABLE:
            return True
    return False


def save_state(state):
    # Private test tmpfs only: not a trust anchor or durable host journal.
    temporary = STATE + ".new"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        json.dump(state, target)
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, STATE)


def read_state():
    fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as source:
        state = json.load(source)
    if state.get("stage") not in ("guard", "ready"):
        raise RuntimeError("Unknown journal state; manual recovery required")
    return state


def current_policy():
    return run([NFT, "-s", "list", "table", "inet", TABLE])


def validate_link(state):
    entry = lookup()
    if state["stage"] == "guard":
        if entry is not None:
            raise RuntimeError("Unexpected interface after partial creation")
        return None
    info = {} if entry is None else entry.get("linkinfo", {})
    if (entry is None or entry.get("ifindex") != state.get("ifindex")
            or entry.get("ifalias") != ALIAS or info.get("info_kind") != "tun"
            or info.get("info_data", {}).get("type") != "tap"):
        raise RuntimeError("TAP identity changed; refusing operation")
    return entry


def create(inject):
    if os.path.lexists(STATE) or os.path.lexists(STATE + ".new") or lookup() is not None or table_exists():
        raise RuntimeError("Existing state, interface or table; refusing collision")
    fd = os.open(STATE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        json.dump({"stage": "reserved"}, target)
        target.flush()
        os.fsync(target.fileno())
    run([NFT, "-f", "-"], POLICY)
    state = {"stage": "guard", "policy": current_policy()}
    save_state(state)
    if inject:
        raise RuntimeError("Injected failure after closed policy")
    run([IP, "tuntap", "add", "dev", NAME, "mode", "tap"])
    run([IP, "link", "set", "dev", NAME, "alias", ALIAS])
    entry = lookup()
    state.update({"stage": "ready", "ifindex": entry["ifindex"]})
    save_state(state)
    print("CREATED_TAP_CLOSED")


def isolate():
    state = read_state()
    entry = validate_link(state)
    if entry is None:
        raise RuntimeError("No owned TAP to isolate")
    run([IP, "link", "set", "dev", NAME, "down"])
    print("TAP_ISOLATED")


def remove():
    state = read_state()
    entry = validate_link(state)
    if entry is not None:
        # Isolate the verified TAP even if its policy has been altered.
        run([IP, "link", "set", "dev", NAME, "down"])
    if current_policy() != state.get("policy"):
        raise RuntimeError("Policy changed; refusing removal")
    if entry is not None:
        run([IP, "tuntap", "del", "dev", NAME, "mode", "tap"])
    run([NFT, "delete", "table", "inet", TABLE])
    os.unlink(STATE)
    print("REMOVED_OWNED_TAP")


def main():
    namespace_check()
    args = sys.argv[1:]
    if args not in (["create"], ["create-fail-test"], ["isolate"], ["remove"]):
        raise RuntimeError("Only fixed test operations are accepted")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args == ["create"]:
            create(False)
        elif args == ["create-fail-test"]:
            create(True)
        elif args == ["isolate"]:
            isolate()
        else:
            remove()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
