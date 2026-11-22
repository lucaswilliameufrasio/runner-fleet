#!/usr/bin/python3
"""Disposable-namespace lifecycle experiment. Never install as a host helper."""
import json
import os
import re
import subprocess
import sys

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
NAME = "rflabctl0"
PEER = "rfguest0"
ALIAS = "runner-fleet-namespace-experiment"
TABLE = "runner_fleet_lab_ops"
STATE = "/run/runner-fleet-lab-ops.json"
POLICY = f"""
create table inet {TABLE}
add set inet {TABLE} permits {{ type ipv4_addr; flags timeout; timeout 3s; }}
add chain inet {TABLE} input_guard {{ type filter hook input priority -310; policy accept; }}
add chain inet {TABLE} forward_guard {{ type filter hook forward priority -310; policy accept; }}
add rule inet {TABLE} input_guard iifname "{NAME}" counter drop
add rule inet {TABLE} forward_guard iifname "{NAME}" oifname "rftarget0" ip saddr @permits ip daddr 198.51.100.2 counter return
add rule inet {TABLE} forward_guard iifname "{NAME}" counter drop
"""


def run(args, *, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=True, timeout=3).stdout


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Only mapped root in a disposable user namespace is supported")


def link():
    result = subprocess.run([IP, "-j", "-d", "link", "show", "dev", NAME], text=True, capture_output=True, timeout=3)
    if result.returncode != 0:
        # Confirm that the interface is absent via a successful complete dump.
        links = json.loads(run([IP, "-j", "-d", "link", "show"]))
        for entry in links:
            if entry["ifname"] == NAME:
                raise RuntimeError("Cannot inspect existing interface")
        return None
    return json.loads(result.stdout)[0]


def policy():
    text = run([NFT, "-s", "list", "table", "inet", TABLE])
    # The only expected dynamic element is the bounded synthetic lease.
    return re.sub(r"^\s*elements = \{ 192\.0\.2\.2 \}\n", "", text, flags=re.MULTILINE)


def write_state(state):
    # This file is in the test's private tmpfs; it is not a production trust anchor.
    with open(STATE, "w", encoding="utf-8") as target:
        json.dump(state, target)
        target.flush()
        os.fsync(target.fileno())


def create(inject_failure):
    if os.path.lexists(STATE) or link() is not None:
        raise RuntimeError("Existing state or interface; refusing collision")
    tables = json.loads(run([NFT, "-j", "list", "tables"]))
    for entry in tables["nftables"]:
        table = entry.get("table", {})
        if table.get("family") == "inet" and table.get("name") == TABLE:
            raise RuntimeError("Existing table; refusing collision")
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    write_state({"stage": "reserved"})
    run([NFT, "-f", "-"], data=POLICY)
    state = {"stage": "guard", "policy": policy()}
    write_state(state)
    if inject_failure:
        raise RuntimeError("Injected failure after closed policy")
    run([IP, "link", "add", "name", NAME, "type", "veth", "peer", "name", PEER])
    run([IP, "link", "set", "dev", NAME, "alias", ALIAS])
    current = link()
    state.update({"stage": "ready", "ifindex": current["ifindex"]})
    write_state(state)
    print("CREATED_CLOSED", flush=True)


def remove():
    with open(STATE, encoding="utf-8") as source:
        state = json.load(source)
    if state.get("stage") not in ("guard", "ready"):
        raise RuntimeError("Unknown partial state; manual recovery required")
    current = link()
    if state["stage"] == "ready":
        if current is None or current.get("ifindex") != state["ifindex"] or current.get("ifalias") != ALIAS:
            raise RuntimeError("Interface identity changed; refusing removal")
        # Isolate a known interface even if the firewall was altered or lost.
        run([IP, "link", "set", "dev", NAME, "down"])
    elif current is not None:
        raise RuntimeError("Unexpected interface in partial state; refusing removal")
    if policy() != state.get("policy"):
        raise RuntimeError("Policy changed; interface isolated, refusing removal")
    if current is not None:
        run([IP, "link", "delete", "dev", NAME])
    run([NFT, "delete", "table", "inet", TABLE])
    os.unlink(STATE)
    print("REMOVED_OWNED", flush=True)


def main():
    namespace_check()
    if sys.argv[1:] == ["create"]:
        create(False)
    elif sys.argv[1:] == ["create", "--inject-failure"]:
        create(True)
    elif sys.argv[1:] == ["remove"]:
        remove()
    else:
        raise RuntimeError("Expected create, create --inject-failure, or remove")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
