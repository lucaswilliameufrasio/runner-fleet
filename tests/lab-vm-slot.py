#!/usr/bin/python3
"""VM admission experiment for disposable namespaces; not a Fleet controller."""
import fcntl
import json
import os
import sqlite3
import subprocess
import sys
import time

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a disposable mapped-root namespace")


class Slot:
    def __init__(self, path):
        self.path = path

    @classmethod
    def create(cls, path):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        slot = cls(path)
        with slot.connect() as connection:
            connection.execute("CREATE TABLE slot (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL)")
            connection.execute("INSERT INTO slot VALUES (1, 'EMPTY')")
        return slot

    def connect(self):
        connection = sqlite3.connect(f"file:{self.path}?mode=rw", uri=True, timeout=5)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def state(self):
        with self.connect() as connection:
            row = connection.execute("SELECT state FROM slot WHERE id=1").fetchone()
        if row is None or row[0] not in ("EMPTY", "RESERVED", "ACTIVE", "UNKNOWN"):
            raise RuntimeError("Missing or invalid state")
        return row[0]

    def transition(self, previous, new):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute("UPDATE slot SET state=? WHERE id=1 AND state=?", (new, previous))
            if result.rowcount != 1:
                raise RuntimeError(f"Transition {previous} -> {new} refused")

    def reserve(self):
        self.transition("EMPTY", "RESERVED")

    def activate(self):
        self.transition("RESERVED", "ACTIVE")

    def mark_unknown(self):
        current = self.state()
        if current in ("RESERVED", "ACTIVE"):
            self.transition(current, "UNKNOWN")
        elif current != "UNKNOWN":
            raise RuntimeError("Cannot mark an empty slot unknown")

    def recover(self):
        # Only one controller or recovery attempt can hold this test lock.
        fd = os.open(self.path + ".controller-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.mark_unknown()

    def run_controller(self):
        fd = os.open(self.path + ".controller-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        transaction = (
            "delete element inet runner_fleet_lab_lease permits { 192.0.2.2 }\n"
            "add element inet runner_fleet_lab_lease permits { 192.0.2.2 timeout 3s }\n"
        )
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            first = True
            while True:
                if self.state() != "ACTIVE":
                    raise RuntimeError("Controller cannot renew a non-active slot")
                subprocess.run(
                    [NFT, "-f", "-"], input=transaction, text=True, env=ENV,
                    capture_output=True, check=True, timeout=2,
                )
                if first:
                    print("CONTROLLER_READY", flush=True)
                    first = False
                time.sleep(0.4)

    def release(self, qemu, overlay, seed):
        if self.state() != "UNKNOWN" or qemu is None or qemu.poll() is None:
            raise RuntimeError("Unknown state and exited owned QEMU are required")
        for path in (overlay, seed):
            if os.path.lexists(path):
                raise RuntimeError("VM disk or seed remains")
        for path in ("/run/runner-fleet-tap-helper.json", "/run/runner-fleet-tap-helper.json.new"):
            if os.path.lexists(path):
                raise RuntimeError("TAP helper state remains")
        links = json.loads(subprocess.run([IP, "-j", "link", "show"], env=ENV, check=True, capture_output=True, text=True, timeout=5).stdout)
        if any(entry["ifname"] in ("rflab0", "rflabvm0", "rftarget0", "rfbr0", "rfbridge0", "rfhostbr0", "rfegress0", "rfpeer0") for entry in links):
            raise RuntimeError("Owned network interface remains")
        tables = json.loads(subprocess.run([NFT, "-j", "list", "tables"], env=ENV, check=True, capture_output=True, text=True, timeout=5).stdout)
        for entry in tables["nftables"]:
            table = entry.get("table", {})
            if table.get("family") == "inet" and table.get("name") in (
                "runner_fleet_lab_closed", "runner_fleet_lab_lease", "runner_fleet_tap_guard",
                "runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b", "native_socket_lab",
                "public_egress_guard",
            ):
                raise RuntimeError("Owned firewall table remains")
            if table.get("family") == "ip" and table.get("name") == "public_egress_nat":
                raise RuntimeError("Owned NAT table remains")
            if table.get("family") == "bridge" and table.get("name") == "runner_fleet_bridge_guard":
                raise RuntimeError("Owned bridge firewall table remains")
            if table.get("family") == "netdev" and table.get("name") == "runner_fleet_ingress_guard":
                raise RuntimeError("Owned ingress firewall table remains")
        namespaces = subprocess.run([IP, "netns", "list"], env=ENV, check=True, capture_output=True, text=True, timeout=5).stdout
        if any(line.split()[0] in ("target", "fence", "protected", "router", "public") for line in namespaces.splitlines() if line.split()):
            raise RuntimeError("Owned test namespace remains")
        self.transition("UNKNOWN", "EMPTY")


if __name__ == "__main__":
    try:
        namespace_check()
        if len(sys.argv) != 3 or sys.argv[1] not in ("reserve", "status", "run", "recover"):
            raise RuntimeError("Expected reserve|status|run|recover STATE_FILE")
        slot = Slot(sys.argv[2])
        if sys.argv[1] == "reserve":
            slot.reserve()
            print("RESERVED")
        elif sys.argv[1] == "status":
            print("SLOT " + slot.state())
        elif sys.argv[1] == "run":
            slot.run_controller()
        else:
            slot.recover()
            print("SLOT " + slot.state())
    except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
