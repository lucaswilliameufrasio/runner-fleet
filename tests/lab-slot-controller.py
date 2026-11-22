#!/usr/bin/python3
"""Single-slot failure/recovery experiment. Not a Fleet or host controller."""
import fcntl
import json
import os
import sqlite3
import subprocess
import sys

DB = "/run/runner-fleet-slot.sqlite3"
LOCK = "/run/runner-fleet-slot.lock"
OPS_STATE = "/run/runner-fleet-lab-ops.json"
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
OPS = "tests/lab-network-operations.py"


def command(args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=5)


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Only a disposable mapped-root namespace is supported")


def resources_absent():
    links = json.loads(command([IP, "-j", "link", "show"]).stdout)
    for link in links:
        if link["ifname"] in ("rflabctl0", "rfguest0"):
            return False
    tables = json.loads(command([NFT, "-j", "list", "tables"]).stdout)
    for entry in tables["nftables"]:
        table = entry.get("table", {})
        if table.get("family") == "inet" and table.get("name") == "runner_fleet_lab_ops":
            return False
    return not os.path.lexists(OPS_STATE)


def connect():
    connection = sqlite3.connect(f"file:{DB}?mode=rw", uri=True, timeout=5)
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def read_state(connection):
    rows = connection.execute("SELECT state FROM slot WHERE id = 1").fetchall()
    if len(rows) != 1 or rows[0][0] not in ("EMPTY", "UNKNOWN", "ACTIVE"):
        raise RuntimeError("State missing or invalid; admission blocked")
    return rows[0][0]


def set_state(connection, value):
    with connection:
        cursor = connection.execute("UPDATE slot SET state = ? WHERE id = 1", (value,))
        if cursor.rowcount != 1:
            raise RuntimeError("State missing; admission blocked")


def initialize():
    if not resources_absent():
        raise RuntimeError("Resources exist; cannot initialize an empty slot")
    fd = os.open(DB, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    with connect() as connection:
        connection.execute("CREATE TABLE slot (id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)")
        connection.execute("INSERT INTO slot VALUES (1, 'EMPTY')")
    print("INITIALIZED EMPTY")


def start(connection, inject_failure, crash):
    if read_state(connection) != "EMPTY":
        raise RuntimeError("Slot reserved or unknown; admission blocked")
    if not resources_absent():
        raise RuntimeError("Unowned or unknown resources; admission blocked")
    set_state(connection, "UNKNOWN")
    if crash:
        os._exit(71)
    args = [sys.executable, OPS, "create"]
    if inject_failure:
        args.append("--inject-failure")
    result = command(args)
    set_state(connection, "ACTIVE")
    print(result.stdout.strip())
    print("SLOT ACTIVE")


def cleanup(connection):
    previous = read_state(connection)
    if previous == "EMPTY":
        if not resources_absent():
            raise RuntimeError("Orphan resources detected; admission blocked")
        print("SLOT EMPTY")
        return
    set_state(connection, "UNKNOWN")
    if os.path.lexists(OPS_STATE):
        command([sys.executable, OPS, "remove"])
    if not resources_absent():
        raise RuntimeError("Cleanup could not be proven; slot remains UNKNOWN")
    set_state(connection, "EMPTY")
    print("CLEANUP_VERIFIED SLOT EMPTY")


def main():
    namespace_check()
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        args = sys.argv[1:]
        if args == ["init"]:
            initialize()
            return
        with connect() as connection:
            if args == ["status"]:
                print("SLOT " + read_state(connection))
            elif args == ["start"]:
                start(connection, False, False)
            elif args == ["start", "--inject-failure"]:
                start(connection, True, False)
            elif args == ["start", "--crash-after-reserve"]:
                start(connection, False, True)
            elif args == ["cleanup"]:
                cleanup(connection)
            else:
                raise RuntimeError("Expected init, status, start or cleanup")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
