#!/usr/bin/python3
"""Experimental watchdog: use only in the disposable network test namespace."""
import select
import subprocess
import sys

NFT = "/usr/sbin/nft"
IP = "/usr/sbin/ip"
EXPECTED = "/run/runner-fleet-lab-expected"
CLOSE = "/run/runner-fleet-lab-close.nft"


def command(args):
    return subprocess.run(args, capture_output=True, timeout=2, check=False)


def isolate():
    result = command([IP, "link", "set", "dev", "rflab0", "down"])
    if result.returncode != 0:
        print("ISOLATION_FAILED", flush=True)
        return False
    print("ISOLATED", flush=True)
    return True


def main():
    with open("/proc/self/uid_map", encoding="ascii") as mapping:
        fields = mapping.read().split()
    if len(sys.argv) != 1 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        print("Refusing non-isolated execution.", file=sys.stderr)
        return 2
    try:
        with open(EXPECTED, "rb") as expected_file:
            expected = expected_file.read(65537)
        if not expected or len(expected) > 65536:
            raise ValueError("Invalid expected policy")
        first = True
        while True:
            result = command([NFT, "-s", "list", "table", "inet", "runner_fleet_lab_closed"])
            if result.returncode != 0 or result.stdout != expected:
                print("POLICY_LOST", flush=True)
                return 1 if isolate() else 2
            if first:
                print("READY", flush=True)
                first = False
            ready, _, _ = select.select([sys.stdin], [], [], 0.05)
            if ready:
                request = sys.stdin.readline()
                if request != "close\n":
                    print("CONTROL_LOST", flush=True)
                    return 1 if isolate() else 2
                # Disconnect before attempting the transaction: even a broken
                # close file must not leave the interface carrying packets.
                if not isolate():
                    return 2
                result = command([NFT, "-f", CLOSE])
                if result.returncode != 0:
                    print("CLOSE_FAILED", flush=True)
                    return 1
                print("CLOSED", flush=True)
                return 0
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"WATCHDOG_ERROR: {exc}", file=sys.stderr, flush=True)
        return 1 if isolate() else 2


if __name__ == "__main__":
    sys.exit(main())
