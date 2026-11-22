#!/usr/bin/python3
"""Namespace-only test watcher: terminate a handed-off PID boundary on fence loss."""
import os
import signal
import subprocess
import sys
import time

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(sys.argv) != 2 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires disposable mapped-root namespaces and handed-off pidfd")
    boundary_fd = int(sys.argv[1])
    with open("/run/fleet-fence-expected", "rb") as source:
        expected = source.read(65537)
    if not expected or len(expected) > 65536:
        raise RuntimeError("Invalid expected fence")
    first = True
    while True:
        try:
            result = subprocess.run([
                "/usr/sbin/ip", "netns", "exec", "fence", "/usr/sbin/nft", "-s",
                "list", "table", "inet", "runner_fleet_independent_fence",
            ], capture_output=True, timeout=2, check=False, env=ENV)
            valid = result.returncode == 0 and result.stdout == expected
        except (OSError, subprocess.TimeoutExpired):
            valid = False
        if not valid:
            print("FENCE_LOST", flush=True)
            signal.pidfd_send_signal(boundary_fd, signal.SIGKILL)
            print("BOUNDARY_SIGNALLED", flush=True)
            return
        if first:
            print("FENCE_WATCHER_READY", flush=True)
            first = False
        time.sleep(0.05)


if __name__ == "__main__":
    main()
