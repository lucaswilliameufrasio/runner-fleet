#!/usr/bin/python3
"""Exercise a kernel-timed lease after killing its owner in a disposable netns."""
import subprocess
import sys
import time

import importlib.util

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("lab_supervision_fixture", "tests/lab-network-supervision-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
NFT = "/usr/sbin/nft"
TABLE = "runner_fleet_lab_lease"
LEASE = "192.0.2.2"


def require_unprivileged_user_namespace():
    with open("/proc/self/uid_map", encoding="ascii") as mapping:
        fields = mapping.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Run only as mapped root in a disposable user namespace")


def renew():
    transaction = (
        f"delete element inet {TABLE} permits {{ {LEASE} }}\n"
        f"add element inet {TABLE} permits {{ {LEASE} timeout 3s }}\n"
    )
    first = True
    while True:
        subprocess.run([NFT, "-f", "-"], input=transaction, text=True, check=True, timeout=2)
        if first:
            print("RENEWING", flush=True)
            first = False
        time.sleep(0.4)


def main():
    global TABLE
    require_unprivileged_user_namespace()
    if sys.argv[1:] == ["--renewer", "--lifecycle"]:
        TABLE = "runner_fleet_lab_ops"
        renew()
        return
    if sys.argv[1:] == ["--renewer"]:
        renew()
        return
    if sys.argv[1:] == ["--lifecycle"]:
        TABLE = "runner_fleet_lab_ops"
        renewer_args = ["--renewer", "--lifecycle"]
    elif len(sys.argv) == 1:
        renewer_args = ["--renewer"]
    else:
        raise RuntimeError("Unexpected arguments")
    processes = []
    try:
        fixture.run([NFT, "add", "element", "inet", TABLE, "permits", "{", LEASE, "timeout", "3s", "}"])
        renewer = fixture.start([sys.executable, "-u", "tests/lab-network-lease-fixture.py", *renewer_args])
        processes.append(renewer)
        if fixture.read_line(renewer) != "RENEWING":
            raise RuntimeError("Lease renewal failed")
        server = fixture.start([fixture.IP, "netns", "exec", "target", sys.executable, "-u", "-c", fixture.SERVER])
        processes.append(server)
        if fixture.read_line(server) != "SERVER_READY":
            raise RuntimeError("Server failed")
        client = fixture.start([fixture.IP, "netns", "exec", "guest", sys.executable, "-u", "-c", fixture.CLIENT])
        processes.append(client)
        if fixture.read_line(client) != "CLIENT_READY":
            raise RuntimeError("Client failed")
        time.sleep(3.4)
        if renewer.poll() is not None:
            raise RuntimeError("Renewer exited before the lease extension was tested")
        client.stdin.write(b"probe\n")
        client.stdin.flush()
        if fixture.read_line(client) != "ECHO":
            raise RuntimeError("Established TCP failed after lease renewal")
        print("Lease renewal kept established TCP working beyond the initial lifetime.")
        if TABLE == "runner_fleet_lab_ops":
            for destination in ("192.0.2.1", "198.51.100.3"):
                result = subprocess.run(
                    [fixture.IP, "netns", "exec", "guest", "ping", "-4", destination, "-c", "1", "-W", "1"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False
                )
                if result.returncode == 0:
                    raise RuntimeError(f"Protected destination unexpectedly reachable: {destination}")
            print("Host and non-approved target remained blocked during the lease.")
        renewer.kill()
        renewer.wait(timeout=3)
        killed = time.monotonic()
        time.sleep(3.4)
        client.stdin.write(b"probe\n")
        client.stdin.flush()
        if fixture.read_line(client) != "BLOCKED":
            raise RuntimeError("Expired lease still permits the TCP flow")
        elapsed = time.monotonic() - killed
        print(f"Renewer killed: established TCP blocked after {elapsed:.2f}s without watchdog action.")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    main()
