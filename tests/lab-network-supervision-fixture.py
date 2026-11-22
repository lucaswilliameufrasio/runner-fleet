#!/usr/bin/python3
"""Exercise the namespace-only watchdog with real TCP and fault injection."""
import os
import select
import subprocess
import sys
import time

NFT = "/usr/sbin/nft"
IP = "/usr/sbin/ip"
EXPECTED = "/run/runner-fleet-lab-expected"
CLOSE = "/run/runner-fleet-lab-close.nft"
SERVER = """
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.2", 34679))
s.listen(1)
print("SERVER_READY", flush=True)
c, _ = s.accept()
while True:
    data = c.recv(1024)
    if not data:
        break
    c.sendall(data)
"""
CLIENT = """
import socket, sys
s = socket.create_connection(("198.51.100.2", 34679), timeout=2)
s.settimeout(1)
print("CLIENT_READY", flush=True)
for line in sys.stdin:
    try:
        s.sendall(b"probe")
        print("ECHO" if s.recv(5) == b"probe" else "INVALID", flush=True)
    except (OSError, TimeoutError):
        print("BLOCKED", flush=True)
        break
"""


def run(args):
    subprocess.run(args, check=True, timeout=5, stdout=subprocess.DEVNULL)


def read_line(process, timeout=5):
    deadline = time.monotonic() + timeout
    line = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Timed out waiting for fixture output")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise RuntimeError("Timed out waiting for fixture output")
        char = os.read(process.stdout.fileno(), 1)
        if not char:
            raise RuntimeError("Fixture exited without expected output")
        if char == b"\n":
            return line.decode()
        line.extend(char)


def start(args):
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)


def main():
    with open("/proc/self/uid_map", encoding="ascii") as mapping:
        fields = mapping.read().split()
    if len(sys.argv) != 1 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Run only in the disposable network namespace")
    processes = []
    try:
        server = start([IP, "netns", "exec", "target", sys.executable, "-u", "-c", SERVER])
        processes.append(server)
        if read_line(server) != "SERVER_READY":
            raise RuntimeError("Server failed to start")
        with open(EXPECTED, "wb") as expected:
            subprocess.run([NFT, "-s", "list", "table", "inet", "runner_fleet_lab_closed"], stdout=expected, check=True)
        watchdog = start([sys.executable, "-u", "tests/lab-network-watchdog.py"])
        processes.append(watchdog)
        if read_line(watchdog) != "READY":
            raise RuntimeError("Watchdog failed to start")
        client = start([IP, "netns", "exec", "guest", sys.executable, "-u", "-c", CLIENT])
        processes.append(client)
        if read_line(client) != "CLIENT_READY":
            raise RuntimeError("Client failed to connect")
        client.stdin.write(b"probe\n")
        client.stdin.flush()
        if read_line(client) != "ECHO":
            raise RuntimeError("Established TCP baseline failed")
        start_time = time.monotonic()
        run([NFT, "delete", "table", "inet", "runner_fleet_lab_closed"])
        if read_line(watchdog) != "POLICY_LOST" or read_line(watchdog) != "ISOLATED":
            raise RuntimeError("Policy loss was not isolated")
        duration = time.monotonic() - start_time
        client.stdin.write(b"probe\n")
        client.stdin.flush()
        if read_line(client) != "BLOCKED":
            raise RuntimeError("Established TCP connection still transferred data")
        print(f"Policy deletion isolated in {duration:.3f}s; established TCP stopped.")
        run([NFT, "-f", "scripts/lab-network-closed.nft"])
        run([NFT, "-f", "scripts/lab-network-synthetic-egress.nft"])
        run([IP, "link", "set", "dev", "rflab0", "up"])
        with open(EXPECTED, "wb") as expected:
            subprocess.run([NFT, "-s", "list", "table", "inet", "runner_fleet_lab_closed"], stdout=expected, check=True)
        with open(CLOSE, "w", encoding="utf-8") as close_file:
            close_file.write("invalid test transaction\n")
        watchdog = start([sys.executable, "-u", "tests/lab-network-watchdog.py"])
        processes.append(watchdog)
        if read_line(watchdog) != "READY":
            raise RuntimeError("Second watchdog failed to start")
        watchdog.stdin.write(b"close\n")
        watchdog.stdin.flush()
        if read_line(watchdog) != "ISOLATED" or read_line(watchdog) != "CLOSE_FAILED":
            raise RuntimeError("Failed close did not isolate the interface")
        link = subprocess.run([IP, "-brief", "link", "show", "dev", "rflab0"], capture_output=True, text=True, check=True)
        if "DOWN" not in link.stdout:
            raise RuntimeError("Interface is not down after failed close")
        print("Invalid close transaction: interface remained down.")
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
