#!/usr/bin/python3
"""Public-egress policy for a disposable lab namespace.

Blackhole routes for non-public ranges are more specific than the default
route. Removing an nftables table does not create a path to those ranges.
The 10.0.2.0/24 exception is only the slirp transit network and must stay
more specific than 10.0.0.0/8. This is not a Fleet controller.
"""
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import threading
import time

IP = "/usr/sbin/ip"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
BLOCKED_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
SLIRP_NET = ipaddress.ip_network("10.0.2.0/24")
BLOCKED_NETS = tuple(ipaddress.ip_network(prefix) for prefix in BLOCKED_V4)
LISTENER = r"""
import socket, sys
address, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, port))
server.listen(8)
with open(path, "a", encoding="ascii") as output:
    output.write("READY\n")
    output.flush()
    while True:
        client, _peer = server.accept()
        client.close()
        output.write("RECEIVED\n")
        output.flush()
"""


def destination_blocked(value):
    address = ipaddress.ip_address(value)
    if address.version != 4:
        return True
    if address in SLIRP_NET:
        return False
    for network in BLOCKED_NETS:
        if address in network:
            return True
    return False


def run(args, data=None):
    completed = subprocess.run(
        args, input=data, text=True, env=ENV, capture_output=True, check=True, timeout=30,
    )
    return completed.stdout


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a mapped-root disposable namespace")


def apply_blackholes():
    for prefix in BLOCKED_V4:
        run([IP, "route", "replace", "blackhole", prefix])


def route_report(address):
    completed = subprocess.run(
        [IP, "route", "get", address], env=ENV, capture_output=True, text=True, timeout=5,
    )
    return completed.returncode, completed.stdout + completed.stderr


def route_is_open(address):
    code, report = route_report(address)
    if code != 0 or "blackhole" in report or "unreachable" in report or "Invalid argument" in report:
        return False
    return True


def assert_policy_routes():
    if not route_is_open("1.1.1.1"):
        raise RuntimeError("Public route is not usable")
    for address in ("10.1.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1"):
        if route_is_open(address):
            raise RuntimeError(f"Private address {address} is not blackholed")
    if not route_is_open("10.0.2.2"):
        raise RuntimeError("Slirp transit gateway is not reachable")


def run_route_loss():
    """Synthetic upstream. Steady state blocks the LAN. Route loss disables it."""
    namespace_check()
    work = tempfile.mkdtemp(prefix="public-route-loss-")
    run(["mount", "-t", "tmpfs", "-o", "size=8m", "tmpfs", "/run"])
    os.mkdir("/run/netns")
    run([IP, "netns", "add", "public"])
    run([IP, "link", "add", "rfegress0", "type", "veth", "peer", "name", "upstream0"])
    run([IP, "link", "set", "upstream0", "netns", "public"])
    run([IP, "link", "set", "lo", "up"])
    run([IP, "addr", "add", "10.0.2.15/24", "dev", "rfegress0"])
    run([IP, "link", "set", "rfegress0", "up"])
    run([IP, "netns", "exec", "public", IP, "link", "set", "lo", "up"])
    run([IP, "netns", "exec", "public", IP, "link", "set", "upstream0", "up"])
    run([IP, "netns", "exec", "public", IP, "addr", "add", "10.0.2.2/24", "dev", "upstream0"])
    run([IP, "netns", "exec", "public", IP, "addr", "add", "203.0.113.10/32", "dev", "lo"])
    run([IP, "netns", "exec", "public", IP, "addr", "add", "192.168.50.2/32", "dev", "lo"])
    proc_setup = (
        "open('/proc/sys/net/ipv4/ip_forward','w').write('1\\n');"
        "open('/proc/sys/net/ipv4/conf/all/rp_filter','w').write('0\\n')"
    )
    run([IP, "netns", "exec", "public", "python3", "-c", proc_setup])
    run([IP, "route", "add", "203.0.113.10/32", "via", "10.0.2.2", "dev", "rfegress0"])
    run([IP, "route", "add", "1.1.1.1/32", "via", "10.0.2.2", "dev", "rfegress0"])
    apply_blackholes()
    assert_policy_routes()
    if not route_is_open("203.0.113.10"):
        raise RuntimeError("Synthetic public route is missing")
    public_log = os.path.join(work, "public.log")
    lan_log = os.path.join(work, "lan.log")
    public_proc = subprocess.Popen(
        [IP, "netns", "exec", "public", "python3", "-u", "-c", LISTENER, "203.0.113.10", "443", public_log],
        env=ENV,
    )
    lan_proc = subprocess.Popen(
        [IP, "netns", "exec", "public", "python3", "-u", "-c", LISTENER, "192.168.50.2", "443", lan_log],
        env=ENV,
    )
    stop = threading.Event()
    try:
        _wait_file(public_log, "READY")
        _wait_file(lan_log, "READY")
        if not _connect("203.0.113.10", 443, 2):
            raise RuntimeError("Synthetic public destination was unreachable")
        if _connect("192.168.50.2", 443, 0.5):
            raise RuntimeError("Synthetic LAN was reachable while blackholed")
        _wait_file(public_log, "RECEIVED")
        if _count(lan_log) != 0:
            raise RuntimeError("Synthetic LAN received traffic while blackholed")
        for prefix in BLOCKED_V4:
            run([IP, "route", "del", "blackhole", prefix])
        if route_is_open("192.168.50.2") or _connect("192.168.50.2", 443, 0.5):
            raise RuntimeError("Removing blackholes created a LAN path without a default route")
        if not _connect("203.0.113.10", 443, 2):
            raise RuntimeError("Public /32 route failed after blackholes were removed")
        watcher = threading.Thread(target=_watch_blackhole, args=(stop,), daemon=True)
        watcher.start()
        run([IP, "route", "add", "default", "via", "10.0.2.2", "dev", "rfegress0"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not _link_down("rfegress0"):
            _connect("192.168.50.2", 443, 0.05)
        if not _link_down("rfegress0"):
            raise RuntimeError("Upstream stayed up after the blackhole disappeared")
        if _connect("192.168.50.2", 443, 0.4):
            raise RuntimeError("LAN connect succeeded after the upstream was disabled")
        leaked = _count(lan_log)
        print(f"ROUTE LOSS: upstream down; synthetic LAN deliveries during reaction={leaked}", flush=True)
    finally:
        stop.set()
        _stop(public_proc)
        _stop(lan_proc)
        subprocess.run([IP, "link", "delete", "dev", "rfegress0"], env=ENV, capture_output=True, timeout=5)
        subprocess.run([IP, "netns", "delete", "public"], env=ENV, capture_output=True, timeout=5)


def _watch_blackhole(stop):
    # Route updates wake the watcher. A poll remains because a message can
    # arrive before the socket is bound. This narrows the window; it does not
    # close it while a default route toward the forwarder exists.
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.bind((0, 0x40))
    sock.settimeout(0.05)
    try:
        while not stop.is_set():
            if route_is_open("192.168.50.2"):
                subprocess.run(
                    [IP, "link", "set", "dev", "rfegress0", "down"],
                    env=ENV, capture_output=True, timeout=5,
                )
                return
            try:
                sock.recv(65535)
            except socket.timeout:
                continue
    finally:
        sock.close()


def _connect(address, port, timeout):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def _count(path):
    try:
        with open(path, encoding="ascii") as source:
            return source.read().count("RECEIVED")
    except FileNotFoundError:
        return 0


def _wait_file(path, text):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="ascii") as source:
                if text in source.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {text}")


def _link_down(name):
    completed = subprocess.run(
        [IP, "-j", "link", "show", "dev", name],
        env=ENV, capture_output=True, text=True, timeout=5,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return True
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    if not payload:
        return True
    flags = payload[0].get("flags", [])
    return "UP" not in flags


def _stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


if __name__ == "__main__":
    import sys
    try:
        if len(sys.argv) != 2 or sys.argv[1] != "--route-loss":
            raise RuntimeError("Expected --route-loss inside a disposable namespace")
        run_route_loss()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"BLOCKED: {exc}", flush=True)
        raise SystemExit(1) from exc
