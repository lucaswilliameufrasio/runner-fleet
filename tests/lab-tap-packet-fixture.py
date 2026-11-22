#!/usr/bin/python3
"""Inject one synthetic Ethernet/IPv4/UDP packet into the disposable TAP."""
import fcntl
import json
import os
import select
import socket
import struct
import subprocess
import sys


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    modes = ("denied", "allowed", "denied-forward", "allowed-forward")
    if (len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1"
            or len(sys.argv) != 2 or sys.argv[1] not in modes):
        raise RuntimeError("Requires disposable namespace and a fixed packet test")
    mode = sys.argv[1]
    forward = mode.endswith("-forward")
    link = subprocess.run(["/usr/sbin/ip", "-j", "link", "show", "dev", "rflabvm0"],
                          capture_output=True, text=True, check=True, timeout=5)
    destination_mac = bytes.fromhex(json.loads(link.stdout)[0]["address"].replace(":", ""))
    source_mac = bytes.fromhex("020000000002")
    source_ip = socket.inet_aton("192.0.2.2")
    destination_ip = socket.inet_aton("198.51.100.2" if forward else "192.0.2.1")
    payload = b"fleet-test"
    udp = struct.pack("!HHHH", 23456, 34680, 8 + len(payload), 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload),
                         23, 0, 64, socket.IPPROTO_UDP, 0, source_ip, destination_ip)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    frame = destination_mac + source_mac + b"\x08\x00" + header + udp + payload
    receiver = None
    remote = None
    fd = None
    try:
        if forward:
            server = (
                "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                "s.bind(('198.51.100.2',34680)); s.settimeout(2); "
                "print('READY',flush=True); "
                "exec(\"try:\\n data,_=s.recvfrom(64)\\n print('RECEIVED' if data==b'fleet-test' else 'INVALID',flush=True)"
                "\\nexcept TimeoutError:\\n print('DENIED',flush=True)\")"
            )
            remote = subprocess.Popen(["/usr/sbin/ip", "netns", "exec", "target", sys.executable, "-u", "-c", server],
                                      stdout=subprocess.PIPE, text=True)
            if not select.select([remote.stdout], [], [], 3)[0] or remote.stdout.readline().strip() != "READY":
                raise RuntimeError("Synthetic forwarded receiver did not start")
        else:
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.bind(("192.0.2.1", 34680))
            receiver.settimeout(1)
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"rflabvm0", 0x1002))
        os.write(fd, frame)
        if forward:
            output, _ = remote.communicate(timeout=5)
            received = output.strip() == "RECEIVED"
            if remote.returncode != 0 or output.strip() not in ("RECEIVED", "DENIED"):
                raise RuntimeError("Synthetic forwarded receiver failed")
        else:
            try:
                data, _ = receiver.recvfrom(64)
                received = data == payload
            except TimeoutError:
                received = False
    finally:
        if fd is not None:
            os.close(fd)
        if receiver is not None:
            receiver.close()
        if remote is not None and remote.poll() is None:
            remote.kill()
            remote.wait(timeout=3)
    expected = mode.startswith("allowed")
    if received != expected:
        if forward:
            subprocess.run(["/usr/sbin/ip", "route", "show"], check=False)
            subprocess.run(["nstat", "-az", "IpInAddrErrors", "IpInNoRoutes", "IpInDiscards", "IpOutForwDatagrams"], check=False)
            subprocess.run(["/usr/sbin/sysctl", "net.ipv4.ip_forward",
                            "net.ipv4.conf.rflabvm0.forwarding", "net.ipv4.conf.rflabvm0.rp_filter",
                            "net.ipv4.conf.all.rp_filter"], check=False)
            subprocess.run(["/usr/sbin/nft", "list", "chain", "inet", "unrelated_fixture", "forward"], check=False)
            subprocess.run(["/usr/sbin/ip", "netns", "exec", "target", "nstat", "-az",
                            "UdpInDatagrams", "UdpInErrors", "UdpNoPorts", "IpInReceives"], check=False)
        raise RuntimeError(f"Unexpected receiver result: {received}")
    if not expected:
        result = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "chain", "inet", "runner_fleet_tap_guard",
             "forward_guard" if forward else "input_guard"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        packets = 0
        for entry in json.loads(result.stdout)["nftables"]:
            for expression in entry.get("rule", {}).get("expr", []):
                packets += expression.get("counter", {}).get("packets", 0)
        if packets < 1:
            raise RuntimeError("No packet reached the guard")
    print(f"Synthetic TAP packet: {mode}; receiver {'received' if received else 'did not receive'}.")


if __name__ == "__main__":
    main()
