#!/usr/bin/python3
"""Correlated, bounded synthetic UDP experiment; not a general network relay."""
import json
import contextlib
import os
import select
import secrets
import socket
import struct
import sys
import time

ALLOWED = "198.51.100.2"
SECOND = "203.0.113.2"
DESTINATIONS = (ALLOWED, SECOND)
HOST = "198.51.100.1"
LAN = "198.51.100.3"
SOURCE = "192.0.2.2"
PORT = 34690
PAYLOAD = b"fleet-allowed"
MAX_FORWARDS = 60
REPLY = b"fleet-reply"
ID_SIZE = 8
NONCE_SIZE = 16


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def classify(frame):
    if len(frame) < 14:
        return "malformed"
    protocol = frame[12:14]
    if protocol == b"\x86\xdd":
        return "ipv6"
    if protocol != b"\x08\x00":
        return "l2"
    if len(frame) < 42:
        return "malformed"
    header = frame[14:34]
    version, _, total, _, fragment, _, ip_protocol, _, src, dst = struct.unpack("!BBHHHBBH4s4s", header)
    if version != 0x45 or ip_protocol != socket.IPPROTO_UDP or checksum(header) != 0:
        return "malformed"
    if fragment & 0x3fff:
        return "fragment"
    if socket.inet_ntoa(src) != SOURCE:
        return "spoof"
    destination = socket.inet_ntoa(dst)
    if destination == HOST:
        return "host"
    if destination == LAN:
        return "lan"
    if destination not in DESTINATIONS:
        return "destination"
    source_port, port, udp_length, udp_checksum = struct.unpack("!HHHH", frame[34:42])
    if port != PORT or source_port != 23456:
        return "port"
    if (total != 20 + udp_length or udp_length < 8 or len(frame) < 14 + total
            or udp_checksum != 0 or len(frame[42:14 + total]) != len(PAYLOAD) + ID_SIZE
            or not frame[42:14 + total].startswith(PAYLOAD)):
        return "malformed"
    return "allowed"


def reply_frame(request_id, destination=ALLOWED):
    if len(request_id) != ID_SIZE:
        raise ValueError("Invalid synthetic request identifier")
    if destination not in DESTINATIONS:
        raise ValueError("Invalid synthetic destination")
    src = socket.inet_aton(destination)
    dst = socket.inet_aton(SOURCE)
    payload = REPLY + request_id
    udp = struct.pack("!HHHH", PORT, 23456, 8 + len(payload), 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload),
                         0, 0, 64, socket.IPPROTO_UDP, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("52540055341202aabb0000010800") + header + udp + payload


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(sys.argv) != 3 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires disposable mapped-root namespace")
    with open("/proc/self/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (int(status["CapEff"].strip(), 16) != 0 or int(status["CapBnd"].strip(), 16) != 0
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Relay requires no capabilities and no_new_privs")
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        if target == "/dev/net/tun":
            raise RuntimeError("Relay must not own a TAP descriptor")
    channel = socket.socket(fileno=int(sys.argv[1]))
    stats_path = sys.argv[2]
    stats = {name: 0 for name in ("allowed", "host", "lan", "ipv6", "l2", "spoof",
                                  "fragment", "port", "destination", "malformed", "limited", "send_error",
                                  "replied", "bad_reply", "reply_timeout",
                                  "allowed_second", "replied_second")}
    buffer = bytearray()
    channel.settimeout(0.2)
    last_write = 0.0

    def save():
        temporary = stats_path + ".new"
        with open(temporary, "w", encoding="utf-8") as target:
            json.dump(stats, target)
        os.replace(temporary, stats_path)

    with contextlib.ExitStack() as stack:
        outgoing = {}
        for destination in DESTINATIONS:
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK))
            sock.connect((destination, PORT))
            outgoing[destination] = sock
        pending_until = 0.0
        pending_nonce = None
        pending_request = None
        pending_destination = None
        try:
            save()
            while True:
                try:
                    ready, _, _ = select.select([channel, *outgoing.values()], [], [], 0.2)
                    if pending_until and time.monotonic() >= pending_until:
                        pending_until = 0.0
                        pending_nonce = None
                        pending_request = None
                        pending_destination = None
                        stats["reply_timeout"] += 1
                    for destination, sock in outgoing.items():
                        if sock not in ready:
                            continue
                        data = sock.recv(1024)
                        if (pending_until and destination == pending_destination
                                and data == REPLY + pending_request + pending_nonce):
                            packet = reply_frame(pending_request, destination)
                            try:
                                channel.sendall(struct.pack("!I", len(packet)) + packet)
                            except TimeoutError as exc:
                                raise RuntimeError("QEMU socket write timed out") from exc
                            pending_until = 0.0
                            pending_nonce = None
                            pending_request = None
                            pending_destination = None
                            stats["replied"] += 1
                            if destination == SECOND:
                                stats["replied_second"] += 1
                        else:
                            stats["bad_reply"] += 1
                    if channel not in ready:
                        if time.monotonic() - last_write >= 0.25:
                            save()
                            last_write = time.monotonic()
                        continue
                    data = channel.recv(65536)
                    if not data:
                        break
                    buffer.extend(data)
                    if len(buffer) > 1048576:
                        raise RuntimeError("QEMU frame buffer exceeded")
                    while len(buffer) >= 4:
                        length = struct.unpack_from("!I", buffer)[0]
                        if length < 14 or length > 65536:
                            raise RuntimeError("Invalid QEMU frame length")
                        if len(buffer) < length + 4:
                            break
                        packet = bytes(buffer[4:4 + length])
                        del buffer[:4 + length]
                        category = classify(packet)
                        if category == "allowed":
                            if stats["allowed"] >= MAX_FORWARDS or pending_until:
                                stats["limited"] += 1
                                continue
                            try:
                                nonce = secrets.token_bytes(NONCE_SIZE)
                                request_id = packet[42 + len(PAYLOAD):42 + len(PAYLOAD) + ID_SIZE]
                                destination = socket.inet_ntoa(packet[30:34])
                                outgoing[destination].send(PAYLOAD + request_id + nonce)
                                stats["allowed"] += 1
                                if destination == SECOND:
                                    stats["allowed_second"] += 1
                                pending_nonce = nonce
                                pending_request = request_id
                                pending_destination = destination
                                pending_until = time.monotonic() + 1.0
                            except OSError:
                                stats["send_error"] += 1
                        else:
                            stats[category] += 1
                except TimeoutError:
                    pass
                if time.monotonic() - last_write >= 0.25:
                    save()
                    last_write = time.monotonic()
        finally:
            save()
            channel.close()


if __name__ == "__main__":
    main()
