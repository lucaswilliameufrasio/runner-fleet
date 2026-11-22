#!/usr/bin/python3
"""Closed QEMU socket backend: consume and discard, with no TAP descriptor."""
import json
import os
import socket
import struct
import sys
import time


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(sys.argv) != 3 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Only a disposable mapped-root namespace is supported")
    with open("/proc/self/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (int(status["CapEff"].strip(), 16) != 0 or int(status["CapBnd"].strip(), 16) != 0
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Socket sink must have no capabilities and no_new_privs")
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        if target == "/dev/net/tun":
            raise RuntimeError("Socket sink must not hold a TAP descriptor")
    channel = socket.socket(fileno=int(sys.argv[1]))
    stats_path = sys.argv[2]
    stats = {"IPv4": 0, "IPv6": 0, "L2": 0, "other": 0}
    buffer = bytearray()
    channel.settimeout(0.2)
    last_write = 0.0

    def save():
        temporary = stats_path + ".new"
        with open(temporary, "w", encoding="utf-8") as target:
            json.dump(stats, target)
        os.replace(temporary, stats_path)

    try:
        save()
        while True:
            try:
                data = channel.recv(65536)
                if not data:
                    break
                buffer.extend(data)
                if len(buffer) > 1048576:
                    raise RuntimeError("QEMU socket frame buffer exceeded")
                while len(buffer) >= 4:
                    length = struct.unpack_from("!I", buffer)[0]
                    if length < 14 or length > 65536:
                        raise RuntimeError("Invalid QEMU socket frame length")
                    if len(buffer) < length + 4:
                        break
                    frame = bytes(buffer[4:4 + length])
                    del buffer[:4 + length]
                    protocol = frame[12:14]
                    name = {b"\x08\x00": "IPv4", b"\x86\xdd": "IPv6", b"\x88\xb5": "L2"}.get(protocol, "other")
                    stats[name] += 1
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
