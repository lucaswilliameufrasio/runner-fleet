#!/usr/bin/python3
"""Unprivileged line-to-seqpacket adapter for the disposable VM experiment."""
import os
import socket
import sys


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    with open("/proc/self/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (len(sys.argv) != 3 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0"
            or fields[2] != "1" or int(status["CapEff"].strip(), 16)
            or int(status["CapBnd"].strip(), 16) or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Requires disposable namespace and no capabilities")
    serial = socket.socket(fileno=int(sys.argv[1]))
    broker = socket.socket(fileno=int(sys.argv[2]))
    broker.settimeout(3)
    with serial, broker:
        pending = bytearray()
        while True:
            data = serial.recv(1024)
            if not data:
                return
            pending.extend(data)
            if len(pending) > 1024:
                raise RuntimeError("Request buffer limit exceeded")
            while b"\n" in pending:
                line, _, remainder = pending.partition(b"\n")
                pending = bytearray(remainder)
                if not line or len(line) > 128:
                    raise RuntimeError("Invalid request frame")
                broker.sendall(line)
                answer = broker.recv(1025)
                if not answer or len(answer) > 1024 or b"\n" in answer:
                    raise RuntimeError("Invalid broker response")
                serial.sendall(answer + b"\n")


if __name__ == "__main__":
    main()
