#!/usr/bin/python3
"""Disposable test owner: nonpersistent TAP fd, two closed guards, child."""
import array
import ctypes
import fcntl
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time

NFT = "/usr/sbin/nft"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
GUARDS = ("runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b")


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires disposable mapped-root namespaces")


def death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def nft(args, data=None):
    return subprocess.run([NFT, *args], input=data, env=ENV, text=True, capture_output=True, check=True, timeout=3).stdout


def consumer():
    os.fstat(int(sys.argv[2]))
    print("CONSUMER_READY", flush=True)
    while True:
        signal.pause()


def owner():
    channel = socket.socket(fileno=int(sys.argv[1]))
    policy = ""
    for index, name in enumerate(GUARDS):
        priority = -320 + index
        policy += f'create table inet {name}\n'
        for hook in ("input", "forward"):
            policy += f'add chain inet {name} {hook}_guard {{ type filter hook {hook} priority {priority}; policy accept; }}\n'
            policy += f'add rule inet {name} {hook}_guard iifname "rflabvm0" counter drop\n'
    nft(["-f", "-"], policy)
    snapshots = {name: nft(["-s", "list", "table", "inet", name]) for name in GUARDS}
    tap_fd = None
    child = None
    child_fd = None
    try:
        tap_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        # IFF_TAP | IFF_NO_PI | IFF_TUN_EXCL. Never make the TAP persistent.
        fcntl.ioctl(tap_fd, 0x400454ca, struct.pack("16sH", b"rflabvm0", 0x9002))
        parent = os.getpid()
        child = subprocess.Popen(
            [sys.executable, "-u", "tests/lab-fd-tap-owner.py", "--consumer", str(tap_fd)],
            stdout=subprocess.PIPE, pass_fds=(tap_fd,), env=ENV,
            preexec_fn=lambda: death_guard(parent),
        )
        ready, _, _ = select.select([child.stdout], [], [], 5)
        if not ready or child.stdout.readline().strip() != b"CONSUMER_READY":
            raise RuntimeError("Synthetic consumer did not start")
        child_fd = os.pidfd_open(child.pid)
        # The observer temporarily gets an explicit duplicate TAP fd for probing.
        channel.sendmsg([b"READY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [child_fd, tap_fd]))])
        while True:
            for name in GUARDS:
                try:
                    actual = nft(["-s", "list", "table", "inet", name])
                except subprocess.SubprocessError:
                    actual = ""
                if actual != snapshots[name]:
                    channel.send(b"GUARD_LOST")
                    return
            ready, _, _ = select.select([channel], [], [], 0.05)
            if ready and not channel.recv(1):
                return
            if child.poll() is not None:
                raise RuntimeError("Synthetic consumer exited unexpectedly")
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
        if child is not None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if child_fd is not None:
            os.close(child_fd)
        if tap_fd is not None:
            os.close(tap_fd)
        channel.close()


if __name__ == "__main__":
    namespace_check()
    if len(sys.argv) == 3 and sys.argv[1] == "--consumer":
        consumer()
    elif len(sys.argv) == 2:
        owner()
    else:
        raise RuntimeError("Invalid fixed test arguments")
