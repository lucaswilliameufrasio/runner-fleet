#!/usr/bin/python3
"""Disposable test owner attaching one nonpersistent TAP fd to QEMU."""
import array
import fcntl
import importlib.util
import os
import select
import socket
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fd_owner", "tests/lab-fd-tap-owner.py")
fd_owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fd_owner)
GUARDS = fd_owner.GUARDS
ENV = fd_owner.ENV


def main():
    fd_owner.namespace_check()
    if len(sys.argv) != 3:
        raise RuntimeError("Expected private workspace and control socket")
    work, socket_fd = sys.argv[1:]
    channel = socket.socket(fileno=int(socket_fd))
    policy = ""
    for index, name in enumerate(GUARDS):
        priority = -320 + index
        policy += f"create table inet {name}\n"
        for hook in ("input", "forward"):
            policy += f"add chain inet {name} {hook}_guard {{ type filter hook {hook} priority {priority}; policy accept; }}\n"
            policy += f'add rule inet {name} {hook}_guard iifname "rflabvm0" counter drop\n'
    fd_owner.nft(["-f", "-"], policy)
    snapshots = {name: fd_owner.nft(["-s", "list", "table", "inet", name]) for name in GUARDS}
    tap_fd = None
    qemu_fd = None
    qemu = None
    try:
        tap_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        fcntl.ioctl(tap_fd, 0x400454ca, struct.pack("16sH", b"rflabvm0", 0x9002))
        parent = os.getpid()
        with open(os.path.join(work, "qemu.log"), "w", encoding="utf-8") as output:
            qemu = subprocess.Popen([
                "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none",
                "-serial", f"file:{work}/serial.log", "-no-reboot",
                "-drive", f"file={work}/overlay.qcow2,format=qcow2,if=virtio",
                "-drive", f"file={work}/seed.img,format=raw,if=virtio,readonly=on",
                "-netdev", f"tap,id=lab,fd={tap_fd}",
                "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12",
            ], pass_fds=(tap_fd,), stdout=output, stderr=output, env=ENV,
                preexec_fn=lambda: fd_owner.death_guard(parent))
            qemu_fd = os.pidfd_open(qemu.pid)
            channel.sendmsg([b"READY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [qemu_fd]))])
            while True:
                for name in GUARDS:
                    try:
                        actual = fd_owner.nft(["-s", "list", "table", "inet", name])
                    except subprocess.SubprocessError:
                        actual = ""
                    if actual != snapshots[name]:
                        channel.send(b"GUARD_LOST")
                        return
                ready, _, _ = select.select([channel], [], [], 0.05)
                if ready and not channel.recv(1):
                    return
                if qemu.poll() is not None:
                    channel.send(b"QEMU_EXITED")
                    raise RuntimeError("QEMU exited unexpectedly")
    finally:
        if qemu is not None and qemu.poll() is None:
            qemu.terminate()
        if qemu is not None:
            try:
                qemu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait(timeout=5)
        if qemu_fd is not None:
            os.close(qemu_fd)
        if tap_fd is not None:
            os.close(tap_fd)
        channel.close()


if __name__ == "__main__":
    main()
