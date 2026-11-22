#!/usr/bin/python3
"""PID-namespace observer used only by the dual-guard-loss experiment."""
import array
import os
import select
import signal
import socket
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def main():
    if len(sys.argv) != 4 or os.getpid() != 1:
        raise RuntimeError("Requires the disposable PID namespace init")
    work, slot_path, outer_fd = sys.argv[1:]
    outer = socket.socket(fileno=int(outer_fd))
    local, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    local.settimeout(10)
    owner = subprocess.Popen([
        sys.executable, "-u", "tests/lab-fd-tap-qemu-owner.py", work, str(child.fileno())
    ], pass_fds=(child.fileno(),), env=ENV)
    child.close()
    qemu_fds = array.array("i")
    init_fd = None
    owner_fd = None
    try:
        message, ancillary, flags, _ = local.recvmsg(32, socket.CMSG_SPACE(qemu_fds.itemsize))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                qemu_fds.frombytes(data[:len(data) - (len(data) % qemu_fds.itemsize)])
        if message != b"READY" or flags & socket.MSG_CTRUNC or len(qemu_fds) != 1:
            raise RuntimeError("Owner did not transfer QEMU pidfd")
        init_fd = os.pidfd_open(1)
        owner_fd = os.pidfd_open(owner.pid)
        # No QEMU or owner pidfd leaves the PID namespace.
        outer.sendmsg([b"READY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [init_fd]))])
        if outer.recv(1) != b"F":
            raise RuntimeError("Invalid test request")
        signal.pidfd_send_signal(owner_fd, signal.SIGSTOP)
        stopped = os.waitid(os.P_PIDFD, owner_fd, os.WSTOPPED)
        if stopped is None or stopped.si_code != os.CLD_STOPPED or select.select([qemu_fds[0]], [], [], 0)[0]:
            raise RuntimeError("Owner was not stopped with QEMU alive")
        outer.send(b"FROZEN")
        while True:
            request = outer.recv(1)
            if request != b"Q":
                break
            outer.send(b"DEAD" if select.select([qemu_fds[0]], [], [], 0)[0] else b"LIVE")
    finally:
        if owner_fd is not None:
            try:
                signal.pidfd_send_signal(owner_fd, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if owner.poll() is None:
            owner.terminate()
        try:
            owner.wait(timeout=5)
        except subprocess.TimeoutExpired:
            owner.kill()
            owner.wait(timeout=5)
        for fd in qemu_fds:
            os.close(fd)
        if owner_fd is not None:
            os.close(owner_fd)
        if init_fd is not None:
            os.close(init_fd)
        local.close()
        outer.close()


if __name__ == "__main__":
    main()
