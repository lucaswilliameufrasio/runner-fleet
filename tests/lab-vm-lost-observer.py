#!/usr/bin/python3
"""PID-namespace init holding the VM pidfds until deliberately lost."""
import array
import os
import socket
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def main():
    if len(sys.argv) != 4 or os.getpid() != 1:
        raise RuntimeError("Only the disposable PID namespace init may run this")
    work, slot_path, outer_fd = sys.argv[1:]
    outer = socket.socket(fileno=int(outer_fd))
    local, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    local.settimeout(10)
    supervisor = subprocess.Popen([
        sys.executable, "-u", "tests/lab-vm-crash-supervisor.py",
        work, slot_path, str(child.fileno()),
    ], pass_fds=(child.fileno(),), env=ENV)
    child.close()
    vm_fds = array.array("i")
    init_fd = None
    try:
        message, ancillary, flags, _ = local.recvmsg(32, socket.CMSG_SPACE(2 * vm_fds.itemsize))
        if message != b"READY" or flags & socket.MSG_CTRUNC:
            raise RuntimeError("Supervisor did not hand off VM handles")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                vm_fds.frombytes(data[:len(data) - (len(data) % vm_fds.itemsize)])
        if len(vm_fds) != 2:
            raise RuntimeError("Expected QEMU and controller handles")
        init_fd = os.pidfd_open(1)
        # Only the namespace-init handle leaves this PID namespace. VM pidfds do not.
        outer.sendmsg([b"READY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [init_fd]))])
        outer.recv(1)
    finally:
        if supervisor.poll() is None:
            supervisor.terminate()
        try:
            supervisor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            supervisor.kill()
            supervisor.wait(timeout=5)
        for fd in vm_fds:
            os.close(fd)
        if init_fd is not None:
            os.close(init_fd)
        local.close()
        outer.close()


if __name__ == "__main__":
    main()
