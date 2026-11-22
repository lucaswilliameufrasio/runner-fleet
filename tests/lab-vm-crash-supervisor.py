#!/usr/bin/python3
"""Own a test QEMU and hand pidfds to a trusted disposable test observer."""
import array
import ctypes
import importlib.util
import os
import select
import signal
import socket
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(sys.argv) != 4 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a disposable mapped-root namespace")
    work, slot_path, fd_text = sys.argv[1:]
    channel = socket.socket(fileno=int(fd_text))
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("lab_vm_slot", "tests/lab-vm-slot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    slot = module.Slot(slot_path)
    parent = os.getpid()
    qemu = None
    controller = None
    fds = []
    try:
        qemu = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none",
            "-serial", f"file:{work}/serial.log", "-no-reboot",
            "-drive", f"file={work}/overlay.qcow2,format=qcow2,if=virtio",
            "-drive", f"file={work}/seed.img,format=raw,if=virtio,readonly=on",
            "-netdev", "tap,id=lab,ifname=rflab0,script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12",
        ], env=ENV, preexec_fn=lambda: parent_death_guard(parent))
        fds.append(os.pidfd_open(qemu.pid))
        slot.activate()
        controller = subprocess.Popen([
            sys.executable, "-u", "tests/lab-vm-slot.py", "run", slot_path,
        ], stdout=subprocess.PIPE, env=ENV, preexec_fn=lambda: parent_death_guard(parent))
        fds.append(os.pidfd_open(controller.pid))
        ready, _, _ = select.select([controller.stdout], [], [], 5)
        if not ready or controller.stdout.readline().strip() != b"CONTROLLER_READY":
            raise RuntimeError("Controller did not become ready")
        channel.sendmsg([b"READY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
        channel.recv(1)
    finally:
        stop(controller)
        stop(qemu)
        for fd in fds:
            os.close(fd)
        channel.close()


if __name__ == "__main__":
    main()
