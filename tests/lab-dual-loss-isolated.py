#!/usr/bin/python3
"""Inject dual firewall loss and observer death with a real disposable VM."""
import array
import ctypes
import importlib.util
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("lab_vm_network", "tests/lab-vm-network-isolated.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
spec = importlib.util.spec_from_file_location("lab_vm_slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP = network.IP
NFT = network.NFT
ENV = network.SAFE_ENV
run = network.run


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


class NamespaceExitProof:
    def __init__(self, init_fd, launcher):
        self.init_fd = init_fd
        self.launcher = launcher

    def poll(self):
        if self.launcher.poll() is None or not select.select([self.init_fd], [], [], 0)[0]:
            return None
        return self.launcher.returncode


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires a verified image")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="dual-loss-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    events = os.path.join(work, "events.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    launcher = None
    init_fd = None
    channel = None
    server = None
    boundary_confirmed = False

    def record(message):
        print(message, flush=True)
        with open(events, "a", encoding="utf-8") as output:
            print(message, file=output, flush=True)

    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = run([NFT, "-s", "list", "table", "inet", "unrelated_fixture"]).stdout
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-vm-network-config", seed,
             "tests/lab-vm-network-user-data", "tests/lab-vm-network-meta-data"])
        channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(10)
        parent = os.getpid()
        launcher = subprocess.Popen([
            "unshare", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--",
            sys.executable, "-u", "tests/lab-dual-loss-observer.py",
            work, slot_path, str(child_channel.fileno()),
        ], pass_fds=(child_channel.fileno(),), env=ENV,
            preexec_fn=lambda: parent_death_guard(parent))
        child_channel.close()
        message, ancillary, flags, _ = channel.recvmsg(32, socket.CMSG_SPACE(array.array("i").itemsize))
        received = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received.frombytes(data[:len(data) - (len(data) % received.itemsize)])
        if message != b"READY" or flags & socket.MSG_CTRUNC or len(received) != 1:
            raise RuntimeError("Observer did not provide only its namespace-init handle")
        init_fd = received[0]
        slot.activate()
        run([IP, "link", "set", "lo", "up"])
        run([IP, "link", "set", "rflabvm0", "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflabvm0"])
        with open(host_log, "w", encoding="utf-8") as host_output:
            server = subprocess.Popen([sys.executable, "-u", "-c", network.SERVER, "192.0.2.1", "34680"],
                                      stdout=host_output, env=ENV)
            network.wait_text(host_log, "READY")
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            network.wait_text(serial, "FLEET_VM_HOST=DENIED", cursor, timeout=10)
            with open(host_log, encoding="utf-8") as source:
                if "RECEIVED" in source.read():
                    raise RuntimeError("Synthetic host received traffic before fault injection")
            channel.send(b"F")
            if channel.recv(32) != b"FROZEN":
                raise RuntimeError("Owner did not freeze with QEMU active")
            record("BASELINE: VM active; host blocked; owner frozen for fault injection.")
            transaction = (
                "delete table inet runner_fleet_fd_guard_a\n"
                "delete table inet runner_fleet_fd_guard_b\n"
            )
            subprocess.run([NFT, "-f", "-"], input=transaction, text=True, env=ENV,
                           capture_output=True, check=True, timeout=5)
            guards_lost = time.monotonic()
            record("FAULT: both firewall guards deleted in one transaction.")
            network.wait_text(host_log, "RECEIVED", timeout=8)
            elapsed = time.monotonic() - guards_lost
            record(f"ISOLATION_FAILURE: synthetic host received VM traffic {elapsed:.2f}s after guard deletion.")
            channel.send(b"Q")
            if channel.recv(32) != b"LIVE":
                raise RuntimeError("QEMU was not alive immediately before observer loss")
            record("FAULT: QEMU confirmed alive with both guards absent immediately before observer loss.")
            rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if rejected.returncode == 0:
                raise RuntimeError("Active slot admitted another attempt")
            signal.pidfd_send_signal(init_fd, signal.SIGKILL)
            if not select.select([init_fd], [], [], 10)[0]:
                raise RuntimeError("PID namespace init did not exit")
            launcher.wait(timeout=10)
            boundary = NamespaceExitProof(init_fd, launcher)
            if boundary.poll() is None:
                raise RuntimeError("PID namespace termination not confirmed")
            boundary_confirmed = True
            links = json.loads(run([IP, "-j", "link", "show"]).stdout)
            if any(entry["ifname"] == "rflabvm0" for entry in links):
                raise RuntimeError("TAP remained after namespace termination")
            recovered = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "recover", slot_path],
                                       env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if recovered.returncode != 0 or recovered.stdout.strip() != "SLOT UNKNOWN":
                raise RuntimeError("Recovery did not persist UNKNOWN")
            rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if rejected.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown slot admitted another attempt")
            try:
                slot.release(None, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Missing VM boundary unexpectedly allowed release")
            record("RECOVERY: observer lost; namespace exit confirmed; UNKNOWN blocked admission.")
            network.stop(server)
            if run([NFT, "-s", "list", "table", "inet", "unrelated_fixture"]).stdout != unrelated:
                raise RuntimeError("Unrelated table changed")
            os.unlink(overlay)
            os.unlink(seed)
            slot.release(boundary, overlay, seed)
            accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if accepted.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Admission did not resume after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            record("CLEANUP: namespace and resources verified; unrelated table preserved; slot EMPTY.")
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        if init_fd is not None:
            if not select.select([init_fd], [], [], 0)[0]:
                try:
                    signal.pidfd_send_signal(init_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if launcher is not None:
                try:
                    launcher.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    network.stop(launcher)
            os.close(init_fd)
        elif launcher is not None:
            network.stop(launcher)
        network.stop(server)
        if channel is not None:
            channel.close()
        if not boundary_confirmed:
            print("Namespace exit unconfirmed; slot and disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
