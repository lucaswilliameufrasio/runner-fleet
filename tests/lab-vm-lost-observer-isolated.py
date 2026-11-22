#!/usr/bin/python3
"""Lose the VM observer/pidfds; recover only via a separate PID namespace."""
import array
import ctypes
import importlib.util
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("lab_vm_network", "tests/lab-vm-network-isolated.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
slot_spec = importlib.util.spec_from_file_location("lab_vm_slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(slot_spec)
slot_spec.loader.exec_module(slot_module)
IP = network.IP
NFT = network.NFT
ENV = network.SAFE_ENV
run = network.run


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


class NamespaceExitProof:
    """Test-only proof for a PID namespace init and its waited launcher."""
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
    work = tempfile.mkdtemp(prefix="observer-loss-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    target_log = os.path.join(work, "target-receiver.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    launcher = None
    init_fd = None
    boundary_confirmed = False
    parent_channel = None
    servers = []
    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "target"])
        run([NFT, "add", "table", "inet", "vm_unrelated_fixture"])
        run([NFT, "-f", "scripts/lab-network-closed.nft"])
        run([NFT, "-f", "scripts/lab-network-synthetic-egress.nft"])
        run([NFT, "-f", "scripts/lab-network-lease-guard.nft"])
        run([IP, "tuntap", "add", "dev", "rflab0", "mode", "tap"])
        run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        run([IP, "link", "set", "target0", "netns", "target"])
        for interface in ("lo", "rflab0", "rftarget0"):
            run([IP, "link", "set", interface, "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflab0"])
        run([IP, "addr", "add", "198.51.100.1/24", "dev", "rftarget0"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
        run([IP, "netns", "exec", "target", IP, "addr", "add", "198.51.100.2/24", "dev", "target0"])
        run([IP, "netns", "exec", "target", IP, "route", "add", "default", "via", "198.51.100.1"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        with open(host_log, "w", encoding="utf-8") as host_output, open(target_log, "w", encoding="utf-8") as target_output:
            servers.append(subprocess.Popen([sys.executable, "-u", "-c", network.SERVER, "192.0.2.1", "34680"], stdout=host_output, env=ENV))
            servers.append(subprocess.Popen([IP, "netns", "exec", "target", sys.executable, "-u", "-c", network.SERVER, "198.51.100.2", "34679"], stdout=target_output, env=ENV))
            network.wait_text(host_log, "READY")
            network.wait_text(target_log, "READY")
            run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
            run(["cloud-localds", "-N", "tests/lab-vm-network-config", seed,
                 "tests/lab-vm-network-user-data", "tests/lab-vm-network-meta-data"])
            run([NFT, "add", "element", "inet", "runner_fleet_lab_lease", "permits",
                 "{", "192.0.2.2", "timeout", "3s", "}"])
            parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent_channel.settimeout(10)
            parent = os.getpid()
            launcher = subprocess.Popen([
                "unshare", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--",
                sys.executable, "-u", "tests/lab-vm-lost-observer.py",
                work, slot_path, str(child_channel.fileno()),
            ], pass_fds=(child_channel.fileno(),), env=ENV,
                preexec_fn=lambda: parent_death_guard(parent))
            child_channel.close()
            message, ancillary, flags, _ = parent_channel.recvmsg(32, socket.CMSG_SPACE(array.array("i").itemsize))
            if message != b"READY" or flags & socket.MSG_CTRUNC:
                raise RuntimeError("Observer did not hand off namespace-init handle")
            received = array.array("i")
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received.frombytes(data[:len(data) - (len(data) % received.itemsize)])
            if len(received) != 1:
                raise RuntimeError("Expected only the namespace-init handle")
            init_fd = received[0]
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            cursor = network.wait_text(serial, "FLEET_VM_TARGET=OK", cursor, timeout=15)
            _, flow_id = network.wait_match(serial, r"FLEET_VM_FLOW_OK=(\d+)", cursor, timeout=10)
            if slot.state() != "ACTIVE" or select.select([init_fd], [], [], 0)[0]:
                raise RuntimeError("Expected active VM and living namespace init")
            print(f"VM: flow {flow_id} active; QEMU pidfds confined to the disposable PID namespace.", flush=True)
            signal.pidfd_send_signal(init_fd, signal.SIGKILL)
            if not select.select([init_fd], [], [], 10)[0]:
                raise RuntimeError("PID namespace init did not exit")
            launcher.wait(timeout=10)
            boundary = NamespaceExitProof(init_fd, launcher)
            if boundary.poll() is None:
                raise RuntimeError("Namespace boundary exit not confirmed")
            boundary_confirmed = True
            print("Observer and VM pidfds lost; PID namespace init termination confirmed.", flush=True)
            recovered = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "recover", slot_path],
                                       env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if recovered.returncode != 0 or recovered.stdout.strip() != "SLOT UNKNOWN":
                raise RuntimeError("Recovery did not retain UNKNOWN")
            blocked = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                     env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if blocked.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown state admitted another execution")
            try:
                slot.release(None, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Missing VM handle unexpectedly allowed release")
            print("Recovery: UNKNOWN blocked admission and missing VM handle refused.", flush=True)
            for server in servers:
                network.stop(server)
            run([IP, "tuntap", "del", "dev", "rflab0", "mode", "tap"])
            run([IP, "link", "delete", "dev", "rftarget0"])
            run([IP, "netns", "delete", "target"])
            run([NFT, "delete", "table", "inet", "runner_fleet_lab_closed"])
            run([NFT, "delete", "table", "inet", "runner_fleet_lab_lease"])
            run([NFT, "list", "table", "inet", "vm_unrelated_fixture"])
            os.unlink(overlay)
            os.unlink(seed)
            try:
                slot.release(None, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Cleanup without process-boundary proof was accepted")
            slot.release(boundary, overlay, seed)
            reserved = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if reserved.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Admission did not recover after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            print("Recovery: namespace exit and cleanup verified; admission re-enabled.", flush=True)
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
        for server in servers:
            network.stop(server)
        if parent_channel is not None:
            parent_channel.close()
        if not boundary_confirmed:
            print("Namespace exit unconfirmed; slot and VM disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
