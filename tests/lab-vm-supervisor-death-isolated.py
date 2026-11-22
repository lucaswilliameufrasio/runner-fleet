#!/usr/bin/python3
"""VM supervisor SIGKILL/recovery experiment, in disposable namespaces only."""
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


class ReapedPidfd:
    def __init__(self, result):
        self.result = result

    def poll(self):
        return self.result.si_status


def wait_exited(fd, timeout=10):
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        raise RuntimeError("Owned process did not exit")
    result = os.waitid(os.P_PIDFD, fd, os.WEXITED)
    if result is None:
        raise RuntimeError("Could not reap owned process")
    return result


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires a verified image")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot become child subreaper")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="supervisor-death-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    target_log = os.path.join(work, "target-receiver.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    supervisor = None
    qemu_fd = None
    controller_fd = None
    qemu_reaped = None
    controller_reaped = None
    servers = []
    parent_channel = None
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
            supervisor = subprocess.Popen([
                sys.executable, "-u", "tests/lab-vm-crash-supervisor.py",
                work, slot_path, str(child_channel.fileno()),
            ], pass_fds=(child_channel.fileno(),), env=ENV)
            child_channel.close()
            message, ancillary, flags, _ = parent_channel.recvmsg(32, socket.CMSG_SPACE(2 * array.array("i").itemsize))
            if message != b"READY" or flags & socket.MSG_CTRUNC:
                raise RuntimeError("Supervisor did not transfer process handles")
            received = array.array("i")
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received.frombytes(data[:len(data) - (len(data) % received.itemsize)])
            if len(received) != 2:
                raise RuntimeError("Expected exactly two process handles")
            qemu_fd, controller_fd = received
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            cursor = network.wait_text(serial, "FLEET_VM_TARGET=OK", cursor, timeout=15)
            cursor, flow_id = network.wait_match(serial, r"FLEET_VM_FLOW_OK=(\d+)", cursor, timeout=10)
            network.wait_text(target_log, "RECEIVED")
            if select.select([qemu_fd], [], [], 0)[0] or slot.state() != "ACTIVE":
                raise RuntimeError("Expected an active VM and slot before failure")
            blocked = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                     env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if blocked.returncode == 0:
                raise RuntimeError("Duplicate admission while active")
            print(f"VM: flow {flow_id} active; supervisor owns QEMU and duplicate admission blocked.", flush=True)
            supervisor.kill()
            supervisor.wait(timeout=5)
            qemu_result = wait_exited(qemu_fd)
            qemu_reaped = ReapedPidfd(qemu_result)
            controller_reaped = wait_exited(controller_fd)
            if qemu_result.si_code != os.CLD_KILLED or qemu_result.si_status != signal.SIGKILL:
                raise RuntimeError("QEMU did not stop through parent-death SIGKILL")
            if controller_reaped.si_code != os.CLD_KILLED or controller_reaped.si_status != signal.SIGKILL:
                raise RuntimeError("Controller did not stop through parent-death SIGKILL")
            print("VM: supervisor SIGKILL caused QEMU and controller SIGKILL; both pidfds reaped.", flush=True)
            recovered = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "recover", slot_path],
                                       env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if recovered.returncode != 0 or recovered.stdout.strip() != "SLOT UNKNOWN":
                raise RuntimeError("Separate recovery did not mark UNKNOWN")
            blocked = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                     env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if blocked.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown state did not block admission")
            try:
                slot.release(None, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Missing QEMU handle unexpectedly allowed release")
            try:
                slot.release(qemu_reaped, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Residual resources unexpectedly allowed release")
            print("Recovery: UNKNOWN persisted; admission and cleanup without proof refused.", flush=True)
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
            slot.release(qemu_reaped, overlay, seed)
            reserved = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if reserved.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Admission was not restored after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            print("Recovery: cleanup verified, unrelated table preserved, admission re-enabled.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        if supervisor is not None:
            network.stop(supervisor)
        for fd, reaped in ((qemu_fd, qemu_reaped), (controller_fd, controller_reaped)):
            if fd is not None:
                if reaped is None:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        wait_exited(fd)
                    except (ChildProcessError, RuntimeError):
                        pass
                os.close(fd)
        for server in servers:
            network.stop(server)
        if parent_channel is not None:
            parent_channel.close()
        # If no process handle arrived, retain disks instead of guessing ownership.
        if qemu_reaped is not None:
            for path in (overlay, seed):
                if os.path.isfile(path):
                    os.unlink(path)
        else:
            print("VM identity or exit unconfirmed; disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
