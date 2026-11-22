#!/usr/bin/python3
"""Closed fd-owned TAP and real QEMU failure scenarios in disposable namespaces."""
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
TABLES = ("runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b")
run = network.run


def owner_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def table(name):
    return run([NFT, "-s", "list", "table", "inet", name]).stdout


def delete_unchanged(name, expected):
    if table(name) != expected:
        raise RuntimeError("Changed table: refusing cleanup")
    run([NFT, "delete", "table", "inet", name])


def tap_absent():
    links = json.loads(run([IP, "-j", "link", "show"]).stdout)
    return all(entry["ifname"] != "rflabvm0" for entry in links)


def guard_saw_packet():
    entries = json.loads(run([NFT, "-j", "list", "chain", "inet", TABLES[0], "input_guard"]).stdout)
    count = 0
    for entry in entries["nftables"]:
        for expression in entry.get("rule", {}).get("expr", []):
            count += expression.get("counter", {}).get("packets", 0)
    return count > 0


class ExitedQemu:
    def __init__(self, owner, pidfd):
        self.owner = owner
        self.pidfd = pidfd

    def poll(self):
        if self.owner.poll() is None or not select.select([self.pidfd], [], [], 0)[0]:
            return None
        return 0


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 3 or sys.argv[2] not in ("guard-loss", "owner-death"):
        raise RuntimeError("Requires verified image and fixed failure scenario")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot become child subreaper")
    image = os.path.realpath(sys.argv[1])
    scenario = sys.argv[2]
    work = tempfile.mkdtemp(prefix=f"fd-vm-{scenario}-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    owner = None
    channel = None
    qemu_fd = None
    server = None
    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = table("unrelated_fixture")
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-vm-network-config", seed,
             "tests/lab-vm-network-user-data", "tests/lab-vm-network-meta-data"])
        channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(10)
        parent = os.getpid()
        owner = subprocess.Popen([
            sys.executable, "-u", "tests/lab-fd-tap-qemu-owner.py", work, str(child_channel.fileno()),
        ], pass_fds=(child_channel.fileno(),), env=ENV, preexec_fn=lambda: owner_death_guard(parent))
        child_channel.close()
        message, ancillary, flags, _ = channel.recvmsg(32, socket.CMSG_SPACE(array.array("i").itemsize))
        received = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received.frombytes(data[:len(data) - (len(data) % received.itemsize)])
        if message != b"READY" or flags & socket.MSG_CTRUNC or len(received) != 1:
            raise RuntimeError("Owner did not hand off QEMU pidfd")
        qemu_fd = received[0]
        time.sleep(0.5)
        if select.select([qemu_fd], [], [], 0)[0]:
            raise RuntimeError(f"QEMU exited during startup; inspect {work}/qemu.log")
        slot.activate()
        links = json.loads(run([IP, "-j", "-d", "link", "show", "dev", "rflabvm0"]).stdout)
        info = links[0].get("linkinfo", {}).get("info_data", {})
        if info.get("type") != "tap" or info.get("persist", False):
            raise RuntimeError("Expected a nonpersistent TAP")
        run([IP, "link", "set", "lo", "up"])
        run([IP, "link", "set", "rflabvm0", "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflabvm0"])
        with open(host_log, "w", encoding="utf-8") as output:
            server = subprocess.Popen([sys.executable, "-u", "-c", network.SERVER, "192.0.2.1", "34680"],
                                      stdout=output, env=ENV)
            network.wait_text(host_log, "READY")
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            network.wait_text(serial, "FLEET_VM_HOST=DENIED", cursor, timeout=15)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not guard_saw_packet():
                time.sleep(0.2)
            if not guard_saw_packet():
                raise RuntimeError("VM packets did not reach the first input guard")
            with open(host_log, encoding="utf-8") as source:
                if "RECEIVED" in source.read():
                    raise RuntimeError("Protected host receiver got traffic")
            if select.select([qemu_fd], [], [], 0)[0]:
                raise RuntimeError("QEMU was not alive before fault injection")
            original = {name: table(name) for name in TABLES}
            print("VM: nonpersistent TAP passed by fd; host denied with guard counter evidence.", flush=True)
            if scenario == "guard-loss":
                run([NFT, "delete", "table", "inet", TABLES[0]])
                if channel.recv(32) != b"GUARD_LOST":
                    raise RuntimeError("Guard loss was not detected")
                owner.wait(timeout=10)
                if owner.returncode != 0:
                    raise RuntimeError("Owner failed during guard loss shutdown")
                if not select.select([qemu_fd], [], [], 5)[0]:
                    raise RuntimeError("QEMU did not exit after guard loss")
                if table(TABLES[1]) != original[TABLES[1]]:
                    raise RuntimeError("Independent guard changed")
                print("VM: guard loss detected, QEMU exited and second guard retained.", flush=True)
            else:
                owner.kill()
                owner.wait(timeout=5)
                if not select.select([qemu_fd], [], [], 5)[0]:
                    raise RuntimeError("QEMU survived owner death")
                result = os.waitid(os.P_PIDFD, qemu_fd, os.WEXITED)
                if result.si_code != os.CLD_KILLED or result.si_status != signal.SIGKILL:
                    raise RuntimeError("Expected QEMU parent-death SIGKILL")
                print("VM: owner SIGKILL caused QEMU SIGKILL; pidfd was reaped.", flush=True)
            if not tap_absent():
                raise RuntimeError("TAP remained after all owner and QEMU fds closed")
            slot.mark_unknown()
            rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if rejected.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown slot admitted another VM")
            print("VM: nonpersistent TAP disappeared; slot UNKNOWN blocked admission.", flush=True)
            network.stop(server)
            os.unlink(overlay)
            os.unlink(seed)
            proof = ExitedQemu(owner, qemu_fd)
            try:
                slot.release(proof, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Slot released while guard resources remained")
            if scenario == "guard-loss":
                # Replacements are created only by this test fixture.
                run([IP, "tuntap", "add", "dev", "rflabvm0", "mode", "tap"])
                run([NFT, "add", "table", "inet", TABLES[0]])
                run([NFT, "add", "chain", "inet", TABLES[0], "foreign"])
                try:
                    delete_unchanged(TABLES[0], original[TABLES[0]])
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Foreign replacement guard was removed")
                try:
                    slot.release(proof, overlay, seed)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Foreign same-name TAP was accepted as clean")
                if tap_absent():
                    raise RuntimeError("Foreign TAP unexpectedly removed")
                print("Recovery: replacement TAP and changed guard preserved; admission blocked.", flush=True)
                run([IP, "tuntap", "del", "dev", "rflabvm0", "mode", "tap"])
                run([NFT, "delete", "table", "inet", TABLES[0]])
                delete_unchanged(TABLES[1], original[TABLES[1]])
            else:
                for name in TABLES:
                    delete_unchanged(name, original[name])
            if table("unrelated_fixture") != unrelated:
                raise RuntimeError("Unrelated firewall table changed")
            slot.release(proof, overlay, seed)
            if slot.state() != "EMPTY":
                raise RuntimeError("Slot did not become empty")
            accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if accepted.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Admission was not restored after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            print("Recovery: owned resources checked, unrelated table intact, admission re-enabled.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait(timeout=5)
        if qemu_fd is not None:
            if not select.select([qemu_fd], [], [], 0)[0]:
                try:
                    signal.pidfd_send_signal(qemu_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.waitid(os.P_PIDFD, qemu_fd, os.WEXITED | os.WNOHANG)
            except ChildProcessError:
                pass
            os.close(qemu_fd)
        network.stop(server)
        if channel is not None:
            channel.close()
        if os.path.exists(overlay) or os.path.exists(seed):
            print("VM disks retained for conservative recovery.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
