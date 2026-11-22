#!/usr/bin/python3
"""Test a separately namespaced closed fence with a real disposable QEMU."""
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
GUARDS = ("runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b")
FENCE = "runner_fleet_independent_fence"


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def nft(args, data=None, namespace=None):
    command = [NFT, *args]
    if namespace is not None:
        command = [IP, "netns", "exec", namespace, *command]
    return subprocess.run(command, input=data, text=True, env=ENV, capture_output=True,
                          check=True, timeout=5).stdout


def count_fence():
    entries = json.loads(nft(["-j", "list", "chain", "inet", FENCE, "input_guard"], namespace="fence"))
    count = 0
    for entry in entries["nftables"]:
        for expression in entry.get("rule", {}).get("expr", []):
            count += expression.get("counter", {}).get("packets", 0)
    return count


def count_received(path):
    with open(path, encoding="utf-8") as source:
        return source.read().count("RECEIVED")


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
    work = tempfile.mkdtemp(prefix="independent-fence-", dir=os.path.dirname(image))
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
        run([IP, "netns", "add", "fence"])
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = nft(["-s", "list", "table", "inet", "unrelated_fixture"])
        run([IP, "link", "add", "rfbr0", "type", "bridge"])
        run([IP, "link", "add", "rfbridge0", "type", "veth", "peer", "name", "rffence0"])
        run([IP, "link", "set", "rffence0", "netns", "fence"])
        run([IP, "link", "set", "rfbridge0", "master", "rfbr0"])
        for interface in ("lo", "rfbr0", "rfbridge0"):
            run([IP, "link", "set", interface, "up"])
        run([IP, "netns", "exec", "fence", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "fence", IP, "link", "set", "rffence0", "up"])
        run([IP, "netns", "exec", "fence", IP, "addr", "add", "192.0.2.1/24", "dev", "rffence0"])
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
        run([IP, "link", "set", "rflabvm0", "master", "rfbr0"])
        run([IP, "link", "set", "rflabvm0", "up"])
        with open(host_log, "w", encoding="utf-8") as host_output:
            server = subprocess.Popen([
                IP, "netns", "exec", "fence", sys.executable, "-u", "-c",
                network.SERVER, "192.0.2.1", "34680",
            ], stdout=host_output, env=ENV)
            network.wait_text(host_log, "READY")
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            snapshots = {name: nft(["-s", "list", "table", "inet", name]) for name in GUARDS}
            channel.send(b"F")
            if channel.recv(32) != b"FROZEN":
                raise RuntimeError("Owner did not freeze with QEMU active")
            delete_guards = "".join(f"delete table inet {name}\n" for name in GUARDS)
            nft(["-f", "-"], delete_guards)
            network.wait_text(host_log, "RECEIVED", timeout=15)
            network.wait_text(serial, "FLEET_VM_HOST=OK", cursor, timeout=10)
            record("POSITIVE CONTROL: synthetic receiver got VM traffic with no guards.")
            fence_policy = (
                f"create table inet {FENCE}\n"
                f"add chain inet {FENCE} input_guard {{ type filter hook input priority -320; policy accept; }}\n"
                f"add chain inet {FENCE} forward_guard {{ type filter hook forward priority -320; policy accept; }}\n"
                f'add rule inet {FENCE} input_guard iifname "rffence0" counter drop\n'
                f'add rule inet {FENCE} forward_guard iifname "rffence0" counter drop\n'
            )
            nft(["-f", "-"], fence_policy, namespace="fence")
            nft(["-f", "-"], "\n".join(snapshots.values()))
            for name in GUARDS:
                if nft(["-s", "list", "table", "inet", name]) != snapshots[name]:
                    raise RuntimeError("Original guard restoration differed")
            time.sleep(1)
            receiver_before = count_received(host_log)
            counter_before = count_fence()
            nft(["-f", "-"], delete_guards)
            slot.mark_unknown()
            rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if rejected.returncode == 0:
                raise RuntimeError("Unknown slot admitted another attempt")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and count_fence() <= counter_before:
                time.sleep(0.2)
            counter_after = count_fence()
            if counter_after <= counter_before:
                raise RuntimeError("Independent guard did not observe a VM packet after original guard loss")
            time.sleep(3)
            receiver_after = count_received(host_log)
            if receiver_after != receiver_before:
                raise RuntimeError("Synthetic receiver got traffic after the independent fence was installed")
            channel.send(b"Q")
            if channel.recv(32) != b"LIVE":
                raise RuntimeError("QEMU was not alive after guard loss")
            record(f"DUAL LOSS: independent guard counter {counter_before}->{counter_after}; receiver unchanged at {receiver_after}.")
            record("ADMISSION: UNKNOWN blocked another reservation while QEMU remained alive.")
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
                raise RuntimeError("Owned nonpersistent TAP remained")
            try:
                slot.release(boundary, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Slot released before network and disk cleanup")
            network.stop(server)
            run([IP, "link", "delete", "dev", "rfbridge0"])
            run([IP, "link", "delete", "dev", "rfbr0"])
            run([IP, "netns", "delete", "fence"])
            if nft(["-s", "list", "table", "inet", "unrelated_fixture"]) != unrelated:
                raise RuntimeError("Unrelated table changed")
            os.unlink(overlay)
            os.unlink(seed)
            slot.release(boundary, overlay, seed)
            accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if accepted.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Admission did not resume after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            record("CLEANUP: namespace exit and owned resources verified; unrelated table preserved; slot EMPTY.")
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
