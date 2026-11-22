#!/usr/bin/python3
"""Real VM path and fence-loss tests in disposable namespaces only."""
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
L2_SERVER = """
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5))
s.bind(("rfbr0", 0))
print("READY", flush=True)
while True:
    frame = s.recv(2048)
    if frame[12:14] == bytes.fromhex("88b5") and b"fleet-l2-probe" in frame:
        print("RECEIVED", flush=True)
"""
V6_SERVER = network.SERVER.replace("s = socket.socket()", "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)")


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def fence_nft(args, data=None):
    return subprocess.run([IP, "netns", "exec", "fence", NFT, *args], input=data, text=True,
                          env=ENV, capture_output=True, check=True, timeout=5).stdout


def fence_count():
    entries = json.loads(fence_nft(["-j", "list", "chain", "inet", FENCE, "input_guard"]))
    count = 0
    for entry in entries["nftables"]:
        for expression in entry.get("rule", {}).get("expr", []):
            count += expression.get("counter", {}).get("packets", 0)
    return count


def received(path):
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
    if len(sys.argv) != 3 or sys.argv[2] not in ("mutate", "delete"):
        raise RuntimeError("Requires verified image and fixed fault scenario")
    image = os.path.realpath(sys.argv[1])
    mode = sys.argv[2]
    work = tempfile.mkdtemp(prefix=f"boundary-paths-{mode}-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    events = os.path.join(work, "events.log")
    logs = {name: os.path.join(work, name + ".log") for name in ("side4", "side6", "l2", "fence")}
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    launcher = None
    init_fd = None
    channel = None
    watcher = None
    servers = []
    outputs = []
    boundary_confirmed = False

    def record(message):
        print(message, flush=True)
        with open(events, "a", encoding="utf-8") as target:
            print(message, file=target, flush=True)

    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "fence"])
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = run([NFT, "-s", "list", "table", "inet", "unrelated_fixture"]).stdout
        run([IP, "link", "add", "rfbr0", "type", "bridge"])
        run([IP, "link", "set", "dev", "rfbr0", "address", "02:aa:bb:00:00:01"])
        run([IP, "link", "add", "rfbridge0", "type", "veth", "peer", "name", "rffence0"])
        run([IP, "link", "set", "rffence0", "netns", "fence"])
        run([IP, "link", "set", "rfbridge0", "master", "rfbr0"])
        for interface in ("lo", "rfbr0", "rfbridge0"):
            run([IP, "link", "set", interface, "up"])
        run([IP, "addr", "add", "192.0.2.3/24", "dev", "rfbr0"])
        run([IP, "-6", "addr", "add", "fd42:1234:5678::1/64", "dev", "rfbr0", "nodad"])
        run([IP, "netns", "exec", "fence", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "fence", IP, "link", "set", "rffence0", "up"])
        run([IP, "netns", "exec", "fence", IP, "addr", "add", "192.0.2.1/24", "dev", "rffence0"])
        fence_policy = (
            f"create table inet {FENCE}\n"
            f"add chain inet {FENCE} input_guard {{ type filter hook input priority -320; policy accept; }}\n"
            f"add chain inet {FENCE} forward_guard {{ type filter hook forward priority -320; policy accept; }}\n"
            f'add rule inet {FENCE} input_guard iifname "rffence0" counter drop\n'
            f'add rule inet {FENCE} forward_guard iifname "rffence0" counter drop\n'
        )
        fence_nft(["-f", "-"], fence_policy)
        expected = fence_nft(["-s", "list", "table", "inet", FENCE])
        with open("/run/fleet-fence-expected", "w", encoding="utf-8") as target:
            target.write(expected)
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-boundary-network-config", seed,
             "tests/lab-boundary-user-data", "tests/lab-vm-network-meta-data"])
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
        handles = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                handles.frombytes(data[:len(data) - (len(data) % handles.itemsize)])
        if message != b"READY" or flags & socket.MSG_CTRUNC or len(handles) != 1:
            raise RuntimeError("Observer did not provide only namespace-init pidfd")
        init_fd = handles[0]
        slot.activate()
        run([IP, "link", "set", "rflabvm0", "master", "rfbr0"])
        run([IP, "link", "set", "rflabvm0", "up"])
        commands = (
            ("side4", [sys.executable, "-u", "-c", network.SERVER, "192.0.2.3", "34681"]),
            ("side6", [sys.executable, "-u", "-c", V6_SERVER, "fd42:1234:5678::1", "34682"]),
            ("l2", [sys.executable, "-u", "-c", L2_SERVER]),
            ("fence", [IP, "netns", "exec", "fence", sys.executable, "-u", "-c",
                       network.SERVER, "192.0.2.1", "34680"]),
        )
        for name, command in commands:
            output = open(logs[name], "w", encoding="utf-8")
            outputs.append(output)
            servers.append(subprocess.Popen(command, stdout=output, env=ENV))
        for path in logs.values():
            network.wait_text(path, "READY")
        network.wait_text(serial, "BOUNDARY_PROBE_READY", timeout=240)
        channel.send(b"F")
        if channel.recv(32) != b"FROZEN":
            raise RuntimeError("Owner did not freeze with QEMU active")
        offsets = {name: os.path.getsize(logs[name]) for name in ("side4", "side6", "l2")}
        delete_guards = "".join(f"delete table inet {name}\n" for name in GUARDS)
        subprocess.run([NFT, "-f", "-"], input=delete_guards, text=True, env=ENV,
                       capture_output=True, check=True, timeout=5)
        slot.mark_unknown()
        for name in ("side4", "side6", "l2"):
            network.wait_text(logs[name], "RECEIVED", offsets[name], timeout=20)
        network.wait_text(serial, "BOUNDARY_SIDE4=OK", timeout=10)
        network.wait_text(serial, "BOUNDARY_SIDE6=OK", timeout=10)
        network.wait_text(serial, "BOUNDARY_L2=SENT", timeout=10)
        if received(logs["fence"]) != 0:
            raise RuntimeError("Fenced receiver unexpectedly got traffic")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and fence_count() == 0:
            time.sleep(0.2)
        if fence_count() == 0:
            raise RuntimeError("Independent fence saw no protected IPv4 traffic")
        record("EXPOSURE: VM-side IPv4, IPv6 and raw L2 synthetic receivers got traffic; fenced receiver got none.")
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if rejected.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot admitted another attempt")
        watcher = subprocess.Popen([
            sys.executable, "-u", "tests/lab-fence-watchdog.py", str(init_fd),
        ], pass_fds=(init_fd,), stdout=subprocess.PIPE, env=ENV, bufsize=0)
        if network.read_line(watcher) != "FENCE_WATCHER_READY":
            raise RuntimeError("Fence watcher did not become ready")
        if mode == "mutate":
            fence_nft(["add", "rule", "inet", FENCE, "input_guard", "counter"])
        else:
            fence_nft(["delete", "table", "inet", FENCE])
        if network.read_line(watcher) != "FENCE_LOST" or network.read_line(watcher) != "BOUNDARY_SIGNALLED":
            raise RuntimeError("Fence failure did not signal PID boundary")
        if not select.select([init_fd], [], [], 10)[0]:
            raise RuntimeError("PID namespace init did not exit")
        launcher.wait(timeout=10)
        boundary = NamespaceExitProof(init_fd, launcher)
        if boundary.poll() is None:
            raise RuntimeError("PID namespace termination not confirmed")
        boundary_confirmed = True
        links = json.loads(run([IP, "-j", "link", "show"]).stdout)
        if any(entry["ifname"] == "rflabvm0" for entry in links):
            raise RuntimeError("TAP remained after PID namespace termination")
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if rejected.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot admitted another attempt after fence loss")
        record(f"FENCE {mode.upper()}: watcher killed PID boundary; slot remained UNKNOWN and blocked.")
        record(f"FENCE RECEIVER: {received(logs['fence'])} data receptions observed through shutdown.")
        try:
            slot.release(boundary, overlay, seed)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Slot released with remaining resources")
        network.stop(watcher)
        for server in servers:
            network.stop(server)
        run([IP, "link", "delete", "dev", "rfbridge0"])
        run([IP, "link", "delete", "dev", "rfbr0"])
        run([IP, "netns", "delete", "fence"])
        if run([NFT, "-s", "list", "table", "inet", "unrelated_fixture"]).stdout != unrelated:
            raise RuntimeError("Unrelated table changed")
        os.unlink(overlay)
        os.unlink(seed)
        slot.release(boundary, overlay, seed)
        accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if accepted.returncode != 0:
            raise RuntimeError("Admission did not resume after cleanup")
        slot.transition("RESERVED", "EMPTY")
        record("CLEANUP: boundary and owned resources verified; unrelated table preserved; slot EMPTY.")
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        network.stop(watcher)
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
        for output in outputs:
            output.close()
        if channel is not None:
            channel.close()
        if not boundary_confirmed:
            print("Namespace exit unconfirmed; slot and disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
