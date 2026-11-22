#!/usr/bin/python3
"""QEMU with an unprivileged closed socket sink, in disposable namespaces."""
import ctypes
import fcntl
import importlib.util
import json
import os
import select
import signal
import socket
import struct
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
spec = importlib.util.spec_from_file_location("boundary_paths", "tests/lab-boundary-paths-isolated.py")
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)
IP = network.IP
NFT = network.NFT
ENV = network.SAFE_ENV
run = network.run
BRIDGE_GUARD = "runner_fleet_bridge_guard"
INGRESS_GUARD = "runner_fleet_ingress_guard"
PAYLOAD = b"fleet-probe"
UDP_SERVER = """
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
print("READY", flush=True)
while True:
    data, _ = s.recvfrom(1024)
    if data == b"fleet-probe":
        print("RECEIVED", flush=True)
"""
LOCAL_L2_SERVER = paths.L2_SERVER.replace("fleet-l2-probe", "fleet-l2-local")
REMOTE_L2_SERVER = paths.L2_SERVER.replace('"rfbr0"', '"rfhost0"')


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def nft(args, data=None):
    return subprocess.run([NFT, *args], input=data, text=True, env=ENV, capture_output=True,
                          check=True, timeout=5).stdout


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(mac, source, destination, port):
    udp = struct.pack("!HHHH", 23456, port, 8 + len(PAYLOAD), 0)
    if ":" in destination:
        src = socket.inet_pton(socket.AF_INET6, source)
        dst = socket.inet_pton(socket.AF_INET6, destination)
        pseudo = src + dst + struct.pack("!I3xB", len(udp) + len(PAYLOAD), socket.IPPROTO_UDP)
        udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp + PAYLOAD) or 0xffff)
        header = struct.pack("!IHBB16s16s", 6 << 28, len(udp) + len(PAYLOAD), 17, 64, src, dst)
        protocol = b"\x86\xdd"
    else:
        src = socket.inet_aton(source)
        dst = socket.inet_aton(destination)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(PAYLOAD),
                             23, 0, 64, 17, 0, src, dst)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        protocol = b"\x08\x00"
    return bytes.fromhex(mac) + bytes.fromhex("525400553412") + protocol + header + udp + PAYLOAD


def counts(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def wait_counts(path, previous, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = counts(path)
            if all(current[name] > previous.get(name, 0) for name in ("IPv4", "IPv6", "L2")):
                return current
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"Socket sink did not receive all test protocols; inspect {path}")


def received(path):
    with open(path, encoding="utf-8") as source:
        return source.read().count("RECEIVED")


def check_no_caps(pid):
    with open(f"/proc/{pid}/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (int(status["CapEff"].strip(), 16) != 0 or int(status["CapBnd"].strip(), 16) != 0
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Process unexpectedly retained capabilities")


def check_no_tap_fd(pid):
    for name in os.listdir(f"/proc/{pid}/fd"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{name}")
        except FileNotFoundError:
            continue
        if target == "/dev/net/tun":
            raise RuntimeError("QEMU or socket sink unexpectedly inherited a TAP descriptor")


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires a verified image")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="socket-boundary-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    sink_stats = os.path.join(work, "sink-stats.json")
    sink_log = os.path.join(work, "sink.log")
    qemu_log = os.path.join(work, "qemu.log")
    events = os.path.join(work, "events.log")
    names = ("side4", "side6", "l2", "local4", "local6", "local_l2")
    logs = {name: os.path.join(work, name + ".log") for name in names}
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    qemu = None
    sink = None
    watcher = None
    tap_fd = None
    qemu_fd = None
    sockets = []
    servers = []
    outputs = []

    def record(message):
        print(message, flush=True)
        with open(events, "a", encoding="utf-8") as output:
            print(message, file=output, flush=True)

    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "protected"])
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = nft(["-s", "list", "table", "inet", "unrelated_fixture"])
        run([IP, "link", "add", "rfbr0", "type", "bridge"])
        run([IP, "link", "set", "dev", "rfbr0", "address", "02:aa:bb:00:00:10"])
        run([IP, "link", "add", "rfhostbr0", "type", "veth", "peer", "name", "rfhost0"])
        run([IP, "link", "set", "rfhost0", "netns", "protected"])
        run([IP, "link", "set", "rfhostbr0", "master", "rfbr0"])
        tap_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        fcntl.ioctl(tap_fd, 0x400454ca, struct.pack("16sH", b"rflabvm0", 0x9002))
        run([IP, "link", "set", "rflabvm0", "master", "rfbr0"])
        for interface in ("lo", "rfbr0", "rfhostbr0", "rflabvm0"):
            run([IP, "link", "set", interface, "up"])
        run([IP, "addr", "add", "192.0.2.4/24", "dev", "rfbr0"])
        run([IP, "-6", "addr", "add", "fd42:1234:5678::4/64", "dev", "rfbr0", "nodad"])
        run([IP, "netns", "exec", "protected", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "protected", IP, "link", "set", "rfhost0", "up"])
        run([IP, "netns", "exec", "protected", IP, "link", "set", "dev", "rfhost0",
             "address", "02:aa:bb:00:00:01"])
        run([IP, "netns", "exec", "protected", IP, "addr", "add", "192.0.2.3/24", "dev", "rfhost0"])
        run([IP, "netns", "exec", "protected", IP, "-6", "addr", "add", "fd42:1234:5678::1/64", "dev", "rfhost0", "nodad"])
        commands = (
            ("side4", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c", UDP_SERVER, "192.0.2.3", "34681"]),
            ("side6", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c", UDP_SERVER, "fd42:1234:5678::1", "34682"]),
            ("l2", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c", REMOTE_L2_SERVER]),
            ("local4", [sys.executable, "-u", "-c", UDP_SERVER, "192.0.2.4", "34683"]),
            ("local6", [sys.executable, "-u", "-c", UDP_SERVER, "fd42:1234:5678::4", "34684"]),
            ("local_l2", [sys.executable, "-u", "-c", LOCAL_L2_SERVER]),
        )
        for name, command in commands:
            output = open(logs[name], "w", encoding="utf-8")
            outputs.append(output)
            servers.append(subprocess.Popen(command, stdout=output, env=ENV))
        for path in logs.values():
            network.wait_text(path, "READY")
        packets = (
            frame("02aabb000001", "192.0.2.2", "192.0.2.3", 34681),
            frame("02aabb000001", "fd42:1234:5678::2", "fd42:1234:5678::1", 34682),
            bytes.fromhex("02aabb00000152540055341288b5") + b"fleet-l2-probe",
            frame("02aabb000010", "192.0.2.2", "192.0.2.4", 34683),
            frame("02aabb000010", "fd42:1234:5678::2", "fd42:1234:5678::4", 34684),
            bytes.fromhex("02aabb00001052540055341288b5") + b"fleet-l2-local",
        )
        for packet in packets:
            os.write(tap_fd, packet)
        for path in logs.values():
            network.wait_text(path, "RECEIVED", timeout=10)
        record("POSITIVE CONTROL: direct trusted TAP injection reached all six synthetic receivers.")
        guard_policy = (
            f"create table bridge {BRIDGE_GUARD}\n"
            f"add chain bridge {BRIDGE_GUARD} input_guard {{ type filter hook input priority -300; policy accept; }}\n"
            f"add chain bridge {BRIDGE_GUARD} forward_guard {{ type filter hook forward priority -300; policy accept; }}\n"
            f'add rule bridge {BRIDGE_GUARD} input_guard iifname "rflabvm0" counter drop\n'
            f'add rule bridge {BRIDGE_GUARD} forward_guard iifname "rflabvm0" counter drop\n'
            f"create table netdev {INGRESS_GUARD}\n"
            f'add chain netdev {INGRESS_GUARD} ingress_guard {{ type filter hook ingress device "rflabvm0" priority -500; policy accept; }}\n'
            f"add rule netdev {INGRESS_GUARD} ingress_guard counter drop\n"
        )
        nft(["-f", "-"], guard_policy)
        bridge_snapshot = nft(["-s", "list", "table", "bridge", BRIDGE_GUARD])
        with open("/run/fleet-bridge-expected", "w", encoding="utf-8") as target:
            target.write(bridge_snapshot)
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-boundary-network-config", seed,
             "tests/lab-socket-probe-user-data", "tests/lab-vm-network-meta-data"])
        vm_socket, sink_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        sockets.extend((vm_socket, sink_socket))
        parent = os.getpid()
        sink_output = open(sink_log, "w", encoding="utf-8")
        qemu_output = open(qemu_log, "w", encoding="utf-8")
        outputs.extend((sink_output, qemu_output))
        sink = subprocess.Popen([
            "/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
            sys.executable, "-u", "tests/lab-socket-sink.py", str(sink_socket.fileno()), sink_stats,
        ], pass_fds=(sink_socket.fileno(),), stdout=sink_output, stderr=sink_output, env=ENV,
            preexec_fn=lambda: parent_death_guard(parent))
        sink_socket.close()
        qemu = subprocess.Popen([
            "/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
            "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-m", "1024", "-smp", "2", "-nic", "none", "-display", "none", "-monitor", "none",
            "-serial", f"file:{serial}", "-no-reboot",
            "-drive", f"file={overlay},format=qcow2,if=virtio",
            "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
            "-netdev", f"socket,id=lab,fd={vm_socket.fileno()}",
            "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12",
        ], pass_fds=(vm_socket.fileno(),), stdout=qemu_output, stderr=qemu_output, env=ENV,
            preexec_fn=lambda: parent_death_guard(parent))
        vm_socket.close()
        qemu_fd = os.pidfd_open(qemu.pid)
        slot.activate()
        network.wait_text(serial, "SOCKET_PROBE_READY", timeout=240)
        check_no_caps(qemu.pid)
        check_no_caps(sink.pid)
        check_no_tap_fd(qemu.pid)
        check_no_tap_fd(sink.pid)
        initial = wait_counts(sink_stats, {}, timeout=15)
        time.sleep(0.5)
        receiver_before = {name: received(logs[name]) for name in names}
        record(f"CLOSED SOCKET: no-capability QEMU/sink without TAP fd active; sink observed {initial}.")
        with open("/run/fleet-bridge-expected", "w", encoding="utf-8") as target:
            target.write(bridge_snapshot)
        watcher = subprocess.Popen([
            sys.executable, "-u", "tests/lab-bridge-watchdog.py", str(qemu_fd),
        ], pass_fds=(qemu_fd,), stdout=subprocess.PIPE, env=ENV, bufsize=0)
        if network.read_line(watcher) != "BRIDGE_WATCHER_READY":
            raise RuntimeError("Watcher did not become ready")
        watcher.send_signal(signal.SIGSTOP)
        stopped = os.waitid(os.P_PID, watcher.pid, os.WSTOPPED)
        if stopped is None or stopped.si_code != os.CLD_STOPPED:
            raise RuntimeError("Could not confirm watcher stall")
        slot.mark_unknown()
        transaction = (f"delete table netdev {INGRESS_GUARD}\n"
                       f"delete table bridge {BRIDGE_GUARD}\n")
        nft(["-f", "-"], transaction)
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if rejected.returncode == 0:
            raise RuntimeError("Unknown slot admitted another execution")
        before_drop = counts(sink_stats)
        after_drop = wait_counts(sink_stats, before_drop, timeout=15)
        time.sleep(1)
        if {name: received(logs[name]) for name in names} != receiver_before:
            raise RuntimeError("Synthetic receiver got VM traffic after both guards were removed")
        record(f"GUARDS LOST: watcher stopped; socket sink dropped new frames {before_drop} -> {after_drop}; receivers unchanged.")
        sink.send_signal(signal.SIGSTOP)
        stopped = os.waitid(os.P_PID, sink.pid, os.WSTOPPED)
        if stopped is None or stopped.si_code != os.CLD_STOPPED:
            raise RuntimeError("Could not confirm socket sink stall")
        time.sleep(2)
        if {name: received(logs[name]) for name in names} != receiver_before:
            raise RuntimeError("Synthetic receiver got traffic while sink was stopped")
        sink.send_signal(signal.SIGCONT)
        resumed = counts(sink_stats)
        wait_counts(sink_stats, resumed, timeout=15)
        if {name: received(logs[name]) for name in names} != receiver_before:
            raise RuntimeError("Synthetic receiver got traffic after sink resumed")
        record("SINK STALL: no receiver traffic; resumed sink consumed more frames.")
        sink.kill()
        sink.wait(timeout=5)
        time.sleep(1)
        if {name: received(logs[name]) for name in names} != receiver_before:
            raise RuntimeError("Synthetic receiver got traffic after sink death")
        record("SINK DEATH: no receiver traffic observed; slot remained UNKNOWN.")
        if qemu.poll() is None:
            watcher.send_signal(signal.SIGCONT)
            if (network.read_line(watcher) != "BRIDGE_GUARD_LOST"
                    or network.read_line(watcher) != "BOUNDARY_SIGNALLED"):
                raise RuntimeError("Watcher did not stop QEMU after resume")
            qemu.wait(timeout=10)
        else:
            watcher.send_signal(signal.SIGCONT)
        if qemu.poll() is None:
            raise RuntimeError("QEMU did not exit")
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if rejected.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot admitted another execution")
        try:
            slot.release(qemu, overlay, seed)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Slot released before resource cleanup")
        network.stop(watcher)
        for server in servers:
            network.stop(server)
        os.close(tap_fd)
        tap_fd = None
        run([IP, "link", "delete", "dev", "rfhostbr0"])
        run([IP, "link", "delete", "dev", "rfbr0"])
        run([IP, "netns", "delete", "protected"])
        if nft(["-s", "list", "table", "inet", "unrelated_fixture"]) != unrelated:
            raise RuntimeError("Unrelated table changed")
        os.unlink(overlay)
        os.unlink(seed)
        slot.release(qemu, overlay, seed)
        accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if accepted.returncode != 0:
            raise RuntimeError("Admission did not resume after cleanup")
        slot.transition("RESERVED", "EMPTY")
        record("CLEANUP: owned processes and resources verified; unrelated table preserved; slot EMPTY.")
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        if watcher is not None and watcher.poll() is None:
            watcher.send_signal(signal.SIGCONT)
        if sink is not None and sink.poll() is None:
            sink.send_signal(signal.SIGCONT)
        network.stop(watcher)
        network.stop(qemu)
        network.stop(sink)
        for server in servers:
            network.stop(server)
        for item in sockets:
            item.close()
        if tap_fd is not None:
            os.close(tap_fd)
        if qemu_fd is not None:
            os.close(qemu_fd)
        for output in outputs:
            output.close()
        if os.path.exists(overlay) or os.path.exists(seed):
            print("Unverified recovery: slot and VM disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
