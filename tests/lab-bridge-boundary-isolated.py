#!/usr/bin/python3
"""Test structural separation and a bridge-family guard with real QEMU."""
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
spec = importlib.util.spec_from_file_location("boundary_paths", "tests/lab-boundary-paths-isolated.py")
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)
IP = network.IP
NFT = network.NFT
ENV = network.SAFE_ENV
run = network.run
GUARDS = ("runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b")
BRIDGE_GUARD = "runner_fleet_bridge_guard"
INGRESS_GUARD = "runner_fleet_ingress_guard"
L2_SERVER = paths.L2_SERVER.replace('"rfbr0"', '"rfhost0"')
LOCAL_L2_SERVER = paths.L2_SERVER.replace("fleet-l2-probe", "fleet-l2-local")


def parent_death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def nft(args, data=None):
    return subprocess.run([NFT, *args], input=data, text=True, env=ENV, capture_output=True,
                          check=True, timeout=5).stdout


def counts():
    result = {}
    for chain in ("input_guard", "forward_guard"):
        entries = json.loads(nft(["-j", "list", "chain", "bridge", BRIDGE_GUARD, chain]))
        for entry in entries["nftables"]:
            rule = entry.get("rule", {})
            name = rule.get("comment")
            for expression in rule.get("expr", []):
                if name is not None and "counter" in expression:
                    result[name] = expression["counter"]["packets"]
    return result


def received(path):
    with open(path, encoding="utf-8") as source:
        return source.read().count("RECEIVED")


def ingress_counts():
    entries = json.loads(nft(["-j", "list", "chain", "netdev", INGRESS_GUARD, "ingress_guard"]))
    result = {}
    for entry in entries["nftables"]:
        rule = entry.get("rule", {})
        name = rule.get("comment")
        for expression in rule.get("expr", []):
            if name is not None and "counter" in expression:
                result[name] = expression["counter"]["packets"]
    return result


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
    if len(sys.argv) != 3 or sys.argv[2] not in ("none", "mutate", "delete", "stall-delete", "ingress-stall-delete"):
        raise RuntimeError("Requires verified image and fixed fault scenario")
    image = os.path.realpath(sys.argv[1])
    mode = sys.argv[2]
    work = tempfile.mkdtemp(prefix=f"bridge-boundary-{mode}-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    events = os.path.join(work, "events.log")
    receiver_names = ("side4", "side6", "l2", "local4", "local6", "local_l2")
    logs = {name: os.path.join(work, name + ".log") for name in (*receiver_names, "fence")}
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
    ingress_snapshot = None

    def record(message):
        print(message, flush=True)
        with open(events, "a", encoding="utf-8") as target:
            print(message, file=target, flush=True)

    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "fence"])
        run([IP, "netns", "add", "protected"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
        run([NFT, "add", "table", "inet", "unrelated_fixture"])
        unrelated = nft(["-s", "list", "table", "inet", "unrelated_fixture"])
        run([IP, "link", "add", "rfbr0", "type", "bridge"])
        run([IP, "link", "set", "dev", "rfbr0", "address", "02:aa:bb:00:00:10"])
        run([IP, "link", "add", "rfbridge0", "type", "veth", "peer", "name", "rffence0"])
        run([IP, "link", "set", "rffence0", "netns", "fence"])
        run([IP, "link", "set", "rfbridge0", "master", "rfbr0"])
        run([IP, "link", "add", "rfhostbr0", "type", "veth", "peer", "name", "rfhost0"])
        run([IP, "link", "set", "rfhost0", "netns", "protected"])
        run([IP, "link", "set", "rfhostbr0", "master", "rfbr0"])
        for interface in ("lo", "rfbr0", "rfbridge0", "rfhostbr0"):
            run([IP, "link", "set", interface, "up"])
        for namespace, interface in (("fence", "rffence0"), ("protected", "rfhost0")):
            run([IP, "netns", "exec", namespace, IP, "link", "set", "lo", "up"])
            run([IP, "netns", "exec", namespace, IP, "link", "set", interface, "up"])
        run([IP, "netns", "exec", "protected", IP, "link", "set", "dev", "rfhost0",
             "address", "02:aa:bb:00:00:01"])
        run([IP, "netns", "exec", "protected", IP, "addr", "add", "192.0.2.3/24", "dev", "rfhost0"])
        run([IP, "netns", "exec", "protected", IP, "-6", "addr", "add", "fd42:1234:5678::1/64", "dev", "rfhost0", "nodad"])
        run([IP, "netns", "exec", "fence", IP, "addr", "add", "192.0.2.1/24", "dev", "rffence0"])
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-boundary-network-config", seed,
             "tests/lab-bridge-probe-user-data", "tests/lab-vm-network-meta-data"])
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
        addresses = json.loads(run([IP, "-j", "address", "show"]).stdout)
        for entry in addresses:
            if entry["ifname"] != "lo" and entry.get("addr_info"):
                raise RuntimeError("Transit interface unexpectedly has a local IP address")
        if run(["ss", "-H", "-lntup"]).stdout.strip():
            raise RuntimeError("Transit namespace has a listening TCP/UDP socket")
        record("TRANSIT BASELINE: no non-loopback IP addresses or listening TCP/UDP sockets.")
        # Explicitly add synthetic local services after the empty-transit baseline.
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.rfbr0.disable_ipv6=0"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.rflabvm0.disable_ipv6=0"])
        run([IP, "addr", "add", "192.0.2.4/24", "dev", "rfbr0"])
        run([IP, "-6", "addr", "add", "fd42:1234:5678::4/64", "dev", "rfbr0", "nodad"])
        commands = (
            ("side4", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c",
                       network.SERVER, "192.0.2.3", "34681"]),
            ("side6", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c",
                       paths.V6_SERVER, "fd42:1234:5678::1", "34682"]),
            ("l2", [IP, "netns", "exec", "protected", sys.executable, "-u", "-c", L2_SERVER]),
            ("local4", [sys.executable, "-u", "-c", network.SERVER, "192.0.2.4", "34683"]),
            ("local6", [sys.executable, "-u", "-c", paths.V6_SERVER, "fd42:1234:5678::4", "34684"]),
            ("local_l2", [sys.executable, "-u", "-c", LOCAL_L2_SERVER]),
            ("fence", [IP, "netns", "exec", "fence", sys.executable, "-u", "-c",
                       network.SERVER, "192.0.2.1", "34680"]),
        )
        for name, command in commands:
            output = open(logs[name], "w", encoding="utf-8")
            outputs.append(output)
            servers.append(subprocess.Popen(command, stdout=output, env=ENV))
        for path in logs.values():
            network.wait_text(path, "READY")
        network.wait_text(serial, "BRIDGE_PROBE_READY", timeout=240)
        snapshots = {name: nft(["-s", "list", "table", "inet", name]) for name in GUARDS}
        channel.send(b"F")
        if channel.recv(32) != b"FROZEN":
            raise RuntimeError("Owner did not freeze with QEMU active")
        delete_guards = "".join(f"delete table inet {name}\n" for name in GUARDS)
        nft(["-f", "-"], delete_guards)
        for name in receiver_names:
            network.wait_text(logs[name], "RECEIVED", timeout=20)
        record("POSITIVE CONTROL: protected and local IPv4, IPv6 and L2 receivers got synthetic VM traffic.")
        bridge_policy = (
            f"create table bridge {BRIDGE_GUARD}\n"
            f"add chain bridge {BRIDGE_GUARD} input_guard {{ type filter hook input priority -300; policy accept; }}\n"
            f"add chain bridge {BRIDGE_GUARD} forward_guard {{ type filter hook forward priority -300; policy accept; }}\n"
            f'add rule bridge {BRIDGE_GUARD} input_guard iifname "rflabvm0" ether type ip counter drop comment "input-IPv4"\n'
            f'add rule bridge {BRIDGE_GUARD} input_guard iifname "rflabvm0" ether type ip6 counter drop comment "input-IPv6"\n'
            f'add rule bridge {BRIDGE_GUARD} input_guard iifname "rflabvm0" ether type 0x88b5 counter drop comment "input-L2"\n'
            f'add rule bridge {BRIDGE_GUARD} input_guard iifname "rflabvm0" counter drop\n'
            f'add rule bridge {BRIDGE_GUARD} forward_guard iifname "rflabvm0" ether type ip counter drop comment "forward-IPv4"\n'
            f'add rule bridge {BRIDGE_GUARD} forward_guard iifname "rflabvm0" ether type ip6 counter drop comment "forward-IPv6"\n'
            f'add rule bridge {BRIDGE_GUARD} forward_guard iifname "rflabvm0" ether type 0x88b5 counter drop comment "forward-L2"\n'
            f'add rule bridge {BRIDGE_GUARD} forward_guard iifname "rflabvm0" counter drop\n'
        )
        nft(["-f", "-"], bridge_policy)
        bridge_snapshot = nft(["-s", "list", "table", "bridge", BRIDGE_GUARD])
        nft(["-f", "-"], "\n".join(snapshots.values()))
        for name in GUARDS:
            if nft(["-s", "list", "table", "inet", name]) != snapshots[name]:
                raise RuntimeError("Original guard restoration differed")
        time.sleep(1)
        receiver_before = {name: received(logs[name]) for name in receiver_names}
        counters_before = counts()
        nft(["-f", "-"], delete_guards)
        slot.mark_unknown()
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5, check=False)
        if rejected.returncode == 0:
            raise RuntimeError("Unknown slot admitted another attempt")
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            current = counts()
            if all(current.get(name, 0) > counters_before.get(name, 0)
                   for name in ("input-IPv4", "input-IPv6", "input-L2",
                                "forward-IPv4", "forward-IPv6", "forward-L2")):
                break
            time.sleep(0.2)
        counters_after = counts()
        if not all(counters_after.get(name, 0) > counters_before.get(name, 0)
                   for name in ("input-IPv4", "input-IPv6", "input-L2",
                                "forward-IPv4", "forward-IPv6", "forward-L2")):
            raise RuntimeError(f"Bridge guard did not observe every protocol: {counters_before} -> {counters_after}")
        time.sleep(3)
        receiver_after = {name: received(logs[name]) for name in receiver_names}
        if receiver_after != receiver_before:
            raise RuntimeError(f"Protected receiver got traffic after bridge guard: {receiver_before} -> {receiver_after}")
        channel.send(b"Q")
        if channel.recv(32) != b"LIVE":
            raise RuntimeError("QEMU was not alive during bridge-guard checks")
        record(f"DUAL LOSS: bridge counters {counters_before} -> {counters_after}; receivers unchanged {receiver_after}.")
        record("ADMISSION: UNKNOWN blocked another reservation while QEMU remained alive.")
        if mode == "none":
            signal.pidfd_send_signal(init_fd, signal.SIGKILL)
        else:
            if mode == "ingress-stall-delete":
                ingress_policy = (
                    f"create table netdev {INGRESS_GUARD}\n"
                    f'add chain netdev {INGRESS_GUARD} ingress_guard {{ type filter hook ingress device "rflabvm0" priority -500; policy accept; }}\n'
                    f'add rule netdev {INGRESS_GUARD} ingress_guard ether type ip counter drop comment "IPv4"\n'
                    f'add rule netdev {INGRESS_GUARD} ingress_guard ether type ip6 counter drop comment "IPv6"\n'
                    f'add rule netdev {INGRESS_GUARD} ingress_guard ether type 0x88b5 counter drop comment "L2"\n'
                    f"add rule netdev {INGRESS_GUARD} ingress_guard counter drop\n"
                )
                nft(["-f", "-"], ingress_policy)
                ingress_snapshot = nft(["-s", "list", "table", "netdev", INGRESS_GUARD])
            with open("/run/fleet-bridge-expected", "w", encoding="utf-8") as target:
                target.write(bridge_snapshot)
            watcher = subprocess.Popen([
                sys.executable, "-u", "tests/lab-bridge-watchdog.py", str(init_fd),
            ], pass_fds=(init_fd,), stdout=subprocess.PIPE, env=ENV, bufsize=0)
            if network.read_line(watcher) != "BRIDGE_WATCHER_READY":
                raise RuntimeError("Bridge watcher did not become ready")
            before_fault = {name: received(logs[name]) for name in receiver_names}
            if mode in ("stall-delete", "ingress-stall-delete"):
                watcher.send_signal(signal.SIGSTOP)
                stopped = os.waitid(os.P_PID, watcher.pid, os.WSTOPPED)
                if stopped is None or stopped.si_code != os.CLD_STOPPED:
                    raise RuntimeError("Could not confirm watcher stall")
            fault_start = time.monotonic()
            if mode == "mutate":
                nft(["add", "rule", "bridge", BRIDGE_GUARD, "input_guard",
                     "counter", "comment", '"lab-injected-fault"'])
            else:
                nft(["delete", "table", "bridge", BRIDGE_GUARD])
            if mode == "stall-delete":
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and received(logs["local4"]) <= before_fault["local4"]:
                    time.sleep(0.02)
                leaked = received(logs["local4"]) - before_fault["local4"]
                if leaked <= 0:
                    raise RuntimeError("Stalled-watcher positive control observed no traffic")
                channel.send(b"Q")
                if channel.recv(32) != b"LIVE" or slot.state() != "UNKNOWN":
                    raise RuntimeError("Expected active QEMU and unknown slot during watcher stall")
                record(f"ISOLATION_FAILURE: stalled watcher and deleted guard allowed {leaked} synthetic local reception(s).")
                watcher.send_signal(signal.SIGCONT)
                fault_start = time.monotonic()
            elif mode == "ingress-stall-delete":
                before_ingress = ingress_counts()
                deadline = time.monotonic() + 18
                while time.monotonic() < deadline:
                    current = ingress_counts()
                    if all(current.get(name, 0) > before_ingress.get(name, 0) for name in ("IPv4", "IPv6", "L2")):
                        break
                    time.sleep(0.2)
                after_ingress = ingress_counts()
                if not all(after_ingress.get(name, 0) > before_ingress.get(name, 0) for name in ("IPv4", "IPv6", "L2")):
                    raise RuntimeError(f"Ingress guard did not observe all protocols: {before_ingress} -> {after_ingress}")
                time.sleep(3)
                guarded_receivers = {name: received(logs[name]) for name in receiver_names}
                if guarded_receivers != before_fault:
                    raise RuntimeError(f"Receiver got traffic during stopped watcher: {before_fault} -> {guarded_receivers}")
                if nft(["-s", "list", "table", "netdev", INGRESS_GUARD]) != ingress_snapshot:
                    raise RuntimeError("Ingress guard changed during stopped-watcher test")
                channel.send(b"Q")
                if channel.recv(32) != b"LIVE" or slot.state() != "UNKNOWN":
                    raise RuntimeError("Expected active QEMU and blocked slot during stopped watcher")
                record(f"INGRESS GUARD: watcher stopped and bridge absent; counters {before_ingress} -> {after_ingress}; receivers unchanged.")
                watcher.send_signal(signal.SIGCONT)
                fault_start = time.monotonic()
            if (network.read_line(watcher) != "BRIDGE_GUARD_LOST"
                    or network.read_line(watcher) != "BOUNDARY_SIGNALLED"):
                raise RuntimeError("Bridge fault was not detected and signalled")
            elapsed = time.monotonic() - fault_start
            record(f"BRIDGE {mode.upper()}: watcher signalled PID boundary in {elapsed:.3f}s.")
        if not select.select([init_fd], [], [], 10)[0]:
            raise RuntimeError("PID namespace init did not exit")
        launcher.wait(timeout=10)
        boundary = NamespaceExitProof(init_fd, launcher)
        if boundary.poll() is None:
            raise RuntimeError("PID namespace termination not confirmed")
        boundary_confirmed = True
        if mode != "none":
            time.sleep(0.5)
            after_fault = {name: received(logs[name]) for name in receiver_names}
            delta = {name: after_fault[name] - before_fault[name] for name in receiver_names}
            if mode in ("mutate", "ingress-stall-delete") and any(value != 0 for value in delta.values()):
                raise RuntimeError(f"Receivers got traffic while a drop guard remained: {delta}")
            record(f"BRIDGE {mode.upper()}: receiver delta during shutdown {delta}.")
            rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if rejected.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown slot admitted another attempt after bridge fault")
            record("ADMISSION: UNKNOWN still blocked reservation after bridge fault.")
        try:
            slot.release(boundary, overlay, seed)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Slot released before network and disk cleanup")
        network.stop(watcher)
        for server in servers:
            network.stop(server)
        if mode == "mutate":
            entries = json.loads(nft(["-a", "-j", "list", "chain", "bridge", BRIDGE_GUARD, "input_guard"]))
            handles = [entry["rule"]["handle"] for entry in entries["nftables"]
                       if entry.get("rule", {}).get("comment") == "lab-injected-fault"]
            if len(handles) != 1:
                raise RuntimeError("Injected rule identity uncertain; refusing cleanup")
            nft(["delete", "rule", "bridge", BRIDGE_GUARD, "input_guard", "handle", str(handles[0])])
        if mode not in ("delete", "stall-delete", "ingress-stall-delete") and nft(["-s", "list", "table", "bridge", BRIDGE_GUARD]) != bridge_snapshot:
            raise RuntimeError("Bridge guard changed; refusing cleanup")
        run([IP, "link", "delete", "dev", "rfhostbr0"])
        run([IP, "link", "delete", "dev", "rfbridge0"])
        run([IP, "link", "delete", "dev", "rfbr0"])
        run([IP, "netns", "delete", "protected"])
        run([IP, "netns", "delete", "fence"])
        if mode not in ("delete", "stall-delete", "ingress-stall-delete"):
            nft(["delete", "table", "bridge", BRIDGE_GUARD])
        if mode == "ingress-stall-delete":
            # Linux detaches the ingress hook from a destroyed TAP; rules remain.
            detached = ingress_snapshot.replace(' device "rflabvm0"', "")
            if nft(["-s", "list", "table", "netdev", INGRESS_GUARD]) != detached:
                raise RuntimeError("Detached ingress guard changed; refusing cleanup")
            nft(["delete", "table", "netdev", INGRESS_GUARD])
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
