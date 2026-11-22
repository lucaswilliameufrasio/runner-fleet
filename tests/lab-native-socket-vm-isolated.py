#!/usr/bin/python3
"""Real guest UDP DNS and TCP through an isolated QEMU socket/libslirp hub."""
import ctypes
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("lab_services", "tests/lab-dns-tcp-egress-isolated.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
spec = importlib.util.spec_from_file_location("lab_network", "tests/lab-vm-network-isolated.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
spec = importlib.util.spec_from_file_location("lab_slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP, NFT, ENV = lab.IP, lab.NFT, lab.ENV


def death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def verify_process(process):
    with open(f"/proc/{process.pid}/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (int(status["CapEff"].strip(), 16) or int(status["CapBnd"].strip(), 16)
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Process retained capabilities")
    for fd in os.listdir(f"/proc/{process.pid}/fd"):
        try:
            target = os.readlink(f"/proc/{process.pid}/fd/{fd}")
        except FileNotFoundError:
            continue
        if target == "/dev/net/tun":
            raise RuntimeError("Process unexpectedly holds a TAP descriptor")


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 3 or sys.argv[2] not in ("normal", "guard-loss"):
        raise RuntimeError("Requires previously verified image and fixed mode")
    image = os.path.realpath(sys.argv[1])
    scenario = sys.argv[2]
    work = tempfile.mkdtemp(prefix=f"native-socket-vm-{scenario}-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    processes, outputs, sockets = [], [], []
    qemu = backend = None
    try:
        lab.run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        lab.run([IP, "netns", "add", "target"])
        lab.run([NFT, "add", "table", "inet", "native_unrelated_fixture"])
        unrelated = lab.run([NFT, "-s", "list", "table", "inet", "native_unrelated_fixture"])
        lab.run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        lab.run([IP, "link", "set", "target0", "netns", "target"])
        for interface in ("lo", "rftarget0"):
            lab.run([IP, "link", "set", interface, "up"])
        lab.run([IP, "addr", "add", "198.51.100.5/24", "dev", "rftarget0"])
        for interface in ("lo", "target0"):
            lab.run([IP, "netns", "exec", "target", IP, "link", "set", interface, "up"])
        logs = {}
        for address in (lab.HOST, lab.DNS, lab.TCP, lab.LAN, "127.0.0.1"):
            if address != "127.0.0.1":
                lab.run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/24", "dev", "target0"])
            for mode in ("dns", "tcp"):
                path = os.path.join(work, address + "-" + mode + ".log")
                logs[(address, mode)] = path
                output = open(path, "w", encoding="utf-8")
                outputs.append(output)
                command = [sys.executable, "-u", "tests/lab-dns-tcp-egress-isolated.py", "--service", address, mode]
                if address != "127.0.0.1":
                    command = [IP, "netns", "exec", "target", *command]
                process = subprocess.Popen(command, env=ENV, stdout=output)
                processes.append(process)
                lab.wait_text(path, "READY")
        # The loopback and veth fixtures are proven reachable before filtering.
        for address in (lab.HOST, lab.DNS, lab.TCP, lab.LAN, "127.0.0.1"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.sendto(b"control", (address, lab.DNS_PORT))
            with socket.create_connection((address, lab.TCP_PORT), timeout=1) as probe:
                probe.sendall(b"control")
        for path in logs.values():
            lab.wait_text(path, "RECEIVED")
        baseline = {key: lab.read_count(path) for key, path in logs.items()}
        policy = f"""create table inet native_socket_lab
add chain inet native_socket_lab output {{ type filter hook output priority -300; policy drop; }}
add rule inet native_socket_lab output ip daddr {lab.DNS} udp dport {lab.DNS_PORT} accept
add rule inet native_socket_lab output ip daddr {lab.TCP} tcp dport {lab.TCP_PORT} accept
"""
        lab.run([NFT, "-f", "-"], policy)
        lab.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        lab.run(["cloud-localds", "-N", "tests/lab-native-socket-network-config", seed,
                 "tests/lab-native-socket-user-data", "tests/lab-vm-network-meta-data"])
        vm_sock, net_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        sockets.extend((vm_sock, net_sock))
        backend_log = open(os.path.join(work, "backend.log"), "w", encoding="utf-8")
        qemu_log = open(os.path.join(work, "qemu.log"), "w", encoding="utf-8")
        outputs.extend((backend_log, qemu_log))
        restricted = ["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs"]
        parent = os.getpid()
        backend = subprocess.Popen(restricted + [
            "qemu-system-x86_64", "-machine", "none", "-nodefaults", "-display", "none",
            "-monitor", "none",
            "-netdev", f"socket,id=wire,fd={net_sock.fileno()}",
            "-netdev", "user,id=nat,ipv6=off",
            "-netdev", "hubport,id=wireport,hubid=0,netdev=wire",
            "-netdev", "hubport,id=natport,hubid=0,netdev=nat",
        ], pass_fds=(net_sock.fileno(),), env=ENV, stdout=backend_log, stderr=backend_log,
            preexec_fn=lambda: death_guard(parent))
        net_sock.close()
        qemu = subprocess.Popen(restricted + [
            "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-m", "1024", "-smp", "2", "-nic", "none", "-display", "none", "-monitor", "none",
            "-serial", f"file:{serial}", "-no-reboot",
            "-drive", f"file={overlay},format=qcow2,if=virtio",
            "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
            "-netdev", f"socket,id=guest,fd={vm_sock.fileno()}",
            "-device", "virtio-net-pci,netdev=guest,mac=52:54:00:55:34:12",
        ], pass_fds=(vm_sock.fileno(),), env=ENV, stdout=qemu_log, stderr=qemu_log,
            preexec_fn=lambda: death_guard(parent))
        vm_sock.close()
        slot.activate()
        network.wait_text(serial, "NATIVE_PROBE_READY", timeout=240)
        network.wait_text(serial, "NATIVE_DNS=OK", timeout=30)
        network.wait_text(serial, "NATIVE_TCP=OK", timeout=30)
        for target in ("HOST", "LAN", "GATEWAY"):
            network.wait_text(serial, f"NATIVE_{target}=DENIED", timeout=15)
            network.wait_text(serial, f"NATIVE_{target}_DNS=DENIED", timeout=15)
        verify_process(qemu)
        verify_process(backend)
        time.sleep(0.5)
        after = {key: lab.read_count(path) for key, path in logs.items()}
        if after[(lab.DNS, "dns")] <= baseline[(lab.DNS, "dns")] or after[(lab.TCP, "tcp")] <= baseline[(lab.TCP, "tcp")]:
            raise RuntimeError("Allowed services did not receive guest traffic")
        for address in (lab.HOST, lab.LAN, "127.0.0.1"):
            for mode in ("dns", "tcp"):
                if after[(address, mode)] != baseline[(address, mode)]:
                    raise RuntimeError(f"Protected receiver {address} {mode} got traffic")
        print(f"Guest native DNS/TCP succeeded; protected receiver counts unchanged: {baseline} -> {after}", flush=True)
        if scenario == "guard-loss":
            slot.mark_unknown()
            lab.run([NFT, "delete", "table", "inet", "native_socket_lab"])
            tables = json.loads(lab.run([NFT, "-j", "list", "tables"]))["nftables"]
            if any(entry.get("table", {}).get("name") == "native_socket_lab" for entry in tables):
                raise RuntimeError("Network policy was not removed")
            if qemu.poll() is not None or backend.poll() is not None:
                raise RuntimeError("VM or socket backend exited before observation")
            denied = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                    env=ENV, capture_output=True, text=True, timeout=5)
            if denied.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown slot did not block admission")
            deadline = time.monotonic() + 20
            protected = (lab.HOST, lab.LAN, "127.0.0.1")
            while time.monotonic() < deadline:
                leaked = {(address, protocol): lab.read_count(logs[(address, protocol)]) - baseline[(address, protocol)]
                          for address in protected for protocol in ("dns", "tcp")}
                if all(value > 0 for value in leaked.values()):
                    break
                time.sleep(0.2)
            if qemu.poll() is not None or backend.poll() is not None:
                raise RuntimeError("VM or socket backend exited during observation")
            print(f"GUARD REMOVED: protected receiver deltas {leaked}; VM and backend active.", flush=True)
            with open(os.path.join(work, "guard-loss.json"), "w", encoding="utf-8") as output:
                json.dump({f"{address}-{protocol}": value for (address, protocol), value in leaked.items()}, output)
            try:
                slot.release(qemu, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Slot released while VM and resources remained")
            lab.stop(qemu)
            lab.stop(backend)
            for process in processes:
                lab.stop(process)
            os.unlink(overlay)
            os.unlink(seed)
            try:
                slot.release(qemu, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Slot released while test network remained")
            lab.run([IP, "link", "delete", "dev", "rftarget0"])
            lab.run([IP, "netns", "delete", "target"])
            if lab.run([NFT, "-s", "list", "table", "inet", "native_unrelated_fixture"]) != unrelated:
                raise RuntimeError("Unrelated table changed")
            slot.release(qemu, overlay, seed)
            print("GUARD LOSS: UNKNOWN blocked admission until owned resources were removed; slot EMPTY.", flush=True)
            return
        backend.send_signal(signal.SIGSTOP)
        if os.waitid(os.P_PID, backend.pid, os.WSTOPPED).si_code != os.CLD_STOPPED:
            raise RuntimeError("Socket network backend did not stop")
        time.sleep(1)
        offset = os.path.getsize(serial)
        network.wait_text(serial, "NATIVE_DNS=DENIED", offset, timeout=15)
        network.wait_text(serial, "NATIVE_TCP=DENIED", offset, timeout=15)
        offset = os.path.getsize(serial)
        backend.send_signal(signal.SIGCONT)
        network.wait_text(serial, "NATIVE_DNS=OK", offset, timeout=30)
        network.wait_text(serial, "NATIVE_TCP=OK", offset, timeout=30)
        print("Backend SIGSTOP: guest DNS/TCP timed out; both recovered after SIGCONT.", flush=True)
        slot.mark_unknown()
        offset = os.path.getsize(serial)
        backend.kill()
        backend.wait(timeout=5)
        network.wait_text(serial, "NATIVE_DNS=DENIED", offset, timeout=20)
        network.wait_text(serial, "NATIVE_TCP=DENIED", offset, timeout=20)
        denied = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                env=ENV, capture_output=True, text=True, timeout=5)
        if denied.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot did not block admission")
        for address in (lab.HOST, lab.LAN, "127.0.0.1"):
            for mode in ("dns", "tcp"):
                if lab.read_count(logs[(address, mode)]) != baseline[(address, mode)]:
                    raise RuntimeError("Protected receiver got traffic during failure tests")
        print("Backend SIGKILL: UNKNOWN blocked admission; protected receivers remained unchanged.", flush=True)
        lab.stop(qemu)
        for process in processes:
            lab.stop(process)
        lab.run([IP, "link", "delete", "dev", "rftarget0"])
        lab.run([IP, "netns", "delete", "target"])
        lab.run([NFT, "delete", "table", "inet", "native_socket_lab"])
        tables = json.loads(lab.run([NFT, "-j", "list", "tables"]))["nftables"]
        if any(entry.get("table", {}).get("name") == "native_socket_lab" for entry in tables):
            raise RuntimeError("Network policy remains")
        if lab.run([NFT, "-s", "list", "table", "inet", "native_unrelated_fixture"]) != unrelated:
            raise RuntimeError("Unrelated table changed")
        os.unlink(overlay)
        os.unlink(seed)
        slot.release(qemu, overlay, seed)
        print("Owned VM, backend and test resources removed; slot EMPTY.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        lab.stop(qemu)
        lab.stop(backend)
        for process in processes:
            lab.stop(process)
        for item in sockets:
            item.close()
        for output in outputs:
            output.close()
        if os.path.exists(overlay) or os.path.exists(seed):
            print("Cleanup unverified; VM disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
