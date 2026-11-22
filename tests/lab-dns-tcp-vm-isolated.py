#!/usr/bin/python3
"""Exercise the fixed DNS/TCP broker through a disposable VM serial socket."""
import importlib.util
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("dns_tcp", "tests/lab-dns-tcp-egress-isolated.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
spec = importlib.util.spec_from_file_location("network", "tests/lab-vm-network-isolated.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
spec = importlib.util.spec_from_file_location("slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP, NFT, ENV = lab.IP, lab.NFT, lab.ENV


def wait_new(path, text, offset=0, timeout=15):
    return network.wait_text(path, text, offset, timeout)


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires previously verified image")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="dns-tcp-vm-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    processes, outputs, sockets = [], [], []
    qemu = broker = bridge = None
    try:
        lab.run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        lab.run([IP, "netns", "add", "target"])
        lab.run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        lab.run([IP, "link", "set", "target0", "netns", "target"])
        for interface in ("lo", "rftarget0"):
            lab.run([IP, "link", "set", interface, "up"])
        lab.run([IP, "addr", "add", "198.51.100.5/24", "dev", "rftarget0"])
        for interface in ("lo", "target0"):
            lab.run([IP, "netns", "exec", "target", IP, "link", "set", interface, "up"])
        logs = {}
        for address in (lab.HOST, lab.DNS, lab.TCP, lab.LAN):
            lab.run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/24", "dev", "target0"])
            for mode in ("dns", "tcp"):
                path = os.path.join(work, address + "-" + mode + ".log")
                logs[(address, mode)] = path
                output = open(path, "w", encoding="utf-8")
                outputs.append(output)
                process = subprocess.Popen([IP, "netns", "exec", "target", sys.executable,
                                            "-u", "tests/lab-dns-tcp-egress-isolated.py",
                                            "--service", address, mode], env=ENV, stdout=output)
                processes.append(process)
                lab.wait_text(path, "READY")
        for address in (lab.HOST, lab.DNS, lab.TCP, lab.LAN):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.sendto(b"control", (address, lab.DNS_PORT))
            with socket.create_connection((address, lab.TCP_PORT), timeout=1) as probe:
                probe.sendall(b"control")
        for path in logs.values():
            lab.wait_text(path, "RECEIVED")
        baseline = {key: lab.read_count(path) for key, path in logs.items()}
        policy = f"""create table inet dns_tcp_lab
add chain inet dns_tcp_lab output {{ type filter hook output priority -300; policy drop; }}
add rule inet dns_tcp_lab output oifname "lo" accept
add rule inet dns_tcp_lab output ip daddr {lab.DNS} udp dport {lab.DNS_PORT} accept
add rule inet dns_tcp_lab output ip daddr {lab.TCP} tcp dport {lab.TCP_PORT} accept
"""
        lab.run([NFT, "-f", "-"], policy)
        lab.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        lab.run(["cloud-localds", seed, "tests/lab-dns-tcp-vm-user-data", "tests/lab-vm-network-meta-data"])
        vm_sock, serial_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        bridge_sock, broker_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sockets.extend((vm_sock, serial_sock, bridge_sock, broker_sock))
        broker_log = open(os.path.join(work, "broker.log"), "w", encoding="utf-8")
        bridge_log = open(os.path.join(work, "bridge.log"), "w", encoding="utf-8")
        qemu_log = open(os.path.join(work, "qemu.log"), "w", encoding="utf-8")
        outputs.extend((broker_log, bridge_log, qemu_log))
        restricted = ["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs"]
        broker = subprocess.Popen(restricted + [sys.executable, "-u", "tests/lab-dns-tcp-egress-isolated.py",
                                               "--relay", str(broker_sock.fileno())],
                                  pass_fds=(broker_sock.fileno(),), env=ENV, stdout=broker_log, stderr=broker_log)
        broker_sock.close()
        bridge = subprocess.Popen(restricted + [sys.executable, "-u", "tests/lab-dns-tcp-serial-bridge.py",
                                               str(serial_sock.fileno()), str(bridge_sock.fileno())],
                                  pass_fds=(serial_sock.fileno(), bridge_sock.fileno()),
                                  env=ENV, stdout=bridge_log, stderr=bridge_log)
        serial_sock.close()
        bridge_sock.close()
        qemu = subprocess.Popen(restricted + [
            "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm",
            "-cpu", "host", "-m", "1024", "-smp", "2", "-nic", "none",
            "-display", "none", "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
            "-drive", f"file={overlay},format=qcow2,if=virtio",
            "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
            "-chardev", f"socket,id=broker,fd={vm_sock.fileno()}",
            "-device", "virtio-serial-pci",
            "-device", "virtserialport,chardev=broker,name=org.runnerfleet.synthetic",
        ], pass_fds=(vm_sock.fileno(),), env=ENV, stdout=qemu_log, stderr=qemu_log)
        vm_sock.close()
        slot.activate()
        wait_new(serial, "VM_BROKER_READY", timeout=240)
        for item in ("dns:dns:203.0.113.2", "tcp:tcp:fleet-response", "host:denied", "lan:denied",
                     "kernel-host-tcp:kernel-denied", "kernel-lan-tcp:kernel-denied",
                     "kernel-host-dns:kernel-denied", "kernel-lan-dns:kernel-denied",
                     "kernel-cross-tcp:kernel-denied", "kernel-cross-dns:kernel-denied"):
            wait_new(serial, "VM_RESULT=" + item, timeout=20)
        for process in (qemu, broker, bridge):
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
                    raise RuntimeError("Process holds TAP descriptor")
        time.sleep(0.5)
        after = {key: lab.read_count(path) for key, path in logs.items()}
        if after[(lab.DNS, "dns")] <= baseline[(lab.DNS, "dns")] or after[(lab.TCP, "tcp")] <= baseline[(lab.TCP, "tcp")]:
            raise RuntimeError("Allowed service received no VM request")
        for address in (lab.HOST, lab.LAN):
            for mode in ("dns", "tcp"):
                if after[(address, mode)] != baseline[(address, mode)]:
                    raise RuntimeError("Protected service got traffic")
        if after[(lab.DNS, "tcp")] != baseline[(lab.DNS, "tcp")] or after[(lab.TCP, "dns")] != baseline[(lab.TCP, "dns")]:
            raise RuntimeError("Crossed protocol reached disallowed service")
        print(f"VM DNS/TCP replies and host/LAN denials verified; receiver counts {baseline} -> {after}", flush=True)
        dns_process = processes[2]
        dns_process.send_signal(signal.SIGSTOP)
        if os.waitid(os.P_PID, dns_process.pid, os.WSTOPPED).si_code != os.CLD_STOPPED:
            raise RuntimeError("DNS receiver did not stop")
        offset = os.path.getsize(serial)
        wait_new(serial, "VM_RESULT=dns:upstream-error", offset, timeout=15)
        offset = os.path.getsize(serial)
        dns_process.send_signal(signal.SIGCONT)
        wait_new(serial, "VM_RESULT=dns:dns:203.0.113.2", offset, timeout=15)
        print("VM observed DNS timeout and subsequent successful response.", flush=True)
        slot.mark_unknown()
        broker.send_signal(signal.SIGSTOP)
        if os.waitid(os.P_PID, broker.pid, os.WSTOPPED).si_code != os.CLD_STOPPED:
            raise RuntimeError("Broker did not stop")
        time.sleep(1)
        with open(serial, encoding="utf-8", errors="replace") as source:
            settled = source.read().count("VM_RESULT=")
        time.sleep(2)
        with open(serial, encoding="utf-8", errors="replace") as source:
            if source.read().count("VM_RESULT=") != settled:
                raise RuntimeError("VM received a response during stopped broker observation")
        broker.kill()
        broker.wait(timeout=3)
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5)
        if rejected.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot did not block admission")
        for address in (lab.HOST, lab.LAN):
            for mode in ("dns", "tcp"):
                if lab.read_count(logs[(address, mode)]) != baseline[(address, mode)]:
                    raise RuntimeError("Protected service got traffic during failures")
        print("Broker SIGSTOP/SIGKILL: VM replies quiet after settling; UNKNOWN blocks admission.", flush=True)
        lab.stop(qemu)
        lab.stop(bridge)
        for process in processes:
            lab.stop(process)
        lab.run([IP, "link", "delete", "dev", "rftarget0"])
        lab.run([IP, "netns", "delete", "target"])
        lab.run([NFT, "delete", "table", "inet", "dns_tcp_lab"])
        os.unlink(overlay)
        os.unlink(seed)
        slot.release(qemu, overlay, seed)
        print("VM, broker and owned resources cleaned; slot EMPTY.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        lab.stop(qemu)
        lab.stop(bridge)
        lab.stop(broker)
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
