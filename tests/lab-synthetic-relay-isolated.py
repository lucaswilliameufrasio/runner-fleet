#!/usr/bin/python3
"""Fixed UDP translation experiment, exclusively in disposable namespaces."""
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
spec = importlib.util.spec_from_file_location("network", "tests/lab-vm-network-isolated.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
spec = importlib.util.spec_from_file_location("slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP = network.IP
NFT = network.NFT
ENV = network.SAFE_ENV
run = network.run
SERVER = """
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 34690))
print("READY", flush=True)
first = None
requests = 0
while True:
    data, peer = s.recvfrom(1024)
    if data == b"fleet-allowed" or (data.startswith(b"fleet-allowed") and len(data) == 37):
        print("RECEIVED", flush=True)
        if sys.argv[1] == "198.51.100.2" and len(data) == 37:
            requests += 1
            identifier = struct.unpack("!Q", data[13:21])[0]
            response = b"fleet-reply" + data[13:]
            if requests == 1:
                first = response
                wrong = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                wrong.bind(("198.51.100.3", 0))
                wrong.sendto(response, peer)
                wrong.close()
                print("WRONG_SOURCE_SENT=" + str(identifier), flush=True)
            elif requests == 2:
                s.sendto(first, peer)
                print("STALE_SENT", flush=True)
                s.sendto(response, peer)
                s.sendto(response, peer)
                print("DUPLICATE_SENT", flush=True)
                print("VALID_ID=" + str(identifier), flush=True)
            else:
                s.sendto(response, peer)
        elif sys.argv[1] == "203.0.113.2" and len(data) == 37:
            s.sendto(b"fleet-reply" + data[13:], peer)
"""


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires previously verified image")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="synthetic-relay-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    stats = os.path.join(work, "relay-stats.json")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    servers, outputs = [], []
    qemu = relay = None
    sockets = []
    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "target"])
        run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        run([IP, "link", "set", "target0", "netns", "target"])
        run([IP, "link", "set", "lo", "up"])
        run([IP, "link", "set", "rftarget0", "up"])
        run([IP, "addr", "add", "198.51.100.4/24", "dev", "rftarget0"])
        run([IP, "addr", "add", "203.0.113.4/24", "dev", "rftarget0"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
        addresses = ("198.51.100.1", "198.51.100.2", "198.51.100.3", "203.0.113.2", "203.0.113.3")
        for address in addresses:
            run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/24", "dev", "target0"])
            path = os.path.join(work, address + ".log")
            output = open(path, "w", encoding="utf-8")
            outputs.append(output)
            servers.append(subprocess.Popen([IP, "netns", "exec", "target", sys.executable,
                                             "-u", "-c", SERVER, address], stdout=output, env=ENV))
            network.wait_text(path, "READY")
        # Controls establish all three receivers are reachable before output policy.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for address in addresses:
                sender.sendto(b"fleet-allowed", (address, 34690))
        for address in addresses:
            network.wait_text(os.path.join(work, address + ".log"), "RECEIVED")
        policy = """create table inet relay_test
add chain inet relay_test output { type filter hook output priority -300; policy drop; }
add rule inet relay_test output oifname "lo" accept
add rule inet relay_test output ip daddr 198.51.100.2 udp dport 34690 accept
add rule inet relay_test output ip daddr 203.0.113.2 udp dport 34690 accept
"""
        subprocess.run([NFT, "-f", "-"], input=policy, text=True, env=ENV, check=True, timeout=5)
        baseline = {}
        for address in addresses:
            with open(os.path.join(work, address + ".log"), encoding="utf-8") as source:
                baseline[address] = source.read().count("RECEIVED")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for address in ("198.51.100.1", "198.51.100.3", "203.0.113.3"):
                try:
                    sender.sendto(b"fleet-allowed", (address, 34690))
                except OSError:
                    pass
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        run(["cloud-localds", "-N", "tests/lab-boundary-network-config", seed,
             "tests/lab-synthetic-relay-user-data", "tests/lab-vm-network-meta-data"])
        vm_socket, relay_socket = socket.socketpair()
        sockets.extend((vm_socket, relay_socket))
        relay_log = open(os.path.join(work, "relay.log"), "w", encoding="utf-8")
        qemu_log = open(os.path.join(work, "qemu.log"), "w", encoding="utf-8")
        outputs.extend((relay_log, qemu_log))
        relay = subprocess.Popen(["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
                                  sys.executable, "-u", "tests/lab-synthetic-relay.py",
                                  str(relay_socket.fileno()), stats], pass_fds=(relay_socket.fileno(),),
                                 stdout=relay_log, stderr=relay_log, env=ENV)
        relay_socket.close()
        qemu = subprocess.Popen(["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
                                 "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm",
                                 "-cpu", "host", "-m", "1024", "-smp", "2", "-nic", "none",
                                 "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
                                 "-no-reboot", "-drive", f"file={overlay},format=qcow2,if=virtio",
                                 "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
                                 "-netdev", f"socket,id=lab,fd={vm_socket.fileno()}",
                                 "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12"],
                                pass_fds=(vm_socket.fileno(),), stdout=qemu_log, stderr=qemu_log, env=ENV)
        vm_socket.close()
        slot.activate()
        network.wait_text(serial, "RELAY_PROBE_READY", timeout=240)
        for process in (qemu, relay):
            with open(f"/proc/{process.pid}/status", encoding="ascii") as source:
                status = dict(line.split(":", 1) for line in source if ":" in line)
            if (int(status["CapEff"].strip(), 16) != 0
                    or int(status["CapBnd"].strip(), 16) != 0
                    or status["NoNewPrivs"].strip() != "1"):
                raise RuntimeError("QEMU or relay retained capabilities")
            for fd in os.listdir(f"/proc/{process.pid}/fd"):
                try:
                    target = os.readlink(f"/proc/{process.pid}/fd/{fd}")
                except FileNotFoundError:
                    continue
                if target == "/dev/net/tun":
                    raise RuntimeError("QEMU or relay holds a TAP descriptor")
        deadline = time.monotonic() + 15
        required = ("allowed", "replied", "allowed_second", "replied_second", "bad_reply",
                    "reply_timeout", "host", "lan", "destination", "ipv6", "l2", "spoof", "fragment", "port")
        while time.monotonic() < deadline:
            with open(stats, encoding="utf-8") as source:
                counters = json.load(source)
            if all(counters[name] > 0 for name in required) and counters["bad_reply"] >= 2:
                break
            time.sleep(0.1)
        if not all(counters[name] > 0 for name in required):
            raise RuntimeError(f"Missing observed frame category: {counters}")
        network.wait_text(serial, "RELAY_VM_REPLY_OK=", timeout=10)
        network.wait_text(serial, "RELAY_VM_SOURCE=198.51.100.2", timeout=10)
        network.wait_text(serial, "RELAY_VM_SOURCE=203.0.113.2", timeout=10)
        target_path = os.path.join(work, "198.51.100.2.log")
        with open(target_path, encoding="utf-8") as source:
            target_lines = source.read().splitlines()
        first_ids = [line.split("=", 1)[1] for line in target_lines if line.startswith("WRONG_SOURCE_SENT=")]
        valid_ids = [line.split("=", 1)[1] for line in target_lines if line.startswith("VALID_ID=")]
        if len(first_ids) != 1 or len(valid_ids) != 1 or first_ids[0] == valid_ids[0]:
            raise RuntimeError("Test did not generate distinct correlated requests")
        network.wait_text(serial, "RELAY_VM_REPLY_OK=" + valid_ids[0] + "\n", timeout=10)
        with open(serial, encoding="utf-8", errors="replace") as source:
            console = source.read()
        if "RELAY_VM_REPLY_OK=" + first_ids[0] + "\n" in console:
            raise RuntimeError("Wrong-source or stale first response was delivered")
        if console.count("RELAY_VM_REPLY_OK=" + valid_ids[0] + "\n") != 1:
            raise RuntimeError("Correlated response was not delivered exactly once in this observation")
        if counters["bad_reply"] < 2 or "STALE_SENT" not in target_lines or "DUPLICATE_SENT" not in target_lines:
            raise RuntimeError("Stale and duplicate responses were not exercised")
        time.sleep(1)
        observed = {}
        for address in baseline:
            with open(os.path.join(work, address + ".log"), encoding="utf-8") as source:
                observed[address] = source.read().count("RECEIVED")
        for address in ("198.51.100.2", "203.0.113.2"):
            if observed[address] <= baseline[address]:
                raise RuntimeError(f"Synthetic target {address} did not receive relay traffic")
        if any(observed[address] != baseline[address] for address in ("198.51.100.1", "198.51.100.3", "203.0.113.3")):
            raise RuntimeError("Protected synthetic receiver received traffic")
        print(f"Correlated IDs: first {first_ids[0]} timed out; later {valid_ids[0]} delivered; stale and duplicate rejected.", flush=True)
        print(f"VM relay categories: {counters}", flush=True)
        print(f"Receivers before {baseline}; after {observed}", flush=True)
        servers[1].send_signal(signal.SIGSTOP)
        stopped_target = os.waitid(os.P_PID, servers[1].pid, os.WSTOPPED)
        if stopped_target.si_code != os.CLD_STOPPED:
            raise RuntimeError("Target did not stop")
        prior_timeouts = counters["reply_timeout"]
        prior_second = counters["replied_second"]
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            with open(stats, encoding="utf-8") as source:
                counters = json.load(source)
            if counters["reply_timeout"] > prior_timeouts and counters["replied_second"] > prior_second:
                break
            time.sleep(0.1)
        if counters["reply_timeout"] <= prior_timeouts:
            raise RuntimeError("Target outage did not time out")
        if counters["replied_second"] <= prior_second:
            raise RuntimeError("Second synthetic target did not respond during first target outage")
        servers[1].send_signal(signal.SIGCONT)
        print(f"Target A suspended: timeouts={counters['reply_timeout']}; target B replies advanced "
              f"{prior_second}->{counters['replied_second']}.", flush=True)
        slot.mark_unknown()
        relay.send_signal(signal.SIGSTOP)
        stopped = os.waitid(os.P_PID, relay.pid, os.WSTOPPED)
        if stopped.si_code != os.CLD_STOPPED:
            raise RuntimeError("Relay did not stop")
        # Allow already-sent datagrams to arrive before measuring the quiet interval.
        time.sleep(1)
        target_paths = [os.path.join(work, address + ".log")
                        for address in ("198.51.100.2", "203.0.113.2")]
        settled = {}
        for path in target_paths:
            with open(path, encoding="utf-8") as source:
                settled[path] = source.read().count("RECEIVED")
        with open(serial, encoding="utf-8", errors="replace") as source:
            replies_settled = source.read().count("RELAY_VM_REPLY_OK")
        time.sleep(2)
        for path in target_paths:
            with open(path, encoding="utf-8") as source:
                if source.read().count("RECEIVED") != settled[path]:
                    raise RuntimeError("Target received data during stopped relay observation")
        with open(serial, encoding="utf-8", errors="replace") as source:
            if source.read().count("RELAY_VM_REPLY_OK") != replies_settled:
                raise RuntimeError("VM received replies during stopped relay observation")
        relay.kill()
        relay.wait(timeout=5)
        rejected = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                  env=ENV, capture_output=True, text=True, timeout=5)
        if rejected.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Admission not blocked")
        for address in ("198.51.100.1", "198.51.100.3", "203.0.113.3"):
            with open(os.path.join(work, address + ".log"), encoding="utf-8") as source:
                if source.read().count("RECEIVED") != baseline[address]:
                    raise RuntimeError("Protected receiver got traffic during failures")
        print("Relay SIGSTOP: both targets and VM replies quiet for 2s after settling; SIGKILL: UNKNOWN, admission refused.", flush=True)
        network.stop(qemu)
        for server in servers:
            network.stop(server)
        run([IP, "link", "delete", "dev", "rftarget0"])
        run([IP, "netns", "delete", "target"])
        run([NFT, "delete", "table", "inet", "relay_test"])
        os.unlink(overlay)
        os.unlink(seed)
        slot.release(qemu, overlay, seed)
        print("Cleanup verified; slot EMPTY.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        if relay is not None and relay.poll() is None:
            relay.send_signal(signal.SIGCONT)
        network.stop(qemu)
        network.stop(relay)
        for server in servers:
            if server.poll() is None:
                server.send_signal(signal.SIGCONT)
            network.stop(server)
        for item in sockets:
            item.close()
        for output in outputs:
            output.close()
        if os.path.exists(overlay) or os.path.exists(seed):
            print("Cleanup unverified: slot and disks retained.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
