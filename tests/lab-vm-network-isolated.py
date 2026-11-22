#!/usr/bin/python3
"""Synthetic VM network experiment, exclusively in new disposable namespaces."""
import importlib.util
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import time

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
SERVER = """
import socket, sys, threading
def serve(c):
    with c:
        c.settimeout(2)
        try:
            while True:
                data = c.recv(5)
                if not data:
                    break
                print("RECEIVED", flush=True)
                c.sendall(data)
        except OSError:
            pass
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(8)
print("READY", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""


def run(args):
    return subprocess.run(args, check=True, timeout=10, env=SAFE_ENV, capture_output=True, text=True)


def wait_text(path, text, offset=0, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="utf-8", errors="replace") as source:
                source.seek(offset)
                content = source.read()
                end = source.tell()
            if text in content:
                return end
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {text}; inspect {path}")


def wait_match(path, pattern, offset=0, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with open(path, encoding="utf-8", errors="replace") as source:
            source.seek(offset)
            content = source.read()
            end = source.tell()
        match = re.search(pattern, content)
        if match:
            return end, match.group(1)
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {pattern}; inspect {path}")


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def read_line(process, timeout=5):
    deadline = time.monotonic() + timeout
    line = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Timed out waiting for watchdog")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise RuntimeError("Timed out waiting for watchdog")
        char = os.read(process.stdout.fileno(), 1)
        if not char:
            raise RuntimeError("Watchdog exited unexpectedly")
        if char == b"\n":
            return line.decode()
        line.extend(char)


def start_watchdog():
    result = run([NFT, "-s", "list", "table", "inet", "runner_fleet_lab_closed"])
    with open("/run/runner-fleet-lab-expected", "w", encoding="utf-8") as target:
        target.write(result.stdout)
    process = subprocess.Popen(
        [sys.executable, "-u", "tests/lab-network-watchdog.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=SAFE_ENV, bufsize=0,
    )
    if read_line(process) != "READY":
        stop(process)
        raise RuntimeError("Watchdog did not become ready")
    return process


def assert_tap_down():
    result = run([IP, "-j", "link", "show", "dev", "rflab0"])
    if "UP" in json.loads(result.stdout)[0]["flags"]:
        raise RuntimeError("TAP remained administratively up")


def main():
    with open("/proc/self/uid_map", encoding="ascii") as mapping:
        fields = mapping.read().split()
    if len(sys.argv) != 2 or len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a verified image and disposable mapped-root namespaces")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="synthetic-network-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    target_log = os.path.join(work, "target-receiver.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    sys.dont_write_bytecode = True
    slot_spec = importlib.util.spec_from_file_location("lab_vm_slot", "tests/lab-vm-slot.py")
    slot_module = importlib.util.module_from_spec(slot_spec)
    slot_spec.loader.exec_module(slot_module)
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    qemu = None
    renewer = None
    watchdog = None
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
        run([IP, "link", "set", "lo", "up"])
        run([IP, "link", "set", "rflab0", "up"])
        run([IP, "link", "set", "rftarget0", "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflab0"])
        run([IP, "addr", "add", "198.51.100.1/24", "dev", "rftarget0"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
        run([IP, "netns", "exec", "target", IP, "addr", "add", "198.51.100.2/24", "dev", "target0"])
        run([IP, "netns", "exec", "target", IP, "route", "add", "default", "via", "198.51.100.1"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        with open(host_log, "w", encoding="utf-8") as host_output, open(target_log, "w", encoding="utf-8") as target_output:
            servers.append(subprocess.Popen([sys.executable, "-u", "-c", SERVER, "192.0.2.1", "34680"], stdout=host_output, env=SAFE_ENV))
            servers.append(subprocess.Popen([IP, "netns", "exec", "target", sys.executable, "-u", "-c", SERVER, "198.51.100.2", "34679"], stdout=target_output, env=SAFE_ENV))
            wait_text(host_log, "READY")
            wait_text(target_log, "READY")
            run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
            run(["cloud-localds", "-N", "tests/lab-vm-network-config", seed,
                 "tests/lab-vm-network-user-data", "tests/lab-vm-network-meta-data"])
            qemu = subprocess.Popen([
                "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none",
                "-serial", f"file:{serial}", "-no-reboot",
                "-drive", f"file={overlay},format=qcow2,if=virtio",
                "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
                "-netdev", "tap,id=lab,ifname=rflab0,script=no,downscript=no",
                "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12",
            ], env=SAFE_ENV)
            slot.activate()
            cursor = wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            cursor = wait_text(serial, "FLEET_VM_HOST=DENIED", cursor, timeout=10)
            cursor = wait_text(serial, "FLEET_VM_TARGET=DENIED", cursor, timeout=10)
            print("VM: host and synthetic target denied before lease.", flush=True)
            run([NFT, "add", "element", "inet", "runner_fleet_lab_lease", "permits",
                 "{", "192.0.2.2", "timeout", "3s", "}"])
            renewer = subprocess.Popen([sys.executable, "-u", "tests/lab-vm-slot.py", "run", slot_path],
                                       stdout=subprocess.PIPE, env=SAFE_ENV)
            ready, _, _ = select.select([renewer.stdout], [], [], 5)
            if not ready or renewer.stdout.readline().strip() != b"CONTROLLER_READY":
                raise RuntimeError("Lease controller did not start")
            premature = subprocess.run(
                [sys.executable, "tests/lab-vm-slot.py", "recover", slot_path],
                env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if premature.returncode == 0 or slot.state() != "ACTIVE":
                raise RuntimeError("Recovery took over from an active controller")
            print("VM: recovery refused while the controller was alive.", flush=True)
            cursor = wait_text(serial, "FLEET_VM_TARGET=OK", cursor, timeout=15)
            cursor = wait_text(serial, "FLEET_VM_HOST=DENIED", cursor, timeout=10)
            cursor, flow_id = wait_match(serial, r"FLEET_VM_FLOW_OK=(\d+)", cursor, timeout=10)
            wait_text(target_log, "RECEIVED")
            with open(host_log, encoding="utf-8") as host_input:
                if "RECEIVED" in host_input.read():
                    raise RuntimeError("Protected host receiver got traffic")
            print("VM: synthetic target reached; host receiver saw no traffic.", flush=True)
            renewer.kill()
            renewer.wait(timeout=5)
            kill_time = time.monotonic()
            if qemu.poll() is not None:
                raise RuntimeError("VM unexpectedly stopped with the controller")
            recovered = subprocess.run(
                [sys.executable, "tests/lab-vm-slot.py", "recover", slot_path],
                env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if recovered.returncode != 0 or recovered.stdout.strip() != "SLOT UNKNOWN" or slot.state() != "UNKNOWN":
                raise RuntimeError("New controller could not retain unknown state")
            rejected = subprocess.run(
                [sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if rejected.returncode == 0 or qemu.poll() is not None:
                raise RuntimeError("Admission was not blocked with the original VM alive")
            print("VM: controller SIGKILL; recovery retained UNKNOWN and blocked admission while QEMU stayed alive.", flush=True)
            wait_text(serial, f"FLEET_VM_FLOW_CLOSED={flow_id}\n", cursor, timeout=10)
            elapsed = time.monotonic() - kill_time
            time.sleep(max(0, 3.4 - elapsed))
            with open(serial, encoding="utf-8", errors="replace") as serial_input:
                serial_input.seek(0, os.SEEK_END)
                cursor = serial_input.tell()
            wait_text(serial, "FLEET_VM_TARGET=DENIED", cursor, timeout=10)
            with open(target_log, encoding="utf-8") as target_input:
                target_before = target_input.read().count("RECEIVED")
            time.sleep(3)
            with open(target_log, encoding="utf-8") as target_input:
                if target_input.read().count("RECEIVED") != target_before:
                    raise RuntimeError("Target received traffic after lease expired")
            print(f"VM: established TCP flow {flow_id} stopped after renewer SIGKILL; receiver saw no later traffic.", flush=True)
            slot.mark_unknown()
            failed_isolation = subprocess.run([
                "/usr/sbin/capsh", "--drop=cap_net_admin", "--", "-c", "ip link set rflab0 down"
            ], env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False)
            if failed_isolation.returncode == 0 or "Operation not permitted" not in failed_isolation.stderr:
                raise RuntimeError("Expected CAP_NET_ADMIN isolation failure")
            tap = json.loads(run([IP, "-j", "link", "show", "dev", "rflab0"]).stdout)[0]
            if "UP" not in tap["flags"] or qemu.poll() is not None:
                raise RuntimeError("Expected a running VM and TAP after the injected failure")
            other = subprocess.run(
                [sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if other.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Unknown slot admitted another attempt")
            try:
                slot.release(qemu, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Live VM resources unexpectedly released the slot")
            print("VM: isolation failed with TAP up; UNKNOWN persisted and another process was denied.", flush=True)
            watchdog = start_watchdog()
            with open("/run/runner-fleet-lab-close.nft", "w", encoding="utf-8") as close_file:
                close_file.write("invalid test transaction\n")
            watchdog.stdin.write(b"close\n")
            watchdog.stdin.flush()
            if read_line(watchdog) != "ISOLATED" or read_line(watchdog) != "CLOSE_FAILED":
                raise RuntimeError("Failed close did not isolate TAP")
            assert_tap_down()
            print("VM: failed close transaction left TAP down.", flush=True)
            stop(watchdog)
            watchdog = start_watchdog()
            run([IP, "link", "set", "dev", "rflab0", "up"])
            run([NFT, "delete", "table", "inet", "runner_fleet_lab_closed"])
            if read_line(watchdog) != "POLICY_LOST" or read_line(watchdog) != "ISOLATED":
                raise RuntimeError("Partial policy loss did not isolate TAP")
            assert_tap_down()
            print("VM: partial policy deletion detected; independent TAP isolation applied.", flush=True)
            qemu.kill()
            qemu.wait(timeout=5)
            if qemu.returncode != -9:
                raise RuntimeError("Unexpected QEMU termination status")
            print("VM: owned QEMU SIGKILL confirmed and reaped.", flush=True)
            try:
                slot.release(qemu, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Residual resources unexpectedly released the slot")
            if slot.state() != "UNKNOWN":
                raise RuntimeError("Slot did not retain UNKNOWN after failed cleanup check")
            print("VM: exited QEMU alone did not release slot while resources remained.", flush=True)
            stop(renewer)
            stop(watchdog)
            for server in servers:
                stop(server)
            run([IP, "tuntap", "del", "dev", "rflab0", "mode", "tap"])
            run([IP, "link", "delete", "dev", "rftarget0"])
            run([IP, "netns", "delete", "target"])
            run([NFT, "delete", "table", "inet", "runner_fleet_lab_lease"])
            run([NFT, "list", "table", "inet", "vm_unrelated_fixture"])
            os.unlink(overlay)
            os.unlink(seed)
            slot.release(qemu, overlay, seed)
            if slot.state() != "EMPTY":
                raise RuntimeError("Slot not released after confirmed cleanup")
            other = subprocess.run(
                [sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                env=SAFE_ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if other.returncode != 0 or slot.state() != "RESERVED":
                raise RuntimeError("Slot did not admit after confirmed cleanup")
            slot.transition("RESERVED", "EMPTY")
            print("VM: cleanup verified, unrelated table preserved and admission re-enabled.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        stop(renewer)
        stop(watchdog)
        stop(qemu)
        for server in servers:
            stop(server)
        if qemu is None or qemu.poll() is not None:
            for path in (overlay, seed):
                if os.path.isfile(path):
                    os.unlink(path)
            print("Owned VM process stopped; overlay and seed removed.", flush=True)
        else:
            print("VM state unknown; disks retained for recovery.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
