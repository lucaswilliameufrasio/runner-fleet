#!/usr/bin/python3
"""Test fd-owned ephemeral TAP lifecycle in disposable namespaces."""
import array
import ctypes
import importlib.util
import json
import os
import select
import signal
import socket
import subprocess
import struct
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("lab_vm_slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
ENV = slot_module.ENV
TABLES = ("runner_fleet_fd_guard_a", "runner_fleet_fd_guard_b")


def run(args):
    return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=5, check=True).stdout


def table(name):
    return run([NFT, "-s", "list", "table", "inet", name])


def delete_unchanged(name, expected):
    if table(name) != expected:
        raise RuntimeError("Guard changed; refusing deletion")
    run([NFT, "delete", "table", "inet", name])


def absent():
    links = run([IP, "-j", "link", "show"])
    return all(item["ifname"] != "rflabvm0" for item in json.loads(links))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def probe_remaining_guard(tap_fd):
    info = json.loads(run([IP, "-j", "link", "show", "dev", "rflabvm0"]))[0]
    destination_mac = bytes.fromhex(info["address"].replace(":", ""))
    payload = b"fleet-test"
    udp = struct.pack("!HHHH", 23456, 34680, 8 + len(payload), 0)
    source = socket.inet_aton("192.0.2.2")
    destination = socket.inet_aton("192.0.2.1")
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload),
                         23, 0, 64, socket.IPPROTO_UDP, 0, source, destination)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    frame = destination_mac + bytes.fromhex("020000000002") + b"\x08\x00" + header + udp + payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("192.0.2.1", 34680))
        receiver.settimeout(1)
        os.write(tap_fd, frame)
        try:
            receiver.recvfrom(64)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("Host receiver got traffic after one guard was lost")
    entries = json.loads(run([NFT, "-j", "list", "chain", "inet", TABLES[1], "input_guard"]))
    packets = 0
    for entry in entries["nftables"]:
        for expression in entry.get("rule", {}).get("expr", []):
            packets += expression.get("counter", {}).get("packets", 0)
    if packets < 1:
        raise RuntimeError("Remaining guard did not observe the test packet")


def launch():
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(10)
    owner = subprocess.Popen([sys.executable, "-u", "tests/lab-fd-tap-owner.py", str(child.fileno())],
                             pass_fds=(child.fileno(),), env=ENV)
    child.close()
    try:
        message, ancillary, flags, _ = parent.recvmsg(32, socket.CMSG_SPACE(2 * array.array("i").itemsize))
        received = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received.frombytes(data[:len(data) - (len(data) % received.itemsize)])
        if message != b"READY" or flags & socket.MSG_CTRUNC or len(received) != 2:
            raise RuntimeError("Owner did not hand off the test handles")
        return owner, parent, received[0], received[1]
    except Exception:
        owner.terminate()
        owner.wait(timeout=5)
        parent.close()
        raise


class ConsumerExit:
    def __init__(self, owner, fd):
        self.owner = owner
        self.fd = fd

    def poll(self):
        if self.owner.poll() is None or not select.select([self.fd], [], [], 0)[0]:
            return None
        return 0


def reject_reservation(slot):
    try:
        slot.reserve()
    except RuntimeError:
        return
    raise RuntimeError("Unknown slot unexpectedly admitted work")


def cleanup_process(owner, channel, fd, tap_fd):
    if tap_fd is not None:
        os.close(tap_fd)
    if owner is not None and owner.poll() is None:
        owner.kill()
        owner.wait(timeout=5)
    if fd is not None:
        if not select.select([fd], [], [], 5)[0]:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        try:
            os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            pass
        os.close(fd)
    if channel is not None:
        channel.close()


def main():
    slot_module.namespace_check()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot become child subreaper")
    run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
    run([NFT, "add", "table", "inet", "unrelated_fixture"])
    slot = slot_module.Slot.create("/run/lab-fd-slot.sqlite3")
    owner = None
    channel = None
    child_fd = None
    tap_fd = None
    try:
        run([NFT, "add", "table", "inet", TABLES[0]])
        run([NFT, "add", "chain", "inet", TABLES[0], "foreign"])
        foreign_before = table(TABLES[0])
        collision_parent, collision_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        collision_owner = subprocess.Popen(
            [sys.executable, "-u", "tests/lab-fd-tap-owner.py", str(collision_child.fileno())],
            pass_fds=(collision_child.fileno(),), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        collision_child.close()
        collision_owner.communicate(timeout=5)
        collision_parent.close()
        if collision_owner.returncode == 0 or not absent() or table(TABLES[0]) != foreign_before:
            raise RuntimeError("Guard collision changed an existing resource")
        tables = json.loads(run([NFT, "-j", "list", "tables"]))["nftables"]
        if any(entry.get("table", {}).get("name") == TABLES[1] for entry in tables):
            raise RuntimeError("Guard collision partially created a second table")
        run([NFT, "delete", "table", "inet", TABLES[0]])
        print("Guard collision: foreign table preserved and no partial resources created.", flush=True)
        slot.reserve()
        owner, channel, child_fd, tap_fd = launch()
        slot.activate()
        original = {name: table(name) for name in TABLES}
        run([IP, "link", "set", "dev", "rflabvm0", "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflabvm0"])
        collision = subprocess.run([IP, "tuntap", "add", "dev", "rflabvm0", "mode", "tap"],
                                   env=ENV, capture_output=True, timeout=5, check=False)
        if collision.returncode == 0:
            raise RuntimeError("Concurrent TAP collision unexpectedly succeeded")
        run([NFT, "delete", "table", "inet", TABLES[0]])
        if channel.recv(32) != b"GUARD_LOST":
            raise RuntimeError("Lost guard was not detected")
        if not select.select([child_fd], [], [], 5)[0]:
            raise RuntimeError("Consumer survived guard loss")
        owner.wait(timeout=5)
        probe_remaining_guard(tap_fd)
        os.close(tap_fd)
        tap_fd = None
        if not absent() or table(TABLES[1]) != original[TABLES[1]]:
            raise RuntimeError("TAP remained or independent guard changed")
        slot.mark_unknown()
        reject_reservation(slot)
        print("Guard loss: remaining guard dropped a packet; consumer stopped and owned TAP vanished.", flush=True)
        run([IP, "tuntap", "add", "dev", "rflabvm0", "mode", "tap"])
        proof = ConsumerExit(owner, child_fd)
        try:
            slot.release(proof, "/run/no-overlay", "/run/no-seed")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Foreign same-name TAP was accepted as cleaned")
        if absent():
            raise RuntimeError("Foreign TAP was unexpectedly removed")
        run([NFT, "add", "table", "inet", TABLES[0]])
        run([NFT, "add", "chain", "inet", TABLES[0], "foreign"])
        try:
            delete_unchanged(TABLES[0], original[TABLES[0]])
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Foreign replacement table was removed")
        table(TABLES[0])
        print("Name reuse: replacement TAP and changed table retained; admission stayed blocked.", flush=True)
        # These foreign resources were created by this fixture itself, not by the owner.
        run([IP, "tuntap", "del", "dev", "rflabvm0", "mode", "tap"])
        run([NFT, "delete", "table", "inet", TABLES[0]])
        delete_unchanged(TABLES[1], original[TABLES[1]])
        slot.release(proof, "/run/no-overlay", "/run/no-seed")
        cleanup_process(owner, channel, child_fd, tap_fd)
        owner = channel = child_fd = tap_fd = None
        slot.reserve()
        owner, channel, child_fd, tap_fd = launch()
        os.close(tap_fd)
        tap_fd = None
        slot.activate()
        original = {name: table(name) for name in TABLES}
        owner.kill()
        owner.wait(timeout=5)
        if not select.select([child_fd], [], [], 5)[0]:
            raise RuntimeError("Consumer survived owner SIGKILL")
        result = os.waitid(os.P_PIDFD, child_fd, os.WEXITED)
        if result.si_code != os.CLD_KILLED or result.si_status != signal.SIGKILL:
            raise RuntimeError("Consumer did not die from parent-death SIGKILL")
        if not absent():
            raise RuntimeError("Nonpersistent TAP survived its last fd")
        slot.mark_unknown()
        reject_reservation(slot)
        print("Owner SIGKILL: child reaped via pidfd, last TAP fd closed and slot stayed UNKNOWN.", flush=True)
        for name in TABLES:
            delete_unchanged(name, original[name])
        slot.release(ConsumerExit(owner, child_fd), "/run/no-overlay", "/run/no-seed")
        table("unrelated_fixture")
        if slot.state() != "EMPTY":
            raise RuntimeError("Slot was not released after verified cleanup")
        print("Owned guards removed after checks; unrelated table preserved; slot EMPTY.", flush=True)
    finally:
        cleanup_process(owner, channel, child_fd, tap_fd)


if __name__ == "__main__":
    main()
