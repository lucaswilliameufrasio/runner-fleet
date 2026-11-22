#!/usr/bin/python3
"""Integrate the test TAP helper and slot with a real disposable VM."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

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
HELPER = "tests/lab-tap-helper.py"
run = network.run


def helper(*args):
    return subprocess.run([sys.executable, HELPER, *args], env=ENV, capture_output=True,
                          text=True, timeout=10, check=False)


def blocked_reservation(path):
    result = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", path],
                            env=ENV, capture_output=True, text=True, timeout=5, check=False)
    if result.returncode == 0:
        raise RuntimeError("Unknown slot admitted another attempt")


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 2:
        raise RuntimeError("Requires a verified image")
    image = os.path.realpath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="tap-integrated-", dir=os.path.dirname(image))
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    host_log = os.path.join(work, "host-receiver.log")
    target_log = os.path.join(work, "target-receiver.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    print(f"EVIDENCE_DIR={work}", flush=True)
    qemu = None
    servers = []
    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "target"])
        run([NFT, "add", "table", "inet", "vm_unrelated_fixture"])
        before = run([NFT, "-s", "list", "table", "inet", "vm_unrelated_fixture"]).stdout
        created = helper("create")
        if created.returncode != 0 or created.stdout.strip() != "CREATED_TAP_CLOSED":
            raise RuntimeError(f"TAP helper could not create closed TAP: {created.stderr}")
        run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        run([IP, "link", "set", "target0", "netns", "target"])
        for interface in ("lo", "rflabvm0", "rftarget0"):
            run([IP, "link", "set", interface, "up"])
        run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflabvm0"])
        run([IP, "addr", "add", "198.51.100.1/24", "dev", "rftarget0"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
        run([IP, "netns", "exec", "target", IP, "addr", "add", "198.51.100.2/24", "dev", "target0"])
        run([IP, "netns", "exec", "target", IP, "route", "add", "default", "via", "198.51.100.1"])
        run(["/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        with open(host_log, "w", encoding="utf-8") as host_output, open(target_log, "w", encoding="utf-8") as target_output:
            servers.append(subprocess.Popen([sys.executable, "-u", "-c", network.SERVER, "192.0.2.1", "34680"], stdout=host_output, env=ENV))
            servers.append(subprocess.Popen([IP, "netns", "exec", "target", sys.executable, "-u", "-c", network.SERVER, "198.51.100.2", "34679"], stdout=target_output, env=ENV))
            network.wait_text(host_log, "READY")
            network.wait_text(target_log, "READY")
            run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
            run(["cloud-localds", "-N", "tests/lab-vm-network-config", seed,
                 "tests/lab-vm-network-user-data", "tests/lab-vm-network-meta-data"])
            qemu = subprocess.Popen([
                "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none",
                "-serial", f"file:{serial}", "-no-reboot",
                "-drive", f"file={overlay},format=qcow2,if=virtio",
                "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
                "-netdev", "tap,id=lab,ifname=rflabvm0,script=no,downscript=no",
                "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:55:34:12",
            ], env=ENV)
            slot.activate()
            cursor = network.wait_text(serial, "FLEET_VM_NET_READY", timeout=240)
            cursor = network.wait_text(serial, "FLEET_VM_HOST=DENIED", cursor, timeout=10)
            network.wait_text(serial, "FLEET_VM_TARGET=DENIED", cursor, timeout=10)
            for path in (host_log, target_log):
                with open(path, encoding="utf-8") as source:
                    if "RECEIVED" in source.read():
                        raise RuntimeError("A protected receiver got traffic")
            print("VM: helper-created closed TAP blocked host and synthetic target.", flush=True)
            slot.mark_unknown()
            failed = subprocess.run([
                "/usr/sbin/capsh", "--drop=cap_net_admin", "--", "-c",
                f"{sys.executable} {HELPER} isolate",
            ], env=ENV, capture_output=True, text=True, timeout=10, check=False)
            tap = json.loads(run([IP, "-j", "link", "show", "dev", "rflabvm0"]).stdout)[0]
            if failed.returncode == 0 or "UP" not in tap["flags"] or qemu.poll() is not None:
                raise RuntimeError("Expected isolation failure with VM active and TAP up")
            blocked_reservation(slot_path)
            print("VM: failed isolation retained UNKNOWN and blocked admission.", flush=True)
            run([IP, "link", "set", "dev", "rflabvm0", "alias", "unknown-owner"])
            if helper("isolate").returncode == 0:
                raise RuntimeError("Helper accepted changed TAP identity")
            blocked_reservation(slot_path)
            run([IP, "link", "set", "dev", "rflabvm0", "alias", "runner-fleet-tap-namespace-experiment"])
            attached = subprocess.run(
                [IP, "tuntap", "del", "dev", "rflabvm0", "mode", "tap"],
                env=ENV, capture_output=True, text=True, timeout=5, check=False,
            )
            if attached.returncode == 0 or "Device or resource busy" not in attached.stderr:
                raise RuntimeError("Kernel did not reject removal of an attached TAP")
            attempted = helper("remove")
            if attempted.returncode == 0 or qemu.poll() is not None:
                raise RuntimeError("Helper removed the TAP while QEMU still owned it")
            tap = json.loads(run([IP, "-j", "link", "show", "dev", "rflabvm0"]).stdout)[0]
            if "UP" in tap["flags"]:
                raise RuntimeError("TAP remained up after failed removal")
            run([NFT, "list", "table", "inet", "runner_fleet_tap_guard"])
            if not os.path.exists("/run/runner-fleet-tap-helper.json"):
                raise RuntimeError("Helper lost journal after failed removal")
            blocked_reservation(slot_path)
            print("VM: changed identity refused; attached TAP removal failed with guard and reservation retained.", flush=True)
            qemu.kill()
            qemu.wait(timeout=5)
            if qemu.returncode != -9:
                raise RuntimeError("QEMU termination was not confirmed")
            for server in servers:
                network.stop(server)
            os.unlink(overlay)
            os.unlink(seed)
            try:
                slot.release(qemu, overlay, seed)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Slot released before resources were removed")
            removed = helper("remove")
            if removed.returncode != 0 or removed.stdout.strip() != "REMOVED_OWNED_TAP":
                raise RuntimeError(f"Helper could not remove TAP after QEMU exit: {removed.stderr}")
            run([IP, "link", "delete", "dev", "rftarget0"])
            run([IP, "netns", "delete", "target"])
            after = run([NFT, "-s", "list", "table", "inet", "vm_unrelated_fixture"]).stdout
            if before != after:
                raise RuntimeError("Unrelated table changed")
            slot.release(qemu, overlay, seed)
            if slot.state() != "EMPTY":
                raise RuntimeError("Slot not empty after verified cleanup")
            accepted = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                      env=ENV, capture_output=True, text=True, timeout=5, check=False)
            if accepted.returncode != 0:
                raise RuntimeError("Admission not restored after verified cleanup")
            slot.transition("RESERVED", "EMPTY")
            print("VM: exited QEMU, helper cleanup verified, unrelated table retained and admission restored.", flush=True)
    finally:
        if slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        network.stop(qemu)
        for server in servers:
            network.stop(server)
        # Failure paths do not infer that helper/network cleanup succeeded.
        if qemu is not None and qemu.poll() is not None:
            for path in (overlay, seed):
                if os.path.isfile(path):
                    os.unlink(path)
            print(f"VM process stopped; disposable disks absent; slot={slot.state()}.", flush=True)


if __name__ == "__main__":
    main()
