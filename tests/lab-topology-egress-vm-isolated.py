#!/usr/bin/python3
"""Closed topology with two reachable synthetic services and no protected links."""
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
spec = importlib.util.spec_from_file_location("lab_native", "tests/lab-native-socket-vm-isolated.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
spec = importlib.util.spec_from_file_location("lab_slot", "tests/lab-vm-slot.py")
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)
IP, NFT, ENV = lab.IP, lab.NFT, lab.ENV
PROTECTED = (lab.HOST, lab.LAN, "127.0.0.1")


def router_guard_counts(chain="input_guard"):
    result = json.loads(lab.run([IP, "netns", "exec", "router", NFT, "-j", "list",
                                 "chain", "inet", "router_local_guard", chain]))
    counts = {}
    for entry in result["nftables"]:
        rule = entry.get("rule", {})
        for expression in rule.get("expr", []):
            if "counter" in expression and rule.get("comment") in ("tcp", "udp"):
                counts[rule["comment"]] = expression["counter"]["packets"]
    return counts


def main():
    slot_module.namespace_check()
    if len(sys.argv) != 3 or sys.argv[2] not in ("direct", "router", "router-fence", "router-lan"):
        raise RuntimeError("Requires previously verified image and fixed test mode")
    image = os.path.realpath(sys.argv[1])
    scenario = sys.argv[2]
    routed = scenario in ("router", "router-fence", "router-lan")
    fenced = scenario in ("router-fence", "router-lan")
    connected_lan = scenario == "router-lan"
    work = tempfile.mkdtemp(prefix=f"topology-egress-vm-{scenario}-", dir=os.path.dirname(image))
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
        namespaces = ("target", "protected", "router") if routed else ("target", "protected")
        if connected_lan:
            namespaces += ("public",)
        for namespace in namespaces:
            lab.run([IP, "netns", "add", namespace])
            lab.run([IP, "netns", "exec", namespace, IP, "link", "set", "lo", "up"])
        lab.run([NFT, "add", "table", "inet", "topology_unrelated_fixture"])
        unrelated = lab.run([NFT, "-s", "list", "table", "inet", "topology_unrelated_fixture"])
        lab.run([IP, "link", "set", "lo", "up"])
        if routed:
            lab.run([IP, "link", "add", "rfegress0", "type", "veth", "peer", "name", "routerin0"])
            lab.run([IP, "link", "set", "routerin0", "netns", "router"])
            lab.run([IP, "link", "set", "rfegress0", "up"])
            lab.run([IP, "addr", "add", "192.0.2.5/30", "dev", "rfegress0"])
            lab.run([IP, "netns", "exec", "router", IP, "link", "set", "routerin0", "up"])
            lab.run([IP, "netns", "exec", "router", IP, "addr", "add", "192.0.2.6/30", "dev", "routerin0"])
            lab.run([IP, "link", "add", "routerout0", "type", "veth", "peer", "name", "target0"])
            lab.run([IP, "link", "set", "routerout0", "netns", "router"])
            lab.run([IP, "link", "set", "target0", "netns", "target"])
            lab.run([IP, "netns", "exec", "router", IP, "link", "set", "routerout0", "up"])
            lab.run([IP, "netns", "exec", "router", IP, "addr", "add", "198.51.100.5/32", "dev", "routerout0"])
            lab.run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
            for address in (lab.DNS, lab.TCP):
                lab.run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/32", "dev", "target0"])
                lab.run([IP, "netns", "exec", "router", IP, "route", "add", address + "/32", "dev", "routerout0"])
            lab.run([IP, "netns", "exec", "target", IP, "route", "add", "198.51.100.5/32", "dev", "target0"])
            lab.run([IP, "netns", "exec", "target", IP, "route", "add", "192.0.2.4/30",
                     "via", "198.51.100.5", "dev", "target0", "onlink"])
            lab.run([IP, "route", "add", "default", "via", "192.0.2.6"])
            lab.run([IP, "netns", "exec", "router", "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        else:
            lab.run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
            lab.run([IP, "link", "set", "target0", "netns", "target"])
            lab.run([IP, "link", "set", "rftarget0", "up"])
            lab.run([IP, "addr", "add", "198.51.100.5/32", "dev", "rftarget0"])
            lab.run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
            for address in (lab.DNS, lab.TCP):
                lab.run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/32", "dev", "target0"])
                lab.run([IP, "route", "add", address + "/32", "dev", "rftarget0"])
            lab.run([IP, "netns", "exec", "target", IP, "route", "add", "198.51.100.5/32", "dev", "target0"])
        for address in (lab.HOST, lab.LAN):
            lab.run([IP, "netns", "exec", "protected", IP, "addr", "add", address + "/32", "dev", "lo"])
        if connected_lan:
            lab.run([IP, "link", "add", "routerlan0", "type", "veth", "peer", "name", "lanpeer"])
            lab.run([IP, "link", "set", "routerlan0", "netns", "router"])
            lab.run([IP, "link", "set", "lanpeer", "netns", "protected"])
            lab.run([IP, "netns", "exec", "router", IP, "link", "set", "routerlan0", "up"])
            lab.run([IP, "netns", "exec", "router", IP, "addr", "add", "192.0.3.1/30", "dev", "routerlan0"])
            lab.run([IP, "netns", "exec", "protected", IP, "link", "set", "lanpeer", "up"])
            lab.run([IP, "netns", "exec", "protected", IP, "addr", "add", "192.0.3.2/30", "dev", "lanpeer"])
            for address in (lab.HOST, lab.LAN):
                lab.run([IP, "netns", "exec", "router", IP, "route", "add", address + "/32", "via", "192.0.3.2"])
            lab.run([IP, "netns", "exec", "protected", IP, "route", "add", "192.0.2.4/30", "via", "192.0.3.1"])
            lab.run([IP, "link", "add", "routerpub0", "type", "veth", "peer", "name", "public0"])
            lab.run([IP, "link", "set", "routerpub0", "netns", "router"])
            lab.run([IP, "link", "set", "public0", "netns", "public"])
            lab.run([IP, "netns", "exec", "router", IP, "link", "set", "routerpub0", "up"])
            lab.run([IP, "netns", "exec", "router", IP, "addr", "add", "203.0.113.1/30", "dev", "routerpub0"])
            lab.run([IP, "netns", "exec", "public", IP, "link", "set", "public0", "up"])
            lab.run([IP, "netns", "exec", "public", IP, "addr", "add", "203.0.113.2/30", "dev", "public0"])
            lab.run([IP, "netns", "exec", "public", IP, "addr", "add", "203.0.113.10/32", "dev", "lo"])
            lab.run([IP, "netns", "exec", "router", IP, "route", "add", "default", "via", "203.0.113.2"])
            lab.run([IP, "netns", "exec", "public", IP, "route", "add", "192.0.2.4/30", "via", "203.0.113.1"])
        # Temporary test link proves host/LAN fixtures are actually reachable.
        lab.run([IP, "link", "add", "rfprobe0", "type", "veth", "peer", "name", "probepeer"])
        lab.run([IP, "link", "set", "probepeer", "netns", "protected"])
        lab.run([IP, "link", "set", "rfprobe0", "up"])
        lab.run([IP, "addr", "add", "192.0.2.1/30", "dev", "rfprobe0"])
        lab.run([IP, "netns", "exec", "protected", IP, "link", "set", "probepeer", "up"])
        lab.run([IP, "netns", "exec", "protected", IP, "addr", "add", "192.0.2.2/30", "dev", "probepeer"])
        for address in (lab.HOST, lab.LAN):
            lab.run([IP, "route", "add", address + "/32", "via", "192.0.2.2"])
        logs = {}
        addresses = (lab.HOST, lab.DNS, lab.TCP, lab.LAN, "127.0.0.1")
        if routed:
            addresses += ("192.0.2.6",)
        if connected_lan:
            addresses += ("203.0.113.10",)
        for address in addresses:
            if address in PROTECTED:
                namespace = "protected"
            elif address == "192.0.2.6":
                namespace = "router"
            elif address == "203.0.113.10":
                namespace = "public"
            else:
                namespace = "target"
            for protocol in ("dns", "tcp"):
                path = os.path.join(work, address + "-" + protocol + ".log")
                logs[(address, protocol)] = path
                output = open(path, "w", encoding="utf-8")
                outputs.append(output)
                process = subprocess.Popen([
                    IP, "netns", "exec", namespace, sys.executable, "-u",
                    "tests/lab-dns-tcp-egress-isolated.py", "--service", address, protocol,
                ], env=ENV, stdout=output)
                processes.append(process)
                lab.wait_text(path, "READY")
        control_addresses = (lab.HOST, lab.DNS, lab.TCP, lab.LAN)
        if routed:
            control_addresses += ("192.0.2.6",)
        if connected_lan:
            control_addresses += ("203.0.113.10",)
        for address in control_addresses:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.sendto(b"control", (address, lab.DNS_PORT))
            with socket.create_connection((address, lab.TCP_PORT), timeout=1) as probe:
                probe.sendall(b"control")
        loopback_probe = (
            "import socket; "
            "u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            f"u.sendto(b'control',('127.0.0.1',{lab.DNS_PORT})); "
            f"s=socket.create_connection(('127.0.0.1',{lab.TCP_PORT}),timeout=1); "
            "s.sendall(b'control'); s.close()"
        )
        lab.run([IP, "netns", "exec", "protected", sys.executable, "-c", loopback_probe])
        for path in logs.values():
            lab.wait_text(path, "RECEIVED")
        baseline = {key: lab.read_count(path) for key, path in logs.items()}
        lab.run([IP, "link", "delete", "dev", "rfprobe0"])
        for address in (lab.HOST, lab.LAN):
            command = [IP, "route", "get", address]
            if routed:
                command = [IP, "netns", "exec", "router", *command]
            route = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=5)
            if (route.returncode == 0) != connected_lan:
                raise RuntimeError(f"Unexpected route to protected address {address}: {route.stdout}")
        routes = json.loads(lab.run([IP, "-j", "route", "show"]))
        has_default = any(item.get("dst") == "default" for item in routes)
        if has_default != routed:
            raise RuntimeError("Translator default route does not match test scenario")
        if lab.run(["ss", "-H", "-lntup"]).strip():
            raise RuntimeError("Translator namespace contains an IP listener")
        route_state = "present at router" if connected_lan else f"absent at {'router' if routed else 'translator'}"
        print(f"Positive controls passed; protected routes {route_state}; translator default={has_default}; no translator IP listeners.", flush=True)
        if fenced:
            router_policy = """create table inet router_local_guard
add chain inet router_local_guard input_guard { type filter hook input priority -320; policy accept; }
add rule inet router_local_guard input_guard iifname "routerin0" meta l4proto tcp counter drop comment "tcp"
add rule inet router_local_guard input_guard iifname "routerin0" meta l4proto udp counter drop comment "udp"
add rule inet router_local_guard input_guard iifname "routerin0" counter drop
"""
            if connected_lan:
                router_policy += """add chain inet router_local_guard forward_guard { type filter hook forward priority -320; policy accept; }
add rule inet router_local_guard forward_guard iifname "routerin0" ip daddr { 198.51.100.1, 198.51.100.4 } meta l4proto tcp counter drop comment "tcp"
add rule inet router_local_guard forward_guard iifname "routerin0" ip daddr { 198.51.100.1, 198.51.100.4 } meta l4proto udp counter drop comment "udp"
add rule inet router_local_guard forward_guard iifname "routerin0" ip daddr { 198.51.100.1, 198.51.100.4 } counter drop
"""
            lab.run([IP, "netns", "exec", "router", NFT, "-f", "-"], router_policy)
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
            "-monitor", "none", "-netdev", f"socket,id=wire,fd={net_sock.fileno()}",
            "-netdev", "user,id=nat,ipv6=off", "-netdev", "hubport,id=wireport,hubid=0,netdev=wire",
            "-netdev", "hubport,id=natport,hubid=0,netdev=nat",
        ], pass_fds=(net_sock.fileno(),), env=ENV, stdout=backend_log, stderr=backend_log,
            preexec_fn=lambda: native.death_guard(parent))
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
            preexec_fn=lambda: native.death_guard(parent))
        vm_sock.close()
        slot.activate()
        network.wait_text(serial, "NATIVE_PROBE_READY", timeout=240)
        network.wait_text(serial, "NATIVE_DNS=OK", timeout=30)
        network.wait_text(serial, "NATIVE_TCP=OK", timeout=30)
        native.verify_process(qemu)
        native.verify_process(backend)
        if routed:
            router_link = [IP, "netns", "exec", "router", IP, "-j", "-s", "link", "show", "dev", "routerout0"]
            router_before = json.loads(lab.run(router_link))[0]["stats64"]["tx"]["packets"]
        if fenced:
            fence_before = router_guard_counts()
            if connected_lan:
                forward_before = router_guard_counts("forward_guard")
        slot.mark_unknown()
        lab.run([NFT, "delete", "table", "inet", "native_socket_lab"])
        tables = json.loads(lab.run([NFT, "-j", "list", "tables"]))["nftables"]
        if any(entry.get("table", {}).get("name") == "native_socket_lab" for entry in tables):
            raise RuntimeError("Experimental policy remains")
        offset = os.path.getsize(serial)
        for target in ("DNS", "TCP"):
            network.wait_text(serial, f"NATIVE_{target}=OK", offset, timeout=25)
        if connected_lan:
            for protocol in ("DNS", "TCP"):
                network.wait_text(serial, f"NATIVE_PUBLIC_{protocol}=OK", offset, timeout=30)
        for target in ("HOST", "LAN", "GATEWAY"):
            network.wait_text(serial, f"NATIVE_{target}=DENIED", offset, timeout=20)
            network.wait_text(serial, f"NATIVE_{target}_DNS=DENIED", offset, timeout=20)
        if routed:
            expected_router = "DENIED" if fenced else "OK"
            network.wait_text(serial, f"NATIVE_ROUTER={expected_router}", offset, timeout=20)
            network.wait_text(serial, f"NATIVE_ROUTER_DNS={expected_router}", offset, timeout=20)
        after = {key: lab.read_count(path) for key, path in logs.items()}
        for address in PROTECTED:
            for protocol in ("dns", "tcp"):
                if after[(address, protocol)] != baseline[(address, protocol)]:
                    raise RuntimeError("Protected synthetic receiver got traffic")
        if after[(lab.DNS, "dns")] <= baseline[(lab.DNS, "dns")] or after[(lab.TCP, "tcp")] <= baseline[(lab.TCP, "tcp")]:
            raise RuntimeError("Allowed services received no traffic")
        if routed:
            for protocol in ("dns", "tcp"):
                current = after[("192.0.2.6", protocol)]
                before = baseline[("192.0.2.6", protocol)]
                if fenced and current != before:
                    raise RuntimeError("Router-local service received traffic despite guard")
                if not fenced and current <= before:
                    raise RuntimeError("Router-local service did not receive guest traffic")
            router_after = json.loads(lab.run(router_link))[0]["stats64"]["tx"]["packets"]
            if router_after <= router_before:
                raise RuntimeError("Router did not forward new frames after policy removal")
            print(f"Router outgoing packets advanced {router_before}->{router_after} after policy removal.", flush=True)
            if fenced:
                fence_after = router_guard_counts()
                if any(fence_after.get(protocol, 0) <= fence_before.get(protocol, 0) for protocol in ("tcp", "udp")):
                    raise RuntimeError(f"Router guard did not see both protocols: {fence_before} -> {fence_after}")
                print(f"Router-local guard counters {fence_before} -> {fence_after}; receivers unchanged.", flush=True)
                if connected_lan:
                    forward_after = router_guard_counts("forward_guard")
                    if any(forward_after.get(protocol, 0) <= forward_before.get(protocol, 0) for protocol in ("tcp", "udp")):
                        raise RuntimeError(f"Router forward guard did not see both protocols: {forward_before} -> {forward_after}")
                    for protocol in ("dns", "tcp"):
                        if after[("203.0.113.10", protocol)] <= baseline[("203.0.113.10", protocol)]:
                            raise RuntimeError("Synthetic public receiver did not get guest traffic")
                    print(f"Router LAN guard {forward_before} -> {forward_after}; synthetic public DNS/TCP responded.", flush=True)
            else:
                print("ISOLATION GAP: router-local DNS and TCP services reachable after policy loss.", flush=True)
        print(f"Policy removed: allowed DNS/TCP worked; protected receivers unchanged: {baseline} -> {after}", flush=True)
        with open(os.path.join(work, "counts.json"), "w", encoding="utf-8") as output:
            json.dump({f"{address}-{protocol}": after[(address, protocol)] for address, protocol in after}, output)
        denied = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                env=ENV, capture_output=True, text=True, timeout=5)
        if denied.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot did not block admission")
        backend.send_signal(signal.SIGSTOP)
        if os.waitid(os.P_PID, backend.pid, os.WSTOPPED).si_code != os.CLD_STOPPED:
            raise RuntimeError("Backend did not stop")
        time.sleep(1)
        offset = os.path.getsize(serial)
        network.wait_text(serial, "NATIVE_DNS=DENIED", offset, timeout=20)
        network.wait_text(serial, "NATIVE_TCP=DENIED", offset, timeout=20)
        offset = os.path.getsize(serial)
        backend.send_signal(signal.SIGCONT)
        network.wait_text(serial, "NATIVE_DNS=OK", offset, timeout=30)
        network.wait_text(serial, "NATIVE_TCP=OK", offset, timeout=30)
        if fenced:
            for protocol in ("dns", "tcp"):
                if lab.read_count(logs[("192.0.2.6", protocol)]) != baseline[("192.0.2.6", protocol)]:
                    raise RuntimeError("Router-local receiver changed while guard remained installed")
            # Demonstrate separately that loss of this new guard remains unsafe.
            offset = os.path.getsize(serial)
            lab.run([IP, "netns", "exec", "router", NFT, "delete", "table", "inet", "router_local_guard"])
            network.wait_text(serial, "NATIVE_ROUTER=OK", offset, timeout=30)
            network.wait_text(serial, "NATIVE_ROUTER_DNS=OK", offset, timeout=30)
            for protocol in ("dns", "tcp"):
                if lab.read_count(logs[("192.0.2.6", protocol)]) <= baseline[("192.0.2.6", protocol)]:
                    raise RuntimeError("Guard-loss positive control did not reach router-local receiver")
            if connected_lan:
                for target in ("HOST", "LAN"):
                    network.wait_text(serial, f"NATIVE_{target}=OK", offset, timeout=30)
                    network.wait_text(serial, f"NATIVE_{target}_DNS=OK", offset, timeout=30)
                for address in (lab.HOST, lab.LAN):
                    for protocol in ("dns", "tcp"):
                        if lab.read_count(logs[(address, protocol)]) <= baseline[(address, protocol)]:
                            raise RuntimeError("Guard-loss positive control did not reach synthetic LAN")
                print("ISOLATION GAP: router guard deletion exposed host and LAN DNS/TCP.", flush=True)
            denied = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                    env=ENV, capture_output=True, text=True, timeout=5)
            if denied.returncode == 0 or slot.state() != "UNKNOWN":
                raise RuntimeError("Admission was not blocked after router guard loss")
            print("ISOLATION GAP: loss of router-local guard exposed router DNS and TCP.", flush=True)
        backend.kill()
        backend.wait(timeout=5)
        denied = subprocess.run([sys.executable, "tests/lab-vm-slot.py", "reserve", slot_path],
                                env=ENV, capture_output=True, text=True, timeout=5)
        if denied.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot did not block admission after backend death")
        for address in PROTECTED:
            for protocol in ("dns", "tcp"):
                if connected_lan and address in (lab.HOST, lab.LAN):
                    continue
                if lab.read_count(logs[(address, protocol)]) != baseline[(address, protocol)]:
                    raise RuntimeError("Protected receiver changed during fault tests")
        print("Backend stop/resume: guest traffic stopped and recovered; backend killed; slot stayed UNKNOWN.", flush=True)
        lab.stop(qemu)
        for process in processes:
            lab.stop(process)
        os.unlink(overlay)
        os.unlink(seed)
        try:
            slot.release(qemu, overlay, seed)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Slot released while namespaces remained")
        lab.run([IP, "link", "delete", "dev", "rfegress0" if routed else "rftarget0"])
        for namespace in namespaces:
            lab.run([IP, "netns", "delete", namespace])
        if lab.run([NFT, "-s", "list", "table", "inet", "topology_unrelated_fixture"]) != unrelated:
            raise RuntimeError("Unrelated firewall table changed")
        slot.release(qemu, overlay, seed)
        print("Owned resources removed; unrelated table preserved; slot EMPTY.", flush=True)
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
