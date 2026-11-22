#!/usr/bin/python3
"""Disposable VM egress through slirp, with private ranges blackholed.

The host firewall and host routes are not modified. slirp4netns runs in the
host network namespace and only attaches a tap inside a new network namespace.
"""
import ctypes
import importlib.util
import ipaddress
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("public_egress", os.path.join(ROOT, "tests", "lab-public-egress.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
spec = importlib.util.spec_from_file_location("lab_slot", os.path.join(ROOT, "tests", "lab-vm-slot.py"))
slot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slot_module)

IP = policy.IP
NFT = "/usr/sbin/nft"
ENV = policy.ENV
DOMAIN = "cicleta.lucaswilliameufrasio.com"
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA


def death_guard(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def host_ipv4_addresses():
    payload = json.loads(policy.run([IP, "-j", "-4", "addr", "show"]))
    found = []
    for link in payload:
        for item in link.get("addr_info", []):
            if item.get("family") != "inet":
                continue
            address = item.get("local")
            if address and address not in found:
                found.append(address)
    return found


def snapshot_host():
    route = policy.run([IP, "-4", "route"])
    payload = json.loads(policy.run([IP, "-j", "-4", "addr"]))
    addresses = []
    for link in payload:
        for item in link.get("addr_info", []):
            if item.get("family") != "inet":
                continue
            addresses.append((link.get("ifname"), item.get("local"), item.get("prefixlen")))
    return route, tuple(addresses)


def write_json(path, payload):
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="ascii") as output:
        json.dump(payload, output)
        output.write("\n")
    os.replace(temporary, path)


def read_json(path):
    with open(path, encoding="ascii") as source:
        return json.load(source)


def listen(stop, bindings, port, counts, path):
    sockets = []
    for address in bindings:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, port))
        server.listen(8)
        sockets.append(server)
    while not stop.is_set():
        readable, _unused, _errors = select.select(sockets, [], [], 0.2)
        for server in readable:
            client, _peer = server.accept()
            counts[sockets.index(server)] += 1
            client.close()
        write_json(path, {"counts": list(counts)})
    for server in sockets:
        server.close()


def open_tap(name):
    descriptor = os.open("/dev/net/tun", os.O_RDWR)
    request = struct.pack("16sH22s", name.encode("ascii"), IFF_TAP | IFF_NO_PI, b"")
    fcntl_ioctl(descriptor, request)
    return descriptor


def fcntl_ioctl(descriptor, request):
    import fcntl
    fcntl.ioctl(descriptor, TUNSETIFF, request)


def wait_text(path, text, timeout, offset=0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="utf-8", errors="replace") as source:
                source.seek(offset)
                if text in source.read():
                    return os.path.getsize(path)
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"Timed out waiting for {text}")


def link_exists(name):
    completed = subprocess.run(
        [IP, "link", "show", "dev", name], env=ENV, capture_output=True, text=True, timeout=5,
    )
    return completed.returncode == 0


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGCONT)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def encode_dns_name(name):
    encoded = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise RuntimeError("Invalid DNS label")
        encoded += bytes((len(raw),)) + raw
    return encoded + b"\x00"


def dns_answers(payload):
    if len(payload) < 12:
        raise RuntimeError("Short DNS payload")
    count = int.from_bytes(payload[6:8], "big")
    offset = skip_dns_name(payload, 12) + 4
    found = []
    for _index in range(count):
        offset = skip_dns_name(payload, offset)
        record_type = int.from_bytes(payload[offset:offset + 2], "big")
        length = int.from_bytes(payload[offset + 8:offset + 10], "big")
        data = payload[offset + 10:offset + 10 + length]
        if record_type == 1 and length == 4:
            found.append(socket.inet_ntoa(data))
        offset += 10 + length
    return found


def skip_dns_name(payload, offset):
    while True:
        if offset >= len(payload):
            raise RuntimeError("Truncated DNS name")
        length = payload[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def resolve_a(name):
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + encode_dns_name(name) + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
        resolver.settimeout(5)
        resolver.sendto(query, ("1.1.1.1", 53))
        payload, _source = resolver.recvfrom(1500)
    answers = dns_answers(payload)
    if not answers:
        raise RuntimeError("Authorized name has no IPv4 answer")
    for address in answers:
        if policy.destination_blocked(address):
            raise RuntimeError("Authorized name resolved to a blocked address")
    return answers


def guest_files(work, attempts, expected):
    rows = []
    for label, address, port in attempts:
        rows.append(f"    ({label!r}, {address!r}, {port}),")
    attempt_text = "\n".join(rows)
    expected_text = "\n".join(f"    {address!r}," for address in expected)
    probe = """#!/usr/bin/python3
import os
import socket
import ssl
import time

DOMAIN = __DOMAIN__
EXPECTED = (
__EXPECTED__
)
ATTEMPTS = (
__ATTEMPTS__
)

def encode(name):
    encoded = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        encoded += bytes((len(raw),)) + raw
    return encoded + b"\\x00"

def skip(payload, offset):
    while True:
        length = payload[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length

def answers(payload):
    count = int.from_bytes(payload[6:8], "big")
    offset = skip(payload, 12) + 4
    found = []
    for _index in range(count):
        offset = skip(payload, offset)
        record_type = int.from_bytes(payload[offset:offset + 2], "big")
        length = int.from_bytes(payload[offset + 8:offset + 10], "big")
        data = payload[offset + 10:offset + 10 + length]
        if record_type == 1 and length == 4:
            found.append(socket.inet_ntoa(data))
        offset += 10 + length
    return found

def resolve():
    query = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" + encode(DOMAIN) + b"\\x00\\x01\\x00\\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
        resolver.settimeout(5)
        resolver.sendto(query, ("1.1.1.1", 53))
        payload, _source = resolver.recvfrom(1500)
    return answers(payload)

def https(address):
    raw = socket.create_connection((address, 443), timeout=20)
    tls = ssl.create_default_context().wrap_socket(raw, server_hostname=DOMAIN)
    tls.sendall(b"GET / HTTP/1.1\\r\\nHost: " + DOMAIN.encode("ascii") + b"\\r\\nConnection: close\\r\\n\\r\\n")
    data = tls.recv(256)
    tls.close()
    if not data.startswith(b"HTTP/"):
        raise RuntimeError("not http")

def reach_expected():
    last = None
    for address in EXPECTED:
        try:
            https(address)
            return address
        except OSError as exc:
            last = exc
    if last is not None:
        raise last
    raise OSError("no expected address")

def host_exposure():
    with open("/proc/mounts", encoding="utf-8", errors="replace") as source:
        for line in source:
            fields = line.split()
            if len(fields) >= 3 and fields[2] in ("9p", "virtiofs", "nfs", "nfs4", "cifs", "fuse.sshfs"):
                return False
    for path in ("/mnt/host", "/run/docker.sock", "/var/run/docker.sock"):
        if os.path.exists(path):
            return False
    return True

def fill_bounded_disk():
    target = None
    for name in sorted(os.listdir("/sys/block")):
        if not name.startswith("vd"):
            continue
        sectors = int(open("/sys/block/" + name + "/size", encoding="ascii").read())
        if sectors * 512 == 64 * 1024 * 1024:
            target = "/dev/" + name
            break
    if target is None:
        raise OSError("missing bounded disk")
    block = b"x" * (1024 * 1024)
    with open(target, "wb", buffering=0) as output:
        for _index in range(80):
            output.write(block)

print("PUBLIC_PROBE_READY", flush=True)
print("HOST_FS=" + ("DENIED" if host_exposure() else "OPEN"), flush=True)
chosen = None
try:
    addresses = resolve()
    if not any(address in EXPECTED for address in addresses):
        raise OSError("dns mismatch")
    print("PUBLIC_DNS=OK", flush=True)
    chosen = reach_expected()
    print("PUBLIC_HTTPS=OK", flush=True)
except OSError:
    print("PUBLIC_DNS=DENIED", flush=True)
    print("PUBLIC_HTTPS=DENIED", flush=True)
for label, address, port in ATTEMPTS:
    try:
        with socket.create_connection((address, port), timeout=0.6):
            print(label + "=OPEN", flush=True)
    except OSError:
        print(label + "=DENIED", flush=True)
print("PUBLIC_PHASE=BASELINE", flush=True)
try:
    fill_bounded_disk()
    print("DISK_BOUND=OPEN", flush=True)
except OSError:
    print("DISK_BOUND=HELD", flush=True)
while True:
    try:
        if chosen is None:
            raise OSError("https unavailable")
        https(chosen)
        print("PUBLIC_HTTPS=OK", flush=True)
    except Exception:
        print("PUBLIC_HTTPS=DENIED", flush=True)
    time.sleep(0.4)
"""
    probe = (
        probe.replace("__DOMAIN__", repr(DOMAIN))
        .replace("__EXPECTED__", expected_text)
        .replace("__ATTEMPTS__", attempt_text)
    )
    user_data = f"""#cloud-config
write_files:
  - path: /usr/local/sbin/fleet-public-probe
    permissions: '0700'
    content: |
{indent(probe, 6)}
runcmd:
  - [sh, -c, "/usr/sbin/ip neigh replace 192.0.2.1 lladdr 52:54:00:55:34:01 dev lab0; /usr/sbin/ip -6 neigh replace fd00:2::1 lladdr 52:54:00:55:34:01 dev lab0; /usr/bin/python3 /usr/local/sbin/fleet-public-probe > /dev/ttyS0 2>&1"]
"""
    network = """version: 2
ethernets:
  lab:
    match:
      macaddress: "52:54:00:55:34:12"
    set-name: lab0
    addresses: [192.0.2.2/24, "fd00:2::2/64"]
    routes:
      - to: default
        via: 192.0.2.1
      - to: "::/0"
        via: "fd00:2::1"
    nameservers:
      addresses: [1.1.1.1, 8.8.8.8]
"""
    meta = "instance-id: runner-fleet-public-egress-1\nlocal-hostname: fleet-public-lab\n"
    paths = {}
    for name, content in (("user-data", user_data), ("network-config", network), ("meta-data", meta)):
        path = os.path.join(work, name)
        with open(path, "w", encoding="utf-8") as output:
            output.write(content)
        paths[name] = path
    return paths


def indent(text, spaces):
    pad = " " * spaces
    return "\n".join(pad + line if line else pad.rstrip() for line in text.splitlines())


def install_guard():
    lines = [
        "add table ip public_egress_nat",
        "add chain ip public_egress_nat postrouting { type nat hook postrouting priority srcnat ; policy accept ; }",
        'add rule ip public_egress_nat postrouting oifname "rfegress0" masquerade',
        "add table inet public_egress_guard",
        "add chain inet public_egress_guard forward { type filter hook forward priority -150 ; policy accept ; }",
        "add chain inet public_egress_guard input { type filter hook input priority -150 ; policy accept ; }",
        'add rule inet public_egress_guard forward iifname "rflab0" meta nfproto ipv6 drop',
        'add rule inet public_egress_guard input iifname "rflab0" drop',
    ]
    for prefix in policy.BLOCKED_V4:
        lines.append(
            f'add rule inet public_egress_guard forward iifname "rflab0" ip daddr {prefix} drop'
        )
    policy.run([NFT, "-f", "-"], "\n".join(lines) + "\n")


def drop_default_routes():
    shown = policy.run([IP, "route", "show", "default"])
    if shown.strip():
        policy.run([IP, "route", "del", "default"])
    shown = policy.run([IP, "route", "show", "default"])
    if shown.strip():
        raise RuntimeError("Default route remains in the egress namespace")


def configure_namespace(host_addresses):
    with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as output:
        output.write("1\n")
    with open("/proc/sys/net/ipv4/conf/all/rp_filter", "w", encoding="ascii") as output:
        output.write("0\n")
    policy.run([IP, "link", "set", "lo", "up"])
    policy.run([IP, "link", "set", "rfegress0", "up"])
    addresses = policy.run([IP, "-4", "addr", "show", "dev", "rfegress0"])
    if "10.0.2.15" not in addresses:
        policy.run([IP, "addr", "add", "10.0.2.15/24", "dev", "rfegress0"])
    drop_default_routes()
    for address in ("1.1.1.1", "8.8.8.8"):
        policy.run([IP, "route", "replace", address + "/32", "via", "10.0.2.2", "dev", "rfegress0"])
    policy.apply_blackholes()
    for address in host_addresses:
        if ipaddress.ip_address(address) in policy.SLIRP_NET:
            continue
        if not policy.destination_blocked(address):
            policy.run([IP, "route", "replace", "blackhole", address + "/32"])
    drop_default_routes()
    policy.assert_policy_routes()
    with socket.create_connection(("1.1.1.1", 443), timeout=8):
        pass
    for address in ("192.168.50.2", "10.1.0.1", "100.64.0.1"):
        try:
            connection = socket.create_connection((address, 443), timeout=0.5)
        except OSError:
            continue
        connection.close()
        raise RuntimeError(f"Pretest reached {address}")


V6_LISTENER = r"""
import socket, sys
address, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, port))
server.listen(8)
with open(path, "a", encoding="ascii") as output:
    output.write("READY\n")
    output.flush()
    while True:
        client, _peer = server.accept()
        client.close()
        output.write("RECEIVED\n")
        output.flush()
"""


def received_count(path):
    try:
        with open(path, encoding="ascii") as source:
            return source.read().count("RECEIVED")
    except FileNotFoundError:
        return 0


def wait_ready(path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="ascii") as source:
                if "READY" in source.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise RuntimeError("Listener did not become ready: " + os.path.basename(path))


def start_peer(work):
    peer = subprocess.Popen(["unshare", "--net", "--", "sleep", "infinity"], env=ENV)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not os.path.exists(f"/proc/{peer.pid}/ns/net"):
        if peer.poll() is not None:
            raise RuntimeError("Peer namespace exited")
        time.sleep(0.05)
    policy.run([IP, "link", "add", "rfpeer0", "type", "veth", "peer", "name", "rfpeer1"])
    policy.run([IP, "link", "set", "rfpeer1", "netns", str(peer.pid)])
    policy.run([IP, "link", "set", "rfpeer0", "up"])
    enter = ["nsenter", f"--net=/proc/{peer.pid}/ns/net"]
    policy.run([*enter, IP, "link", "set", "lo", "up"])
    policy.run([*enter, IP, "link", "set", "rfpeer1", "up"])
    policy.run([*enter, IP, "addr", "add", "198.51.100.10/24", "dev", "rfpeer1"])
    policy.run([*enter, IP, "-6", "addr", "add", "fd00:9::10/64", "dev", "rfpeer1", "nodad"])
    v4_log = os.path.join(work, "peer.log")
    v6_log = os.path.join(work, "peer6.log")
    v4 = subprocess.Popen(
        [*enter, sys.executable, "-u", "-c", policy.LISTENER, "198.51.100.10", "443", v4_log],
        env=ENV,
    )
    v6 = subprocess.Popen(
        [*enter, sys.executable, "-u", "-c", V6_LISTENER, "fd00:9::10", "443", v6_log],
        env=ENV,
    )
    wait_ready(v4_log)
    wait_ready(v6_log)
    for address in ("198.51.100.10", "fd00:9::10"):
        probe = subprocess.run(
            [*enter, sys.executable, "-c",
             "import socket,sys; socket.create_connection((sys.argv[1],443),2).close()", address],
            env=ENV, timeout=5,
        )
        if probe.returncode != 0:
            raise RuntimeError("Peer listener control failed")
    return peer, v4, v6, v4_log, v6_log


def worker():
    if sys.argv[-1] == "--hold":
        worker_hold()
        return
    if len(sys.argv) != 8:
        raise RuntimeError("Invalid worker arguments")
    _sleeper_pid = sys.argv[2]
    slirp_pid = int(sys.argv[3])
    image = sys.argv[4]
    work = sys.argv[5]
    port = int(sys.argv[6])
    counts_path = sys.argv[7]
    hosts_path = os.path.join(work, "host-addresses")
    with open(hosts_path, encoding="ascii") as source:
        host_addresses = [line.strip() for line in source if line.strip()]
    configure_namespace(host_addresses)
    public_routes = [address for address in resolve_a(DOMAIN) if address not in host_addresses]
    if not public_routes:
        raise RuntimeError("Authorized name did not resolve outside host addresses")
    for address in public_routes:
        policy.run([IP, "route", "replace", address + "/32", "via", "10.0.2.2", "dev", "rfegress0"])
    drop_default_routes()
    attempts = [
        ("DENY_10", "10.1.0.1", 443),
        ("DENY_172", "172.16.0.1", 443),
        ("DENY_192", "192.168.1.1", 443),
        ("DENY_LINKLOCAL", "169.254.1.1", 443),
        ("DENY_CGNAT", "100.64.0.1", 443),
        ("DENY_SLIRP", "10.0.2.2", port),
        ("DENY_PEER", "198.51.100.10", 443),
        ("DENY_GATEWAY", "192.0.2.1", 443),
        ("DENY_V6_ULA", "fd00::1", 443),
        ("DENY_V6_PEER", "fd00:9::10", 443),
        ("DENY_V6_GATEWAY", "fd00:2::1", 443),
        ("DENY_V6_PUBLIC", "2606:4700:4700::1111", 443),
    ]
    for index, address in enumerate(host_addresses):
        if address.startswith("127."):
            continue
        attempts.append((f"DENY_HOST_{index}", address, port))
    files = guest_files(work, attempts, public_routes)
    install_guard()
    overlay = os.path.join(work, "overlay.qcow2")
    seed = os.path.join(work, "seed.img")
    serial = os.path.join(work, "serial.log")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = None
    qemu = None
    tap = -1
    peer = v4_listener = v6_listener = gw_listener = gw6_listener = None
    peer_log = os.path.join(work, "peer.log")
    peer6_log = os.path.join(work, "peer6.log")
    gateway_log = os.path.join(work, "gateway.log")
    gateway6_log = os.path.join(work, "gateway6.log")
    bounded = os.path.join(work, "bounded.img")
    try:
        tap = open_tap("rflab0")
        policy.run([IP, "link", "set", "dev", "rflab0", "address", "52:54:00:55:34:01"])
        with open("/proc/sys/net/ipv6/conf/rflab0/accept_dad", "w", encoding="ascii") as output:
            output.write("0\n")
        policy.run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflab0"])
        policy.run([IP, "-6", "addr", "add", "fd00:2::1/64", "dev", "rflab0", "nodad"])
        policy.run([IP, "link", "set", "rflab0", "up"])
        peer, v4_listener, v6_listener, peer_log, peer6_log = start_peer(work)
        gw_listener = subprocess.Popen(
            [sys.executable, "-u", "-c", policy.LISTENER, "192.0.2.1", "443", gateway_log], env=ENV,
        )
        gw6_listener = subprocess.Popen(
            [sys.executable, "-u", "-c", V6_LISTENER, "fd00:2::1", "443", gateway6_log], env=ENV,
        )
        wait_ready(gateway_log)
        wait_ready(gateway6_log)
        for address in ("192.0.2.1", "fd00:2::1"):
            with socket.create_connection((address, 443), timeout=2):
                pass
        slot = slot_module.Slot.create(slot_path)
        slot.reserve()
        policy.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        policy.run(["qemu-img", "create", "-f", "raw", bounded, "64M"])
        policy.run([
            "cloud-localds", "-N", files["network-config"], seed, files["user-data"], files["meta-data"],
        ])
        for name in ("user-data", "host-addresses"):
            path = os.path.join(work, name) if name != "user-data" else files["user-data"]
            os.unlink(path)
        qemu_log = open(os.path.join(work, "qemu.log"), "w", encoding="utf-8")
        parent = os.getpid()
        qemu = subprocess.Popen(
            [
                "/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
                "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot",
                "-serial", f"file:{serial}",
                "-drive", f"file={overlay},format=qcow2,if=virtio",
                "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
                "-drive", f"file={bounded},format=raw,if=virtio",
                "-netdev", f"tap,id=guest,fd={tap}",
                "-device", "virtio-net-pci,netdev=guest,mac=52:54:00:55:34:12",
            ],
            pass_fds=(tap,), env=ENV, stdout=qemu_log, stderr=qemu_log,
            preexec_fn=lambda: death_guard(parent),
        )
        os.close(tap)
        tap = -1
        slot.activate()
        wait_text(serial, "PUBLIC_PROBE_READY", 300)
        wait_text(serial, "HOST_FS=DENIED", 20)
        wait_text(serial, "PUBLIC_DNS=OK", 30)
        wait_text(serial, "PUBLIC_HTTPS=OK", 40)
        for label, _address, _port in attempts:
            wait_text(serial, label + "=DENIED", 20)
        offset = wait_text(serial, "PUBLIC_PHASE=BASELINE", 20)
        baseline = read_json(counts_path)["counts"]
        time.sleep(1)
        during = read_json(counts_path)["counts"]
        if during != baseline:
            raise RuntimeError("Host listener received traffic from the VM")
        for path, label in (
            (peer_log, "peer"), (peer6_log, "ipv6 peer"),
            (gateway_log, "gateway"), (gateway6_log, "ipv6 gateway"),
        ):
            if received_count(path) != 1:
                raise RuntimeError(f"VM reached the {label} listener")
        wait_text(serial, "DISK_BOUND=HELD", 60)
        with open(bounded, "rb") as bounded_disk:
            written = bounded_disk.read(16) == b"x" * 16
        if os.path.getsize(bounded) != 64 * 1024 * 1024 or not written:
            raise RuntimeError("Bounded disk was not the disk that stopped growing")
        print(
            "PUBLIC BASELINE: DNS and HTTPS succeeded; private, peer, gateway and host attempts were denied.",
            flush=True,
        )
        os.kill(slirp_pid, signal.SIGKILL)
        wait_text(serial, "PUBLIC_HTTPS=DENIED", 40, offset)
        after = read_json(counts_path)["counts"]
        if after != baseline:
            raise RuntimeError("Host listener changed after slirp termination")
        print("SLIRP KILLED: guest HTTPS failed closed; host listeners unchanged.", flush=True)
        slot.mark_unknown()
        denied = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tests", "lab-vm-slot.py"), "reserve", slot_path],
            env=ENV, capture_output=True, text=True, timeout=5,
        )
        if denied.returncode == 0 or slot.state() != "UNKNOWN":
            raise RuntimeError("Unknown slot did not block admission")
        stop_process(qemu)
        qemu.wait(timeout=5)
        os.unlink(overlay)
        os.unlink(seed)
        for name in ("rfpeer0", "rflab0", "rfegress0"):
            if link_exists(name):
                policy.run([IP, "link", "delete", "dev", name])
        policy.run([NFT, "delete", "table", "ip", "public_egress_nat"])
        policy.run([NFT, "delete", "table", "inet", "public_egress_guard"])
        slot.release(qemu, overlay, seed)
        print("Owned VM, slirp tap and policy removed; slot EMPTY.", flush=True)
    finally:
        if tap >= 0:
            os.close(tap)
        for process in (gw_listener, gw6_listener, v4_listener, v6_listener, peer):
            stop_process(process)
        if slot is not None and slot.state() in ("RESERVED", "ACTIVE"):
            slot.mark_unknown()
        stop_process(qemu)


def worker_hold():
    if len(sys.argv) != 9:
        raise RuntimeError("Invalid hold worker arguments")
    image = sys.argv[4]
    work = sys.argv[5]
    hosts_path = os.path.join(work, "host-addresses")
    with open(hosts_path, encoding="ascii") as source:
        host_addresses = [line.strip() for line in source if line.strip()]
    configure_namespace(host_addresses)
    overlay = os.path.join(work, "overlay.qcow2")
    serial = os.path.join(work, "serial.log")
    slot = slot_module.Slot.create(os.path.join(work, "slot.sqlite3"))
    slot.reserve()
    tap = open_tap("rflab0")
    qemu = None
    try:
        policy.run([IP, "addr", "add", "192.0.2.1/24", "dev", "rflab0"])
        policy.run([IP, "link", "set", "rflab0", "up"])
        policy.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "8G"])
        parent = os.getpid()
        qemu = subprocess.Popen(
            [
                "/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
                "qemu-system-x86_64", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "512", "-smp", "1", "-display", "none", "-monitor", "none", "-no-reboot",
                "-serial", f"file:{serial}",
                "-drive", f"file={overlay},format=qcow2,if=virtio",
                "-netdev", f"tap,id=guest,fd={tap}",
                "-device", "virtio-net-pci,netdev=guest,mac=52:54:00:55:34:12",
            ],
            pass_fds=(tap,), env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=lambda: death_guard(parent),
        )
        os.close(tap)
        tap = -1
        slot.activate()
        print("HOLD_READY", flush=True)
        signal.pause()
    finally:
        if tap >= 0:
            os.close(tap)
        stop_process(qemu)


def cleanup_refusal():
    work = tempfile.mkdtemp(prefix="public-egress-cleanup-", dir="/tmp")
    slot_path = os.path.join(work, "slot.sqlite3")
    slot = slot_module.Slot.create(slot_path)
    slot.reserve()
    slot.activate()
    slot.mark_unknown()
    policy.run([IP, "link", "add", "rflab0", "type", "veth", "peer", "name", "rfpeer0"])
    qemu = subprocess.Popen(["sleep", "0"], env=ENV)
    qemu.wait(timeout=5)
    missing_overlay = os.path.join(work, "overlay.qcow2")
    missing_seed = os.path.join(work, "seed.img")

    def release_refused(expected):
        try:
            slot.release(qemu, missing_overlay, missing_seed)
        except RuntimeError as exc:
            if expected not in str(exc):
                raise
            return
        raise RuntimeError("Release accepted leftover state: " + expected)

    release_refused("Owned network interface remains")
    if slot.state() != "UNKNOWN":
        raise RuntimeError("Leftover interface did not keep the slot unknown")
    denied = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests", "lab-vm-slot.py"), "reserve", slot_path],
        env=ENV, capture_output=True, text=True, timeout=5,
    )
    if denied.returncode == 0:
        raise RuntimeError("Reserve succeeded while an interface remained")
    policy.run([IP, "link", "delete", "dev", "rflab0"])
    policy.run([NFT, "-f", "-"], "add table inet public_egress_guard\n")
    release_refused("Owned firewall table remains")
    if slot.state() != "UNKNOWN":
        raise RuntimeError("Leftover table did not keep the slot unknown")
    policy.run([NFT, "delete", "table", "inet", "public_egress_guard"])
    slot.release(qemu, missing_overlay, missing_seed)
    if slot.state() != "EMPTY":
        raise RuntimeError("Clean release did not reach EMPTY")
    print(
        "CLEANUP REFUSAL: leftover interface and table blocked release; clean release reached EMPTY.",
        flush=True,
    )


def main():
    os.chdir(ROOT)
    policy.namespace_check()
    if len(sys.argv) >= 2 and sys.argv[1] == "--worker":
        worker()
        return
    if len(sys.argv) == 2 and sys.argv[1] == "--cleanup":
        cleanup_refusal()
        return
    hold = len(sys.argv) == 3 and sys.argv[1] == "--hold"
    if hold:
        image = os.path.realpath(sys.argv[2])
    elif len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        image = os.path.realpath(sys.argv[1])
    else:
        raise RuntimeError("Requires the verified qcow2 image")
    if not os.path.isfile(image):
        raise RuntimeError("Requires the verified qcow2 image")
    if not hold:
        route_loss = subprocess.run(
            [
                "unshare", "--net", "--mount", "--", sys.executable,
                os.path.join(ROOT, "tests", "lab-public-egress.py"), "--route-loss",
            ],
            env=ENV, timeout=60,
        )
        if route_loss.returncode != 0:
            raise RuntimeError("Synthetic route-loss test failed")
    before = snapshot_host()
    addresses = host_ipv4_addresses()
    bindings = []
    for address in ["127.0.0.1", *addresses]:
        if address not in bindings:
            bindings.append(address)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    work = tempfile.mkdtemp(prefix="public-egress-vm-", dir=os.path.dirname(image))
    counts_path = os.path.join(work, "listeners.json")
    hosts_path = os.path.join(work, "host-addresses")
    with open(hosts_path, "w", encoding="ascii") as output:
        os.chmod(hosts_path, 0o600)
        for address in addresses:
            output.write(address + "\n")
    print(f"EVIDENCE_DIR={work}", flush=True)
    stop = threading.Event()
    counts = [0 for _address in bindings]
    listener = threading.Thread(target=listen, args=(stop, bindings, port, counts, counts_path), daemon=True)
    listener.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not os.path.exists(counts_path):
        time.sleep(0.05)
    for address in bindings:
        with socket.create_connection((address, port), timeout=2):
            pass
    time.sleep(0.3)
    if read_json(counts_path)["counts"] != [1 for _address in bindings]:
        raise RuntimeError("Host listeners did not observe the local control connection")
    sleeper = subprocess.Popen(["unshare", "--net", "--", "sleep", "infinity"], env=ENV)
    slirp = None
    ready_read, ready_write = os.pipe()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not os.path.exists(f"/proc/{sleeper.pid}/ns/net"):
            if sleeper.poll() is not None:
                raise RuntimeError("Network namespace exited")
            time.sleep(0.05)
        slirp = subprocess.Popen(
            [
                "slirp4netns", "--configure", "--disable-host-loopback", "--disable-dns",
                "--mtu=1500", "--cidr=10.0.2.0/24", "--ready-fd", str(ready_write),
                str(sleeper.pid), "rfegress0",
            ],
            pass_fds=(ready_write,), env=ENV,
        )
        os.close(ready_write)
        ready_write = -1
        readable, _unused, _errors = select.select([ready_read], [], [], 10)
        if not readable:
            raise RuntimeError("slirp4netns did not become ready")
        os.read(ready_read, 1)
        completed = subprocess.run(
            [
                "nsenter", f"--net=/proc/{sleeper.pid}/ns/net", "--",
                sys.executable, os.path.join(ROOT, "tests", "lab-public-egress-vm-isolated.py"),
                "--worker", str(sleeper.pid), str(slirp.pid), image, work, str(port), counts_path,
                *(["--hold"] if hold else []),
            ],
            env=ENV,
        )
        if completed.returncode != 0:
            raise RuntimeError("VM egress worker failed")
    finally:
        stop.set()
        if ready_write >= 0:
            os.close(ready_write)
        stop_process(slirp)
        stop_process(sleeper)
        after = snapshot_host()
        if after != before:
            route_before, addr_before = before
            route_after, addr_after = after
            names_before = sorted({item[0] for item in addr_before})
            names_after = sorted({item[0] for item in addr_after})
            raise RuntimeError(
                "Host routes or addresses changed: "
                f"route_lines {len(route_before.splitlines())}->{len(route_after.splitlines())}, "
                f"addr_count {len(addr_before)}->{len(addr_after)}, "
                f"ifnames {names_before}->{names_after}"
            )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, json.JSONDecodeError, socket.timeout) as exc:
        print(f"BLOCKED: {exc}", flush=True)
        raise SystemExit(1) from exc
