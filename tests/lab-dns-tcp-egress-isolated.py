#!/usr/bin/python3
"""Fixed DNS/TCP message broker experiment; not a transparent VM network."""
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
DNS = "198.51.100.2"
TCP = "198.51.100.3"
HOST = "198.51.100.1"
LAN = "198.51.100.4"
DNS_PORT = 35353
TCP_PORT = 38080
QUESTION = b"\x07service\x07example\x00\x00\x01\x00\x01"


def run(args, data=None):
    return subprocess.run(args, input=data, text=True, env=ENV, capture_output=True,
                          check=True, timeout=5).stdout


def namespace_check():
    with open("/proc/self/uid_map", encoding="ascii") as source:
        fields = source.read().split()
    if len(fields) != 3 or fields[0] != "0" or fields[1] == "0" or fields[2] != "1":
        raise RuntimeError("Requires a mapped-root disposable namespace")


def dns_query(identifier):
    return identifier + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + QUESTION


def dns_answer(query):
    return (query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + QUESTION
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04"
            + socket.inet_aton("203.0.113.2"))


def service(address, mode):
    if mode == "dns":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((address, DNS_PORT))
            print("READY", flush=True)
            while True:
                data, peer = server.recvfrom(512)
                print("RECEIVED", flush=True)
                if len(data) == 12 + len(QUESTION) and data[2:] == dns_query(data[:2])[2:]:
                    server.sendto(dns_answer(data), peer)
    elif mode == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, TCP_PORT))
            server.listen(8)
            print("READY", flush=True)
            while True:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(1)
                    data = connection.recv(128)
                    print("RECEIVED", flush=True)
                    if data == b"fleet-tcp":
                        connection.sendall(b"fleet-response")
    else:
        raise RuntimeError("Invalid fixed service")


def relay(fd):
    with open("/proc/self/status", encoding="ascii") as source:
        status = dict(line.split(":", 1) for line in source if ":" in line)
    if (int(status["CapEff"].strip(), 16) or int(status["CapBnd"].strip(), 16)
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("Relay must have no capabilities and no_new_privs")
    channel = socket.socket(fileno=fd)
    # Allow the disposable VM to boot before its first message.
    channel.settimeout(300)
    with channel:
        for _ in range(512):
            request = channel.recv(1025)
            if not request:
                return
            if len(request) > 1024:
                raise RuntimeError("Oversized broker message")
            # Fixed test operations: no untrusted address or port enters a connect call.
            if request == b"dns":
                identifier = secrets.token_bytes(2)
                query = dns_query(identifier)
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing:
                        outgoing.settimeout(1)
                        outgoing.connect((DNS, DNS_PORT))
                        outgoing.send(query)
                        result = outgoing.recv(512)
                except OSError:
                    channel.send(b"upstream-error")
                    continue
                if result != dns_answer(query):
                    raise RuntimeError("Invalid DNS response")
                channel.send(b"dns:203.0.113.2")
            elif request == b"tcp":
                with socket.create_connection((TCP, TCP_PORT), timeout=1) as outgoing:
                    outgoing.settimeout(1)
                    outgoing.sendall(b"fleet-tcp")
                    result = outgoing.recv(128)
                if result != b"fleet-response":
                    raise RuntimeError("Invalid TCP response")
                channel.send(b"tcp:fleet-response")
            elif request in (b"host", b"lan"):
                channel.send(b"denied")
            elif request in (b"kernel-host-tcp", b"kernel-lan-tcp",
                             b"kernel-host-dns", b"kernel-lan-dns",
                             b"kernel-cross-tcp", b"kernel-cross-dns"):
                # Fault injection only: bypass the application's fixed allowlist.
                if b"-host-" in request:
                    address = HOST
                elif b"-lan-" in request:
                    address = LAN
                elif request.endswith(b"-tcp"):
                    address = DNS
                else:
                    address = TCP
                udp = request.endswith(b"-dns")
                try:
                    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
                    with socket.socket(socket.AF_INET, kind) as outgoing:
                        outgoing.settimeout(1)
                        outgoing.connect((address, DNS_PORT if udp else TCP_PORT))
                        outgoing.send(b"fleet-probe")
                    channel.send(b"unexpected-allowed")
                except OSError:
                    channel.send(b"kernel-denied")
            else:
                channel.send(b"denied")


def read_count(path):
    with open(path, encoding="utf-8") as source:
        return source.read().count("RECEIVED")


def wait_text(path, text):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with open(path, encoding="utf-8") as source:
            if text in source.read():
                return
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {text} in {path}")


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGCONT)
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def main():
    namespace_check()
    if len(sys.argv) == 4 and sys.argv[1] == "--service":
        service(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--relay":
        relay(int(sys.argv[2]))
        return
    if len(sys.argv) != 1:
        raise RuntimeError("Invalid test arguments")
    work = tempfile.mkdtemp(prefix="dns-tcp-egress-", dir="/mnt/storage")
    print(f"EVIDENCE_DIR={work}", flush=True)
    processes = []
    outputs = []
    broker = None
    channels = []
    try:
        run(["mount", "-t", "tmpfs", "-o", "size=2m", "tmpfs", "/run"])
        os.mkdir("/run/netns")
        run([IP, "netns", "add", "target"])
        run([IP, "link", "add", "rftarget0", "type", "veth", "peer", "name", "target0"])
        run([IP, "link", "set", "target0", "netns", "target"])
        run([IP, "link", "set", "lo", "up"])
        run([IP, "link", "set", "rftarget0", "up"])
        run([IP, "addr", "add", "198.51.100.5/24", "dev", "rftarget0"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "lo", "up"])
        run([IP, "netns", "exec", "target", IP, "link", "set", "target0", "up"])
        logs = {}
        for address in (HOST, DNS, TCP, LAN):
            run([IP, "netns", "exec", "target", IP, "addr", "add", address + "/24", "dev", "target0"])
            for mode in ("dns", "tcp"):
                path = os.path.join(work, address + "-" + mode + ".log")
                logs[(address, mode)] = path
                output = open(path, "w", encoding="utf-8")
                outputs.append(output)
                process = subprocess.Popen([IP, "netns", "exec", "target", sys.executable,
                                            "-u", __file__, "--service", address, mode],
                                           env=ENV, stdout=output)
                processes.append(process)
                wait_text(path, "READY")
        # Prove every protected and allowed service is reachable before policy.
        for address in (HOST, DNS, TCP, LAN):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.sendto(b"control", (address, DNS_PORT))
            with socket.create_connection((address, TCP_PORT), timeout=1) as probe:
                probe.sendall(b"control")
        for path in logs.values():
            wait_text(path, "RECEIVED")
        baseline = {key: read_count(path) for key, path in logs.items()}
        policy = f"""create table inet dns_tcp_lab
add chain inet dns_tcp_lab output {{ type filter hook output priority -300; policy drop; }}
add rule inet dns_tcp_lab output oifname "lo" accept
add rule inet dns_tcp_lab output ip daddr {DNS} udp dport {DNS_PORT} accept
add rule inet dns_tcp_lab output ip daddr {TCP} tcp dport {TCP_PORT} accept
"""
        run([NFT, "-f", "-"], policy)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channels.extend((parent, child))
        parent.settimeout(3)
        broker = subprocess.Popen(["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs",
                                   sys.executable, "-u", __file__, "--relay", str(child.fileno())],
                                  env=ENV, pass_fds=(child.fileno(),))
        child.close()
        for request, expected in ((b"dns", b"dns:203.0.113.2"), (b"tcp", b"tcp:fleet-response"),
                                  (b"host", b"denied"), (b"lan", b"denied"),
                                  (b"kernel-host-tcp", b"kernel-denied"),
                                  (b"kernel-lan-tcp", b"kernel-denied"),
                                  (b"kernel-host-dns", b"kernel-denied"),
                                  (b"kernel-lan-dns", b"kernel-denied"),
                                  (b"kernel-cross-tcp", b"kernel-denied"),
                                  (b"kernel-cross-dns", b"kernel-denied")):
            parent.send(request)
            if parent.recv(1024) != expected:
                raise RuntimeError(f"Unexpected result for {request!r}")
        time.sleep(0.5)
        after = {key: read_count(path) for key, path in logs.items()}
        if after[(DNS, "dns")] <= baseline[(DNS, "dns")] or after[(TCP, "tcp")] <= baseline[(TCP, "tcp")]:
            raise RuntimeError("Approved DNS/TCP service did not receive request")
        for address in (HOST, LAN):
            for mode in ("dns", "tcp"):
                if after[(address, mode)] != baseline[(address, mode)]:
                    raise RuntimeError("Protected synthetic service received traffic")
        if (after[(DNS, "tcp")] != baseline[(DNS, "tcp")]
                or after[(TCP, "dns")] != baseline[(TCP, "dns")]):
            raise RuntimeError("Wrong service on allowed address received traffic")
        print(f"DNS and TCP responses verified; protected DNS/TCP counters unchanged: {baseline} -> {after}", flush=True)
        dns_service = processes[2]
        dns_service.send_signal(signal.SIGSTOP)
        if os.waitid(os.P_PID, dns_service.pid, os.WSTOPPED).si_code != os.CLD_STOPPED:
            raise RuntimeError("DNS service did not stop")
        parent.send(b"dns")
        if parent.recv(1024) != b"upstream-error":
            raise RuntimeError("DNS outage did not return a bounded error")
        dns_service.send_signal(signal.SIGCONT)
        parent.send(b"dns")
        if parent.recv(1024) != b"dns:203.0.113.2":
            raise RuntimeError("DNS did not recover after outage")
        print("DNS outage: bounded error; subsequent query succeeded.", flush=True)
        broker.send_signal(signal.SIGSTOP)
        stopped = os.waitid(os.P_PID, broker.pid, os.WSTOPPED)
        if stopped.si_code != os.CLD_STOPPED:
            raise RuntimeError("Relay did not stop")
        tcp_before_stall = read_count(logs[(TCP, "tcp")])
        parent.send(b"tcp")
        parent.settimeout(0.5)
        try:
            parent.recv(1024)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("Stopped relay unexpectedly answered")
        # No claim about in-flight requests: this one remained queued in the socket.
        broker.kill()
        broker.wait(timeout=3)
        time.sleep(0.3)
        if read_count(logs[(TCP, "tcp")]) != tcp_before_stall:
            raise RuntimeError("Queued request unexpectedly reached synthetic TCP target")
        for address in (HOST, LAN):
            for mode in ("dns", "tcp"):
                if read_count(logs[(address, mode)]) != baseline[(address, mode)]:
                    raise RuntimeError("Protected service received traffic during relay failure")
        print("SIGSTOP/SIGKILL: queued request received no response; protected services unchanged.", flush=True)
        for process in processes:
            stop(process)
        run([IP, "link", "delete", "dev", "rftarget0"])
        run([IP, "netns", "delete", "target"])
        run([NFT, "delete", "table", "inet", "dns_tcp_lab"])
        links = json.loads(run([IP, "-j", "link", "show"]))
        if any(entry["ifname"] == "rftarget0" for entry in links):
            raise RuntimeError("Test interface remains")
        print("Owned processes, network and policy removed.", flush=True)
    finally:
        stop(broker)
        for process in processes:
            stop(process)
        for channel in channels:
            channel.close()
        for output in outputs:
            output.close()


if __name__ == "__main__":
    main()
