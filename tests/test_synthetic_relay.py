import importlib.util
import socket
import struct
import unittest

spec = importlib.util.spec_from_file_location("relay", "tests/lab-synthetic-relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def packet(destination="198.51.100.2", source="192.0.2.2", flags=0, port=34690, payload=b"fleet-allowed" + bytes(8)):
    udp = struct.pack("!HHHH", 23456, port, 8 + len(payload), 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload),
                         23, flags, 64, 17, 0, socket.inet_aton(source), socket.inet_aton(destination))
    header = header[:10] + struct.pack("!H", relay.checksum(header)) + header[12:]
    return bytes.fromhex("02aabb0000015254005534120800") + header + udp + payload


class ClassificationTests(unittest.TestCase):
    def test_categories(self):
        cases = [
            (packet(), "allowed"),
            (packet(destination="198.51.100.1"), "host"),
            (packet(destination="198.51.100.3"), "lan"),
            (packet(destination="203.0.113.2"), "allowed"),
            (packet(destination="203.0.113.3"), "destination"),
            (packet(source="192.0.2.99"), "spoof"),
            (packet(flags=0x2000), "fragment"),
            (packet(flags=1), "fragment"),
            (packet(port=2), "port"),
            (packet(payload=b"wrong"), "malformed"),
            (packet(payload=b"fleet-allowed"), "malformed"),
            (packet(payload=b"fleet-allowed" + bytes(9)), "malformed"),
            (packet()[:-1], "malformed"),
            (packet()[:20], "malformed"),
            (b"\0" * 12 + b"\x86\xdd", "ipv6"),
            (b"\0" * 12 + b"\x88\xb5", "l2"),
            (b"", "malformed"),
        ]
        for frame, expected in cases:
            with self.subTest(expected=expected, length=len(frame)):
                self.assertEqual(relay.classify(frame), expected)

    def test_bad_header_checksum(self):
        frame = bytearray(packet())
        frame[22] ^= 1
        self.assertEqual(relay.classify(frame), "malformed")

    def test_fixed_reply_packet(self):
        frame = relay.reply_frame(b"12345678")
        self.assertEqual(frame[:6], bytes.fromhex("525400553412"))
        self.assertEqual(socket.inet_ntoa(frame[26:30]), "198.51.100.2")
        self.assertEqual(socket.inet_ntoa(frame[30:34]), "192.0.2.2")
        self.assertEqual(struct.unpack("!HH", frame[34:38]), (34690, 23456))
        self.assertEqual(frame[42:], b"fleet-reply12345678")
        self.assertEqual(relay.checksum(frame[14:34]), 0)
        self.assertEqual(socket.inet_ntoa(relay.reply_frame(b"12345678", "203.0.113.2")[26:30]), "203.0.113.2")
        with self.assertRaises(ValueError):
            relay.reply_frame(b"short")
        with self.assertRaises(ValueError):
            relay.reply_frame(b"12345678", "203.0.113.3")


if __name__ == "__main__":
    unittest.main()
