import importlib.util
import socket
import unittest

spec = importlib.util.spec_from_file_location("dns_tcp_egress", "tests/lab-dns-tcp-egress-isolated.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class DnsWireTests(unittest.TestCase):
    def test_query_and_answer_keep_transaction_and_question(self):
        query = lab.dns_query(b"\x12\x34")
        answer = lab.dns_answer(query)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertEqual(answer[:2], query[:2])
        self.assertEqual(answer[2:4], b"\x81\x80")
        self.assertEqual(answer[12:12 + len(lab.QUESTION)], lab.QUESTION)
        self.assertEqual(answer[-4:], socket.inet_aton("203.0.113.2"))
        self.assertNotEqual(answer, lab.dns_answer(lab.dns_query(b"\x12\x35")))


if __name__ == "__main__":
    unittest.main()
