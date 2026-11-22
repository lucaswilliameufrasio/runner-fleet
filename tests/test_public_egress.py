import importlib.util
import unittest

spec = importlib.util.spec_from_file_location("public_egress", "tests/lab-public-egress.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class DestinationPolicyTests(unittest.TestCase):
    def test_private_and_special_ranges_are_blocked(self):
        blocked = (
            "0.1.2.3",
            "10.1.0.1",
            "100.64.0.1",
            "100.127.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.0.1",
            "192.168.50.2",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fd00::1",
        )
        for address in blocked:
            with self.subTest(address=address):
                self.assertTrue(policy.destination_blocked(address))

    def test_public_and_slirp_transit_are_not_blocked(self):
        allowed = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "203.0.113.10", "192.0.2.2", "10.0.2.2", "10.0.2.15")
        for address in allowed:
            with self.subTest(address=address):
                self.assertFalse(policy.destination_blocked(address))


if __name__ == "__main__":
    unittest.main()
