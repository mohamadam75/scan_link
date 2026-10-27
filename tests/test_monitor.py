import base64
import json
import unittest

import monitor


class ConfigParsingTests(unittest.TestCase):
    def test_extracts_supported_uri_schemes(self):
        text = "\n".join([
            "vless://uuid@example.com:443?security=tls#test",
            "trojan://password@example.org:8443#test",
            "not-a-config",
        ])
        found = monitor.extract_configs(text)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].startswith("vless://"))
        self.assertTrue(found[1].startswith("trojan://"))

    def test_parses_vless_endpoint_with_query(self):
        self.assertEqual(
            monitor.endpoint("vless://uuid@example.com:443?security=tls#name"),
            ("example.com", 443),
        )

    def test_parses_bracketed_ipv6_endpoint(self):
        self.assertEqual(
            monitor.endpoint("trojan://secret@[2001:db8::1]:443#name"),
            ("2001:db8::1", 443),
        )

    def test_parses_vmess_json_endpoint(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"add": "vmess.example", "port": "8443"}).encode()
        ).decode().rstrip("=")
        self.assertEqual(
            monitor.endpoint(f"vmess://{payload}"),
            ("vmess.example", 8443),
        )

    def test_rejects_unparseable_endpoint(self):
        self.assertIsNone(monitor.endpoint("vless://not-a-valid-authority"))


if __name__ == "__main__":
    unittest.main()
