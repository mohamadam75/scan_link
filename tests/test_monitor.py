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

    def test_rejects_truncated_uri(self):
        malformed = "vless://f47c506e-9b4a-41ce-a07c-ef084c16468c@example.com:443?security=tls&extra={"
        self.assertFalse(monitor.is_valid_config(malformed))
        self.assertEqual(monitor.extract_configs(malformed), [])

    def test_builds_vless_xray_outbound(self):
        outbound = monitor.xray_outbound("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=ws&sni=example.com&path=%2Fvpn")
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["streamSettings"]["network"], "ws")

    def test_builds_trojan_xray_outbound(self):
        outbound = monitor.xray_outbound("trojan://secret@example.org:443?sni=example.org")
        self.assertEqual(outbound["protocol"], "trojan")
        self.assertEqual(outbound["settings"]["servers"][0]["password"], "secret")

    def test_skips_unsupported_scheme(self):
        self.assertIsNone(monitor.xray_outbound("hy2://secret@example.org:443"))

    def test_validates_vmess_required_fields(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"add": "vmess.example", "port": "8443", "id": "uuid"}).encode()
        ).decode().rstrip("=")
        self.assertTrue(monitor.is_valid_config(f"vmess://{payload}"))


if __name__ == "__main__":
    unittest.main()
