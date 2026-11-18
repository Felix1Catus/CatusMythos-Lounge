"""Portable tests for the fail-closed WSL network namespace policy."""

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "campaign_wsl_sandbox_test", ROOT / "scripts" / "campaign_wsl_sandbox.py")
sandbox = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sandbox)


class CampaignWslSandboxTests(unittest.TestCase):
    def test_firewall_allows_only_declared_address_protocol_and_port(self):
        rules = sandbox.build_firewall_rules(
            "cm12345678", "cmh12345678", "eth0", "10.254.42.0/30",
            {("203.0.113.8", "tcp", 443), ("192.0.2.53", "udp", 53)},
            {"192.0.2.53"},
        )
        self.assertIn("ip daddr 203.0.113.8 tcp dport 443 accept", rules)
        self.assertIn("ip daddr 192.0.2.53 udp dport 53 accept", rules)
        self.assertIn("ip daddr 192.0.2.53 udp dport 53 accept", rules)
        self.assertIn('iifname "cmh12345678" drop', rules)
        self.assertIn('meta nfproto ipv6 drop', rules)
        self.assertIn("ip saddr 10.254.42.0/30 masquerade", rules)
        self.assertNotIn("0.0.0.0/0", rules)
        self.assertNotIn("tcp dport { 1-65535 } accept", rules)

    def test_loopback_target_is_rejected_for_a_separate_network_namespace(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            sandbox._resolve_ipv4("127.0.0.1")


if __name__ == "__main__":
    unittest.main()
