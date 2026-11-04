import unittest
from vulncraft.cvss import CVSS31Calculator
from vulncraft.models import ScopeConfig
from vulncraft.scope import ScopeGuard
from vulncraft.sanitizer import HTTPSanitizer
from vulncraft.remediation import RemediationLibrary


class TestVulnCraftEngine(unittest.TestCase):
    def test_cvss_critical_calculation(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(score, 9.1)
        self.assertEqual(label, "CRITICAL")

    def test_cvss_high_calculation(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(score, 6.5)
        self.assertEqual(label, "WARNING")

    def test_cvss_scope_changed_xss(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(score, 5.4)
        self.assertEqual(label, "WARNING")

    def test_scope_guard_wildcard_and_override(self):
        cfg = ScopeConfig(
            program_name="TestProg",
            in_scope=["*.example.com"],
            out_of_scope=["blog.example.com", "api.example.com/health"],
        )
        guard = ScopeGuard(cfg)
        ok1, _ = guard.validate("https://app.example.com/login")
        self.assertTrue(ok1)

        ok2, _ = guard.validate("https://blog.example.com/post/1")
        self.assertFalse(ok2)

        ok3, _ = guard.validate("https://api.example.com/health")
        self.assertFalse(ok3)

        ok4, _ = guard.validate("https://evil.com")
        self.assertFalse(ok4)

    def test_http_sanitizer_redacts_secrets(self):
        raw = (
            "POST /login?token=mysecret HTTP/1.1\n"
            "Host: app.example.com\n"
            "Authorization: Bearer secret_jwt_token_123\n"
            "Cookie: sid=12345; pref=dark\n"
            "\n"
            '{"username": "admin", "password": "PlaintextPassword!"}'
        )
        sanitized = HTTPSanitizer.sanitize_http_block(raw)
        self.assertNotIn("mysecret", sanitized)
        self.assertNotIn("secret_jwt_token_123", sanitized)
        self.assertNotIn("12345", sanitized)
        self.assertNotIn("PlaintextPassword!", sanitized)
        self.assertIn("[REDACTED]", sanitized)
        self.assertIn("[REDACTED_TOKEN]", sanitized)

    def test_remediation_enrichment(self):
        rem = RemediationLibrary.enrich("IDOR")
        self.assertIn("CWE-639", rem["cwe_id"])
        self.assertIn("owner_id", rem["code"])


if __name__ == "__main__":
    unittest.main()
