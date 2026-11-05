import json
import shutil
import tempfile
import unittest
from pathlib import Path
from vulncraft.cvss import CVSS31Calculator
from vulncraft.models import ScopeConfig
from vulncraft.scope import ScopeGuard
from vulncraft.sanitizer import HTTPSanitizer
from vulncraft.remediation import RemediationLibrary
from vulncraft.cli import main


class TestVulnCraftEngine(unittest.TestCase):
    def test_cvss_critical_calculation(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(score, 9.1)
        self.assertEqual(label, "CRITICAL")

    def test_cvss_high_calculation(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(score, 8.1)
        self.assertEqual(label, "HIGH")

    def test_cvss_scope_changed_xss(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(score, 5.4)
        self.assertEqual(label, "WARNING")

    def test_cvss_invalid_metric_raises_value_error(self):
        with self.assertRaises(ValueError):
            CVSS31Calculator.calculate("CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")

    def test_scope_guard_wildcard_override_and_traversal(self):
        cfg = ScopeConfig(
            program_name="TestProg",
            in_scope=["*.example.com"],
            out_of_scope=["blog.example.com", "api.example.com/v1/healthcheck"],
        )
        guard = ScopeGuard(cfg)
        self.assertTrue(guard.validate("https://app.example.com/login")[0])
        self.assertFalse(guard.validate("https://blog.example.com/post/1")[0])
        self.assertFalse(guard.validate("https://api.example.com/v1/healthcheck")[0])
        self.assertFalse(guard.validate("https://api.example.com/v1/healthcheck/deep")[0])
        # Path traversal attempt trying to bypass out-of-scope rule
        self.assertFalse(guard.validate("https://api.example.com/v1/public/../healthcheck")[0])
        self.assertFalse(guard.validate("https://evil.com")[0])

    def test_http_sanitizer_redacts_json_form_and_cookies(self):
        raw = (
            "POST /login?token=mysecret HTTP/1.1\n"
            "Host: app.example.com\n"
            "Authorization: Bearer secret_jwt_token_123\n"
            "Set-Cookie: sid=12345; Path=/; HttpOnly; Secure; SameSite=Lax\n"
            "\n"
            '{"username": "admin", "password": "PlaintextPassword!"}\n'
            "username=admin&password=FormSecretPassword123&access_token=tok999"
        )
        sanitized = HTTPSanitizer.sanitize_http_block(raw)
        self.assertNotIn("mysecret", sanitized)
        self.assertNotIn("secret_jwt_token_123", sanitized)
        self.assertNotIn("12345", sanitized)
        self.assertNotIn("PlaintextPassword!", sanitized)
        self.assertNotIn("FormSecretPassword123", sanitized)
        self.assertNotIn("tok999", sanitized)
        # Ensure cookie attributes like Path=/ and SameSite=Lax are preserved
        self.assertIn("Path=/", sanitized)
        self.assertIn("SameSite=Lax", sanitized)

    def test_remediation_enrichment(self):
        rem = RemediationLibrary.enrich("IDOR")
        self.assertIn("CWE-639", rem["cwe_id"])
        self.assertEqual(rem["lang"], "javascript")
        self.assertIn("owner_id", rem["code"])

    def test_cli_creates_missing_output_dir_and_strips_raw_secrets_in_json(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            nested_out = Path(tmp_dir) / "nonexistent_output" / "sub"
            md_path = str(nested_out / "report.md")
            html_path = str(nested_out / "dashboard.html")
            json_path = str(nested_out / "enriched.json")
            rc = main([
                "triage",
                "-f", "examples/sample_findings.json",
                "-s", "examples/sample_scope.json",
                "--md", md_path,
                "--html", html_path,
                "--json-out", json_path,
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(Path(md_path).is_file())
            self.assertTrue(Path(html_path).is_file())
            self.assertTrue(Path(json_path).is_file())
            exported_data = json.loads(Path(json_path).read_text(encoding="utf-8"))
            self.assertNotIn("raw_http_request", exported_data[0])
            self.assertNotIn("sk_live_9988776655", json.dumps(exported_data))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
