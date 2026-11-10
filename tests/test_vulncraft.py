import json
import tempfile
import unittest
from pathlib import Path

from vulncraft.cli import main
from vulncraft.cvss import CVSS31Calculator
from vulncraft.models import ScopeRule
from vulncraft.sanitizer import HTTPSanitizer
from vulncraft.scope import ScopeGuard


class TestVulnCraftSuite(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.findings_path = self.base / "findings.json"
        self.scope_path = self.base / "scope.json"

        scope_data = {
            "program_name": "Test Program",
            "in_scope": ["*.acme.local", "api.acme.local/v1/*"],
            "out_of_scope": ["blog.acme.local*"],
        }
        self.scope_path.write_text(json.dumps(scope_data), encoding="utf-8")

        findings_data = [
            {
                "id": "VULN-001",
                "title": "SQL Injection in User Lookup",
                "endpoint": "https://api.acme.local/v1/users?id=1",
                "vuln_type": "SQLI",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "description": "Unsanitized parameter passed to raw SQL query.",
                "impact": "Database extraction.",
                "raw_http_request": "GET /v1/users?id=1&api_key=secret_123 HTTP/1.1\r\nHost: api.acme.local\r\nAuthorization: Bearer token_abc\r\nCookie: sid=sess_xyz\r\n\r\n",
            },
            {
                "id": "VULN-002",
                "title": "Out of Scope Blog Leak",
                "endpoint": "https://blog.acme.local/info",
                "vuln_type": "INFO_DISCLOSURE",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "description": "Server version disclosure.",
                "impact": "Info leak.",
            },
        ]
        self.findings_path.write_text(json.dumps(findings_data), encoding="utf-8")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_cvss_calculator(self):
        score, label = CVSS31Calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(score, 9.1)
        self.assertEqual(label, "CRITICAL")

    def test_scope_guard(self):
        guard = ScopeGuard(["*.acme.local", "api.acme.local/v1/*"], ["blog.acme.local*"])
        in_scope, _ = guard.validate("https://api.acme.local/v1/users")
        self.assertTrue(in_scope)

        out_scope, _ = guard.validate("https://blog.acme.local/info")
        self.assertFalse(out_scope)

    def test_http_sanitizer(self):
        raw = (
            "GET /api/data?api_key=sec_9988 HTTP/1.1\r\n"
            "Host: api.acme.local\r\n"
            "Authorization: Bearer my_secret_token_12345\r\n"
            "Cookie: session_id=session_secret_cookie_val\r\n\r\n"
            '{"password": "plain_password_123", "username": "admin"}'
        )
        sanitized = HTTPSanitizer.sanitize(raw)
        self.assertNotIn("sec_9988", sanitized)
        self.assertNotIn("my_secret_token_12345", sanitized)
        self.assertNotIn("session_secret_cookie_val", sanitized)
        self.assertNotIn("plain_password_123", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_cli_triage_flow(self):
        md_out = self.base / "report.md"
        html_out = self.base / "report.html"
        json_out = self.base / "sanitized.json"

        rc = main(
            [
                "triage",
                "-f",
                str(self.findings_path),
                "-s",
                str(self.scope_path),
                "--exclude-out-of-scope",
                "--md",
                str(md_out),
                "--html",
                str(html_out),
                "--json-out",
                str(json_out),
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(md_out.exists())
        self.assertTrue(html_out.exists())
        self.assertTrue(json_out.exists())

        md_content = md_out.read_text(encoding="utf-8")
        self.assertIn("SQL Injection in User Lookup", md_content)
        self.assertNotIn("Out of Scope Blog Leak", md_content)
        self.assertNotIn("secret_123", md_content)


if __name__ == "__main__":
    unittest.main()