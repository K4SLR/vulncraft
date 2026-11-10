from typing import Dict


class RemediationLibrary:
    """DevFixer knowledge base providing CWE/OWASP categorizations and code patches."""

    BLUEPRINTS: Dict[str, Dict[str, str]] = {
        "SQLI": {
            "cwe_id": "CWE-89 / OWASP A03:2021 - Injection",
            "lang": "python",
            "summary": "Use parameterized queries (prepared statements) for all database operations and enforce strict allowlist validation on dynamic sort or filter column identifiers.",
            "references": "OWASP Top 10 A03:2021 (Injection), MITRE CWE-89, NIST SP 800-53 SI-10.",
            "code": (
                "ALLOWED_SORT_COLUMNS = {'id', 'created_at', 'username'}\n"
                "sort_col = request.args.get('sort', 'id')\n"
                "if sort_col not in ALLOWED_SORT_COLUMNS:\n"
                "    abort(400, 'Invalid sort parameter')\n"
                "cursor.execute(f'SELECT id, username FROM users WHERE org_id = %s ORDER BY {sort_col} DESC', (current_user.org_id,))"
            ),
        },
        "IDOR": {
            "cwe_id": "CWE-639 / OWASP A01:2021 - Broken Access Control",
            "lang": "python",
            "summary": "Enforce strict object-level authorization checks on every resource retrieval endpoint by verifying that the requested object belongs to the currently authenticated user session.",
            "references": "OWASP Top 10 A01:2021 (Broken Access Control), OWASP API Security API1:2023 (BOLA), MITRE CWE-639.",
            "code": (
                "document_record = db.session.execute(\n"
                "    select(Document).where(Document.id == doc_id, Document.owner_id == current_user.id)\n"
                ").scalar_one_or_none()\n"
                "if document_record is None:\n"
                "    abort(403, 'Access denied: You are not authorized to access this resource')"
            ),
        },
        "XSS": {
            "cwe_id": "CWE-79 / OWASP A03:2021 - Cross-Site Scripting (XSS)",
            "lang": "javascript",
            "summary": "Apply context-aware HTML entity encoding to all untrusted user input prior to rendering, avoid unsafe DOM sinks such as innerHTML, and enforce a strict Content-Security-Policy (CSP).",
            "references": "OWASP Top 10 A03:2021 (Injection / XSS), MITRE CWE-79, OWASP XSS Prevention Cheat Sheet.",
            "code": (
                "const safeCommentNode = document.createElement('div');\n"
                "safeCommentNode.textContent = untrustedUserInput;\n"
                "threadContainer.appendChild(safeCommentNode);"
            ),
        },
        "SSRF": {
            "cwe_id": "CWE-918 / OWASP A10:2021 - Server-Side Request Forgery",
            "lang": "python",
            "summary": "Validate outbound URL schemes and hostnames against an explicit allowlist and block all connections to private, loopback, and link-local IP ranges after DNS resolution.",
            "references": "OWASP Top 10 A10:2021 (SSRF), MITRE CWE-918, CISA Cloud Security Technical Reference.",
            "code": (
                "resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed_url.hostname))\n"
                "if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local:\n"
                "    raise ValueError('Outbound connection to internal network address blocked')"
            ),
        },
        "PATH_TRAVERSAL": {
            "cwe_id": "CWE-22 / OWASP A01:2021 - Path Traversal",
            "lang": "python",
            "summary": "Canonicalize file paths using Path.resolve() and verify that the resolved target path remains strictly inside the permitted base directory using is_relative_to().",
            "references": "OWASP Top 10 A01:2021 (Broken Access Control), MITRE CWE-22, OWASP File System Security.",
            "code": (
                "safe_base = Path('/var/app/uploads').resolve()\n"
                "target_path = (safe_base / Path(user_filename).name).resolve()\n"
                "if not target_path.is_relative_to(safe_base):\n"
                "    abort(403, 'Directory traversal attempt blocked')"
            ),
        },
        "INFO_DISCLOSURE": {
            "cwe_id": "CWE-200 / OWASP A05:2021 - Security Misconfiguration",
            "lang": "nginx",
            "summary": "Disable verbose server version banners, restrict access to sensitive configuration files, and enforce strict DTO response serialization schemas on public API endpoints.",
            "references": "OWASP Top 10 A05:2021 (Security Misconfiguration), MITRE CWE-200, CIS Benchmark Web Server Hardening.",
            "code": (
                "server_tokens off;\n"
                "proxy_hide_header X-Powered-By;\n"
                "location ~ /\\.(env|git|svn) { deny all; return 404; }"
            ),
        },
    }

    DEFAULT_BLUEPRINT = {
        "cwe_id": "CWE-284 / OWASP A01:2021 - Improper Access Control",
        "lang": "text",
        "summary": "Enforce server-side input validation, contextual output encoding, least-privilege access controls, and defense-in-depth checks across affected endpoints.",
        "references": "OWASP Application Security Verification Standard (ASVS v4.0), MITRE CWE-284.",
        "code": "# Ensure strict server-side authorization and parameter sanitization are enforced.",
    }

    @classmethod
    def get(cls, vuln_type: str) -> Dict[str, str]:
        """Retrieves remediation blueprint for a given vulnerability identifier."""
        key = (vuln_type or "").upper().strip()
        if key in ("LFI", "RFI", "TRAVERSAL"):
            key = "PATH_TRAVERSAL"
        elif key in ("BAC", "BOLA"):
            key = "IDOR"
        return cls.BLUEPRINTS.get(key, cls.DEFAULT_BLUEPRINT)