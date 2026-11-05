from typing import Dict


class RemediationLibrary:
    """
    DevFixer Remediation Knowledge Base mapping vulnerability types to CWE IDs,
    programming language syntax tags, architectural root causes, and secure Before/After code patches.
    """

    KNOWLEDGE_BASE: Dict[str, Dict[str, str]] = {
        "IDOR": {
            "cwe_id": "CWE-639: Authorization Bypass Through User-Controlled Key",
            "lang": "javascript",
            "summary": "Enforce strict object-level ownership validation on the server using the authenticated session identity before returning or modifying records.",
            "code": """// [VULNERABLE] Directly trusting user-supplied resource ID
app.get('/api/v1/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  return res.json(invoice);
});

// [SECURE PATCH] Scope query to authenticated session user_id
app.get('/api/v1/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await db.invoices.findOne({
    id: req.params.id,
    owner_id: req.user.id // Enforces strict ownership check
  });
  if (!invoice) return res.status(404).json({ error: 'Not found' });
  return res.json(invoice);
});""",
        },
        "SQLI": {
            "cwe_id": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
            "lang": "python",
            "summary": "Replace string concatenation in database queries with parameterized queries (prepared statements) to strictly separate code from user data.",
            "code": """# [VULNERABLE] Direct string formatting in SQL query
cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")

# [SECURE PATCH] Parameterized query / Prepared statement
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))""",
        },
        "XSS": {
            "cwe_id": "CWE-79: Improper Neutralization of Input During Web Page Generation",
            "lang": "javascript",
            "summary": "Apply context-aware output encoding before rendering user-controllable data in the DOM and enforce a strict Content-Security-Policy (CSP).",
            "code": """// [VULNERABLE] Unsafe sink rendering raw HTML
element.innerHTML = `Search results for: ${userQuery}`;

// [SECURE PATCH] Use safe textContent sink to prevent script execution
element.textContent = `Search results for: ${userQuery}`;""",
        },
        "RACE_CONDITION": {
            "cwe_id": "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization",
            "lang": "sql",
            "summary": "Use atomic database transactions with row-level locking (SELECT ... FOR UPDATE) or idempotency keys on state-changing financial endpoints.",
            "code": """-- [SECURE PATCH] Atomic transaction with row-level lock in PostgreSQL
BEGIN;
SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE;
-- Verify balance >= amount in application logic, then update:
UPDATE wallets SET balance = balance - $2 WHERE user_id = $1;
COMMIT;""",
        },
        "MASS_ASSIGNMENT": {
            "cwe_id": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "lang": "javascript",
            "summary": "Bind request payloads strictly to explicit Data Transfer Objects (DTOs) or allowlists rather than passing raw request bodies into ORM update methods.",
            "code": """// [VULNERABLE] Passing entire request body into ORM update
await User.update(req.body, { where: { id: req.user.id } });

// [SECURE PATCH] Explicitly allowlist safe editable fields
const { displayName, bio } = req.body;
await User.update({ displayName, bio }, { where: { id: req.user.id } });""",
        },
        "SSRF": {
            "cwe_id": "CWE-918: Server-Side Request Forgery (SSRF)",
            "lang": "python",
            "summary": "Validate user-supplied URLs against a strict domain allowlist and block connections to private/loopback IP ranges (RFC 1918, 127.0.0.0/8, 169.254.169.254).",
            "code": """# [SECURE PATCH] Validate resolved IP against private/internal networks
import ipaddress, socket
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)""",
        },
    }

    @classmethod
    def enrich(cls, vuln_type: str) -> Dict[str, str]:
        key = vuln_type.strip().upper().replace(" ", "_").replace("-", "_")
        return cls.KNOWLEDGE_BASE.get(
            key,
            {
                "cwe_id": "CWE-20: Improper Input Validation",
                "lang": "javascript",
                "summary": "Validate all untrusted inputs on the server side and enforce least-privilege access controls.",
                "code": "// Implement strict input validation and server-side authorization checks.",
            },
        )
