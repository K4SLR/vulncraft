import html
from datetime import datetime, timezone
from typing import List
from .models import Finding, ScopeRule


class ReportExporter:
    """Generates structured Markdown and CSP-hardened HTML vulnerability reports."""

    SEVERITY_BADGES = {
        "CRITICAL": "background:#dc2626;color:#ffffff;",
        "HIGH": "background:#ea580c;color:#ffffff;",
        "WARNING": "background:#d97706;color:#ffffff;",
        "LOW": "background:#2563eb;color:#ffffff;",
        "INFO": "background:#4b5563;color:#ffffff;",
    }

    @classmethod
    def to_markdown(cls, findings: List[Finding], scope_rule: ScopeRule) -> str:
        """Builds publication-ready Markdown PoC document."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"# Vulnerability Assessment & PoC Report",
            f"**Target Program:** {scope_rule.program_name}  ",
            f"**Generated:** {now}  ",
            f"**Security Researcher:** k4slr  ",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Finding ID | Severity | CVSS | Type | Scope Status | Target Endpoint |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for f in findings:
            scope_str = "IN-SCOPE" if f.in_scope else "**OUT-OF-SCOPE**"
            lines.append(
                f"| `{f.id}` | **{f.severity_label}** | {f.cvss_score:.1f} | `{f.vuln_type}` | {scope_str} | `{f.endpoint}` |"
            )

        lines.extend(["", "---", "", "## Technical Details", ""])

        for idx, f in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {idx}. [{f.id}] {f.title}",
                    "",
                    f"- **Severity Rating:** {f.severity_label} (CVSS Base Score: `{f.cvss_score:.1f}`)",
                    f"- **CVSS v3.1 Vector:** `{f.cvss_vector}`",
                    f"- **CWE Classification:** {f.cwe_id}",
                    f"- **Target Endpoint:** `{f.endpoint}`",
                    f"- **Scope Status:** {'In-Scope' if f.in_scope else 'Out-of-Scope'}",
                    "",
                    "#### Description",
                    f"{f.description}",
                    "",
                    "#### Impact",
                    f"{f.impact}",
                    "",
                    "#### Steps to Reproduce",
                ]
            )

            if f.steps_to_reproduce:
                for s_idx, step in enumerate(f.steps_to_reproduce, 1):
                    lines.append(f"{s_idx}. {step}")
            else:
                lines.append("1. Follow standard reproduction protocol against the affected endpoint.")

            lines.append("")

            if f.redacted_request:
                lines.extend(
                    [
                        "#### Proof of Concept: Sanitized HTTP Request",
                        "```http",
                        f.redacted_request,
                        "```",
                        "",
                    ]
                )

            if f.redacted_response:
                lines.extend(
                    [
                        "#### Proof of Concept: Sanitized HTTP Response",
                        "```http",
                        f.redacted_response,
                        "```",
                        "",
                    ]
                )

            lines.extend(
                [
                    "#### Remediation Blueprint",
                    f"{f.remediation_summary}",
                    "",
                    f"```{f.remediation_lang}",
                    f"{f.remediation_code}",
                    "```",
                    "",
                    "---",
                    "",
                ]
            )

        return "\n".join(lines)

    @classmethod
    def to_html(cls, findings: List[Finding], scope_rule: ScopeRule) -> str:
        """Renders an interactive, dark-mode standalone HTML report with strict CSP."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        crit = sum(1 for f in findings if f.severity_label == "CRITICAL")
        high = sum(1 for f in findings if f.severity_label == "HIGH")
        warn = sum(1 for f in findings if f.severity_label == "WARNING")
        low = sum(1 for f in findings if f.severity_label in ("LOW", "INFO"))

        finding_cards = []
        for f in findings:
            badge_style = cls.SEVERITY_BADGES.get(f.severity_label, cls.SEVERITY_BADGES["INFO"])
            scope_badge = (
                '<span class="badge in-scope">IN-SCOPE</span>'
                if f.in_scope
                else '<span class="badge out-scope">OUT-OF-SCOPE</span>'
            )

            steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in f.steps_to_reproduce)

            req_html = (
                f'<pre class="code-block"><code>{html.escape(f.redacted_request)}</code></pre>'
                if f.redacted_request
                else "<p class='dim'>No HTTP request captured.</p>"
            )

            resp_html = (
                f'<pre class="code-block"><code>{html.escape(f.redacted_response)}</code></pre>'
                if f.redacted_response
                else "<p class='dim'>No HTTP response captured.</p>"
            )

            card = f"""
            <div class="finding-card" id="{html.escape(f.id)}">
                <div class="finding-header">
                    <span class="badge" style="{badge_style}">{html.escape(f.severity_label)}</span>
                    <span class="cvss-pill">CVSS {f.cvss_score:.1f}</span>
                    {scope_badge}
                    <h3 class="finding-title">[{html.escape(f.id)}] {html.escape(f.title)}</h3>
                </div>
                <div class="finding-body">
                    <p class="meta"><strong>Endpoint:</strong> <code>{html.escape(f.endpoint)}</code> | <strong>Classification:</strong> {html.escape(f.cwe_id)}</p>
                    <h4>Description</h4>
                    <p>{html.escape(f.description)}</p>
                    <h4>Impact</h4>
                    <p>{html.escape(f.impact)}</p>
                    <h4>Steps to Reproduce</h4>
                    <ol>{steps_html}</ol>
                    <h4>Sanitized Evidence</h4>
                    <div class="evidence-grid">
                        <div>
                            <h5>HTTP Request</h5>
                            {req_html}
                        </div>
                        <div>
                            <h5>HTTP Response</h5>
                            {resp_html}
                        </div>
                    </div>
                    <h4>Remediation Blueprint</h4>
                    <p>{html.escape(f.remediation_summary)}</p>
                    <pre class="code-block"><code>{html.escape(f.remediation_code)}</code></pre>
                </div>
            </div>
            """
            finding_cards.append(card)

        cards_combined = "\n".join(finding_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:;">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCraft Security Assessment Report — {html.escape(scope_rule.program_name)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-border: #1f2937;
            --text-main: #f9fafb;
            --text-dim: #9ca3af;
            --accent: #0ea5e9;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 2.5rem 1rem;
        }}
        .container {{ max-width: 1040px; margin: 0 auto; }}
        header {{ margin-bottom: 2.5rem; border-bottom: 1px solid var(--surface-border); padding-bottom: 1.5rem; }}
        h1 {{ font-size: 2rem; color: #fff; margin-bottom: 0.5rem; }}
        .header-meta {{ color: var(--text-dim); font-size: 0.95rem; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }}
        .stat-box {{ background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; padding: 1.25rem; text-align: center; }}
        .stat-box .count {{ font-size: 2.2rem; font-weight: 700; color: #fff; }}
        .stat-box .label {{ font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }}
        .finding-card {{ background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; margin-bottom: 1.75rem; overflow: hidden; }}
        .finding-header {{ background: #161f30; padding: 1rem 1.25rem; display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
        .finding-title {{ font-size: 1.15rem; color: #fff; margin: 0; }}
        .badge {{ padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .cvss-pill {{ background: #374151; color: #f3f4f6; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }}
        .in-scope {{ background: #065f46; color: #a7f3d0; }}
        .out-scope {{ background: #831843; color: #fbcfe8; }}
        .finding-body {{ padding: 1.5rem; }}
        .finding-body h4 {{ color: var(--accent); margin: 1.25rem 0 0.5rem; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.04em; }}
        .finding-body p, .finding-body ol {{ color: #d1d5db; margin-bottom: 0.75rem; }}
        .finding-body ol {{ padding-left: 1.5rem; }}
        .meta {{ font-size: 0.9rem; color: var(--text-dim); margin-bottom: 1rem; }}
        .code-block {{ background: #030712; border: 1px solid #1f2937; padding: 0.85rem; border-radius: 6px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.85rem; color: #38bdf8; }}
        .evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem; }}
        .evidence-grid h5 {{ font-size: 0.85rem; color: var(--text-dim); margin-bottom: 0.35rem; text-transform: uppercase; }}
        .dim {{ color: #6b7280; font-style: italic; }}
        footer {{ text-align: center; color: var(--text-dim); margin-top: 3rem; font-size: 0.85rem; }}
        @media(max-width: 768px) {{ .evidence-grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>VulnCraft Triage Assessment Report</h1>
            <div class="header-meta">
                <span>Program: <strong>{html.escape(scope_rule.program_name)}</strong></span> &bull;
                <span>Author: <strong>k4slr</strong></span> &bull;
                <span>Generated: {now}</span>
            </div>
        </header>

        <section class="stat-grid">
            <div class="stat-box"><div class="count">{len(findings)}</div><div class="label">Total Findings</div></div>
            <div class="stat-box"><div class="count" style="color:#ef4444">{crit}</div><div class="label">Critical</div></div>
            <div class="stat-box"><div class="count" style="color:#f97316">{high}</div><div class="label">High</div></div>
            <div class="stat-box"><div class="count" style="color:#f59e0b">{warn}</div><div class="label">Warning</div></div>
            <div class="stat-box"><div class="count" style="color:#3b82f6">{low}</div><div class="label">Low / Info</div></div>
        </section>

        <section class="findings-list">
            {cards_combined}
        </section>

        <footer>
            <p>Generated by <strong>VulnCraft v1.1.0</strong> &bull; Developed by <strong>k4slr</strong> &bull; MIT License</p>
        </footer>
    </div>
</body>
</html>
"""