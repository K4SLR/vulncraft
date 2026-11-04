import argparse
import json
import sys
from pathlib import Path
from typing import List
from .models import Finding, ScopeConfig
from .cvss import CVSS31Calculator
from .scope import ScopeGuard
from .sanitizer import HTTPSanitizer
from .remediation import RemediationLibrary
from .exporter import ReportExporter


def load_scope(path: str) -> ScopeConfig:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ScopeConfig(
        program_name=data.get("program_name", "Default Security Program"),
        in_scope=data.get("in_scope", ["*"]),
        out_of_scope=data.get("out_of_scope", []),
        rules=data.get("rules", []),
    )


def process_findings(findings_path: str, scope_cfg: ScopeConfig) -> List[Finding]:
    with open(findings_path, "r", encoding="utf-8") as f:
        raw_list = json.load(f)

    guard = ScopeGuard(scope_cfg)
    processed: List[Finding] = []

    for item in raw_list:
        finding = Finding(
            id=item["id"],
            title=item["title"],
            endpoint=item["endpoint"],
            vuln_type=item["vuln_type"],
            cvss_vector=item["cvss_vector"],
            description=item["description"],
            steps_to_reproduce=item.get("steps_to_reproduce", []),
            raw_http_request=item.get("raw_http_request", ""),
            raw_http_response=item.get("raw_http_response", ""),
            impact=item.get("impact", ""),
            status=item.get("status", "OPEN"),
        )

        # 1. Calculate CVSS v3.1 & Label Severity (CRITICAL, HIGH, WARNING, LOW, INFO)
        score, label = CVSS31Calculator.calculate(finding.cvss_vector)
        finding.cvss_score = score
        finding.severity_label = label

        # 2. ScopeGuard validation
        in_scope, _ = guard.validate(finding.endpoint)
        finding.in_scope = in_scope

        # 3. Sanitize Raw HTTP Request
        finding.redacted_request = HTTPSanitizer.sanitize_http_block(finding.raw_http_request)

        # 4. Attach DevFixer Remediation Blueprint
        rem = RemediationLibrary.enrich(finding.vuln_type)
        finding.cwe_id = rem["cwe_id"]
        finding.remediation_summary = rem["summary"]
        finding.remediation_code = rem["code"]

        processed.append(finding)

    return ReportExporter.sort_findings(processed)


def print_ascii_table(findings: List[Finding], program_name: str) -> None:
    counts = ReportExporter.count_by_severity(findings)
    print("=" * 98)
    print(f" VULNCRAFT TRIAGE ENGINE | Program: {program_name}")
    print(
        f" Summary: TOTAL={len(findings)} | CRITICAL={counts['CRITICAL']} | HIGH={counts['HIGH']} "
        f"| WARNING={counts['WARNING']} | LOW={counts['LOW']} | INFO={counts['INFO']}"
    )
    print("=" * 98)
    print(f"{'ID':<10} {'SEVERITY':<10} {'CVSS':<6} {'TYPE':<16} {'SCOPE':<12} {'ENDPOINT'}")
    print("-" * 98)
    for f in findings:
        scope_str = "IN-SCOPE" if f.in_scope else "OUT-SCOPE!"
        ep = f.endpoint if len(f.endpoint) <= 38 else f.endpoint[:35] + "..."
        print(f"{f.id:<10} {f.severity_label:<10} {f.cvss_score:<6.1f} {f.vuln_type:<16} {scope_str:<12} {ep}")
    print("=" * 98)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulncraft",
        description="VulnCraft: Manual Bug Hunting Triage, ScopeGuard & PoC Report Engine",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand 1: triage
    p_triage = subparsers.add_parser("triage", help="Triage findings JSON, label severities, and export reports")
    p_triage.add_argument("-f", "--findings", required=True, help="Path to findings JSON file")
    p_triage.add_argument("-s", "--scope", required=True, help="Path to scope JSON file")
    p_triage.add_argument("--md", help="Output path for Markdown PoC report (.md)")
    p_triage.add_argument("--html", help="Output path for interactive Dark-Mode HTML dashboard (.html)")
    p_triage.add_argument("--json-out", help="Output path for enriched JSON dataset")

    # Subcommand 2: scope-check
    p_scope = subparsers.add_parser("scope-check", help="Check if a target URL/domain is In-Scope")
    p_scope.add_argument("-s", "--scope", required=True, help="Path to scope JSON file")
    p_scope.add_argument("-u", "--url", required=True, help="Target URL or hostname to verify")

    # Subcommand 3: sanitize
    p_san = subparsers.add_parser("sanitize", help="Sanitize a raw HTTP request file (redact tokens/cookies)")
    p_san.add_argument("-r", "--request", required=True, help="Path to raw HTTP request file")

    args = parser.parse_args(argv)

    if args.command == "triage":
        scope_cfg = load_scope(args.scope)
        findings = process_findings(args.findings, scope_cfg)
        print_ascii_table(findings, scope_cfg.program_name)

        if args.md:
            md_content = ReportExporter.to_markdown(findings, scope_cfg)
            Path(args.md).write_text(md_content, encoding="utf-8")
            print(f"[+] Markdown PoC Report saved to: {args.md}")

        if args.html:
            html_content = ReportExporter.to_html(findings, scope_cfg)
            Path(args.html).write_text(html_content, encoding="utf-8")
            print(f"[+] Interactive Dark-Mode HTML Report saved to: {args.html}")

        if args.json_out:
            Path(args.json_out).write_text(
                json.dumps([f.to_dict() for f in findings], indent=2),
                encoding="utf-8",
            )
            print(f"[+] Enriched JSON data saved to: {args.json_out}")
        return 0

    elif args.command == "scope-check":
        scope_cfg = load_scope(args.scope)
        guard = ScopeGuard(scope_cfg)
        allowed, reason = guard.validate(args.url)
        print(f"Target: {args.url} -> {reason}")
        return 0 if allowed else 2

    elif args.command == "sanitize":
        raw_text = Path(args.request).read_text(encoding="utf-8")
        meta = HTTPSanitizer.parse_raw_request_metadata(raw_text)
        sanitized = HTTPSanitizer.sanitize_http_block(raw_text)
        print(f"// Detected Endpoint: {meta['endpoint']} ({meta['method']})")
        print(sanitized)
        return 0

    return 0
