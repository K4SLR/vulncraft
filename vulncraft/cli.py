import argparse
import json
import sys
from pathlib import Path
from typing import List

from . import __version__
from .cvss import CVSS31Calculator
from .exporter import ReportExporter
from .models import Finding, ScopeRule
from .remediation import RemediationLibrary
from .sanitizer import HTTPSanitizer
from .scope import ScopeGuard

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "LOW": 3, "INFO": 4}


def load_findings(
    findings_path: Path,
    scope_guard: ScopeGuard,
    exclude_out_of_scope: bool = False,
) -> List[Finding]:
    """Loads, validates, enriches, and sanitizes findings from a JSON file."""
    if not findings_path.is_file():
        raise FileNotFoundError(f"Findings file not found: {findings_path}")

    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON Array ([...])")

    findings: List[Finding] = []

    for idx, item in enumerate(data, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Finding #{idx} must be a valid JSON object")

        fid = item.get("id", f"VULN-{idx:03d}")
        title = item.get("title", "Untitled Vulnerability")
        endpoint = item.get("endpoint", "-")
        vuln_type = item.get("vuln_type", "General Flaw")
        cvss_vector = item.get("cvss_vector", "")
        description = item.get("description", "No technical description provided.")
        impact = item.get("impact", "Impact analysis pending.")
        status = item.get("status", "OPEN")

        # 1. CVSS Calculation and normalization
        raw_score = item.get("cvss_score")
        raw_label = item.get("severity_label") or item.get("severity")
        if cvss_vector and (raw_score is None or float(raw_score) == 0.0):
            cvss_score, severity_label = CVSS31Calculator.calculate(cvss_vector)
        else:
            cvss_score = float(raw_score or 0.0)
            severity_label = str(raw_label or CVSS31Calculator.label_for_score(cvss_score)).upper()

        # 2. Scope verification
        is_in_scope, _ = scope_guard.validate(endpoint)
        if exclude_out_of_scope and not is_in_scope:
            continue

        # 3. HTTP Evidence Sanitization
        raw_req = item.get("raw_http_request") or item.get("redacted_request") or ""
        raw_resp = item.get("raw_http_response") or item.get("redacted_response") or ""
        redacted_req = HTTPSanitizer.sanitize(raw_req)
        redacted_resp = HTTPSanitizer.sanitize(raw_resp)

        # 4. Remediation blueprint enrichment
        blueprint = RemediationLibrary.get(vuln_type)
        cwe_id = item.get("cwe_id") or blueprint["cwe_id"]
        rem_summary = item.get("remediation_summary") or blueprint["summary"]
        rem_code = item.get("remediation_code") or blueprint["code"]
        rem_lang = item.get("remediation_lang") or blueprint["lang"]

        steps = [str(s).strip() for s in item.get("steps_to_reproduce", []) if str(s).strip()]

        findings.append(
            Finding(
                id=fid,
                title=title,
                endpoint=endpoint,
                vuln_type=vuln_type,
                cwe_id=cwe_id,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                severity_label=severity_label,
                description=description,
                impact=impact,
                status=status,
                in_scope=is_in_scope,
                steps_to_reproduce=steps,
                redacted_request=redacted_req,
                redacted_response=redacted_resp,
                remediation_summary=rem_summary,
                remediation_code=rem_code,
                remediation_lang=rem_lang,
            )
        )

    findings.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity_label, 99), -x.cvss_score))
    return findings


def load_scope(scope_path: Path) -> ScopeRule:
    """Loads scope rules from JSON file."""
    if not scope_path.is_file():
        raise FileNotFoundError(f"Scope file not found: {scope_path}")

    with open(scope_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return ScopeRule(
        program_name=data.get("program_name", "Target Bounty Program"),
        in_scope=data.get("in_scope", ["*"]),
        out_of_scope=data.get("out_of_scope", []),
        rules=data.get("rules", []),
    )


def print_cli_table(findings: List[Finding], program_name: str) -> None:
    """Prints a clean ASCII triage table in the terminal."""
    crit = sum(1 for f in findings if f.severity_label == "CRITICAL")
    high = sum(1 for f in findings if f.severity_label == "HIGH")
    warn = sum(1 for f in findings if f.severity_label == "WARNING")
    low = sum(1 for f in findings if f.severity_label == "LOW")
    info = sum(1 for f in findings if f.severity_label == "INFO")

    print("=" * 88)
    print(f"VULNCRAFT TRIAGE ENGINE v{__version__} | Program: {program_name}")
    print(f"Summary: TOTAL={len(findings)} | CRITICAL={crit} | HIGH={high} | WARNING={warn} | LOW={low} | INFO={info}")
    print("=" * 88)
    print(f"{'ID':<10} {'SEVERITY':<10} {'CVSS':<6} {'TYPE':<16} {'SCOPE':<12} {'ENDPOINT'}")
    print("-" * 88)
    for f in findings:
        scope_str = "IN-SCOPE" if f.in_scope else "OUT-SCOPE!"
        print(f"{f.id:<10} {f.severity_label:<10} {f.cvss_score:<6.1f} {f.vuln_type:<16} {scope_str:<12} {f.endpoint}")
    print("=" * 88)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulncraft",
        description="VulnCraft: Zero-dependency manual bug hunting triage engine & PoC report generator.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"vulncraft {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Triage command
    triage_p = subparsers.add_parser("triage", help="Triage findings JSON against scope and output report formats")
    triage_p.add_argument("-f", "--findings", required=True, help="Path to input findings JSON")
    triage_p.add_argument("-s", "--scope", required=True, help="Path to scope JSON configuration")
    triage_p.add_argument("--exclude-out-of-scope", action="store_true", help="Exclude out-of-scope findings")
    triage_p.add_argument("--md", help="Export structured Markdown PoC report to destination path")
    triage_p.add_argument("--html", help="Export CSP-hardened dark-mode HTML report to destination path")
    triage_p.add_argument("--json-out", help="Export sanitized and enriched JSON findings to destination path")

    # 2. Scope check command
    scope_p = subparsers.add_parser("scope-check", help="Test a single URL endpoint against a scope definition")
    scope_p.add_argument("-s", "--scope", required=True, help="Path to scope JSON configuration")
    scope_p.add_argument("-u", "--url", required=True, help="Target URL endpoint to evaluate")

    # 3. Sanitize raw HTTP request command
    san_p = subparsers.add_parser("sanitize", help="Sanitize credentials and tokens from a raw HTTP file")
    san_p.add_argument("-r", "--request", required=True, help="Path to raw HTTP request/response file")
    san_p.add_argument("-o", "--output", help="Optional output file path for sanitized HTTP block")

    # 4. CVSS calculate command
    cvss_p = subparsers.add_parser("cvss", help="Calculate CVSS v3.1 base score from metric vector string")
    cvss_p.add_argument("vector", help="CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)")

    args = parser.parse_args(argv)

    try:
        if args.command == "cvss":
            score, label = CVSS31Calculator.calculate(args.vector)
            print(f"CVSS v3.1 Base Score : {score:.1f}")
            print(f"Severity Rating     : {label}")
            return 0

        if args.command == "scope-check":
            scope_rule = load_scope(Path(args.scope))
            guard = ScopeGuard(scope_rule.in_scope, scope_rule.out_of_scope)
            allowed, reason = guard.validate(args.url)
            verdict = "[+] ALLOWED" if allowed else "[-] BLOCKED"
            print(f"{verdict}: {args.url}")
            print(f"Reason: {reason}")
            return 0 if allowed else 1

        if args.command == "sanitize":
            req_path = Path(args.request)
            if not req_path.is_file():
                raise FileNotFoundError(f"Raw HTTP file not found: {req_path}")
            raw_content = req_path.read_text(encoding="utf-8")
            sanitized_content = HTTPSanitizer.sanitize(raw_content)
            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(sanitized_content, encoding="utf-8")
                print(f"[+] Sanitized HTTP output saved : {out_path}")
            else:
                print(sanitized_content)
            return 0

        if args.command == "triage":
            scope_rule = load_scope(Path(args.scope))
            guard = ScopeGuard(scope_rule.in_scope, scope_rule.out_of_scope)
            findings = load_findings(
                Path(args.findings),
                guard,
                exclude_out_of_scope=args.exclude_out_of_scope,
            )

            print_cli_table(findings, scope_rule.program_name)

            if args.md:
                md_path = Path(args.md)
                md_path.parent.mkdir(parents=True, exist_ok=True)
                md_content = ReportExporter.to_markdown(findings, scope_rule)
                md_path.write_text(md_content, encoding="utf-8")
                print(f"[+] Markdown PoC report saved : {md_path}")

            if args.html:
                html_path = Path(args.html)
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_content = ReportExporter.to_html(findings, scope_rule)
                html_path.write_text(html_content, encoding="utf-8")
                print(f"[+] Interactive HTML report saved : {html_path}")

            if args.json_out:
                json_path = Path(args.json_out)
                json_path.parent.mkdir(parents=True, exist_ok=True)
                json_data = [f.to_dict() for f in findings]
                json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
                print(f"[+] Sanitized JSON dataset saved : {json_path}")

            return 0

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 2

    return 0