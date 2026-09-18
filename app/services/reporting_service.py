from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def generate_markdown_report(
    *,
    target: str,
    scan_id: str,
    kind: str,
    module_results: dict[str, Any],
) -> str:
    """Generate an executive Markdown security audit report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [
        f"# Executive Security Audit Report: {target}",
        "",
        f"- **Target Domain:** `{target}`",
        f"- **Scan ID:** `{scan_id}`",
        f"- **Scan Type:** `{kind.upper()}`",
        f"- **Generated At:** `{now_str}`",
        f"- **Engine:** SecuScan API v1.0",
        "",
        "---",
        "",
    ]

    # Posture Score Section
    posture = module_results.get("posture")
    if posture:
        score = posture.get("score", "N/A")
        grade = posture.get("grade", "N/A")
        lines.extend(
            [
                "## 🛡️ Security Posture Summary",
                "",
                f"| Overall Score | Letter Grade | Risk Evaluation |",
                f"| :---: | :---: | :--- |",
                f"| **{score} / 100** | **`{grade}`** | {'Low Risk' if score >= 85 else 'Moderate Risk' if score >= 70 else 'High Risk'} |",
                "",
            ]
        )

        deductions = posture.get("deductions", [])
        if deductions:
            lines.extend(
                [
                    "### Identified Risk Factors & Penalties",
                    "",
                    "| Module | Penalty | Severity | Reason |",
                    "| :--- | :---: | :---: | :--- |",
                ]
            )
            for d in deductions:
                lines.append(
                    f"| `{d.get('module')}` | -{d.get('penalty')} pts | **{d.get('severity', '').upper()}** | {d.get('reason')} |"
                )
            lines.append("")

        recs = posture.get("recommendations", [])
        if recs:
            lines.extend(["### Prioritized Remediation Steps", ""])
            for idx, r in enumerate(recs, start=1):
                lines.append(f"{idx}. {r}")
            lines.append("")

    # Ports Section
    ports = module_results.get("ports")
    if ports:
        open_ports = ports.get("open_ports", [])
        lines.extend(
            [
                "## 🔌 Port & Service Exposure",
                "",
                f"- **Ports Scanned:** {ports.get('start_port', 1)} - {ports.get('end_port', 1024)}",
                f"- **Total Open Ports Found:** {len(open_ports)}",
                "",
            ]
        )
        if open_ports:
            lines.append(f"- **Open Port List:** `{', '.join(str(p) for p in open_ports)}`")
        else:
            lines.append("✅ No open ports detected in the scanned range.")
        lines.append("")

    # TLS Section
    tls = module_results.get("tls")
    if tls:
        cert = tls.get("certificate")
        lines.extend(
            [
                "## 🔒 SSL / TLS Transport Security",
                "",
                f"- **TLS Reachable:** {'Yes' if tls.get('reachable') else 'No'}",
                f"- **Negotiated Protocol:** `{tls.get('tls_version', 'None')}`",
                f"- **Cipher Suite:** `{tls.get('cipher', 'None')}`",
            ]
        )
        if cert:
            lines.extend(
                [
                    f"- **Issuer:** `{cert.get('issuer')}`",
                    f"- **Subject:** `{cert.get('subject')}`",
                    f"- **Days Until Expiry:** `{cert.get('days_until_expiry')}` days",
                    f"- **Expired:** `{'YES (CRITICAL)' if cert.get('expired') else 'No'}`",
                    f"- **Self-Signed:** `{'YES (UNTRUSTED)' if cert.get('self_signed') else 'No'}`",
                ]
            )
        lines.append("")

    # Headers Section
    headers = module_results.get("headers")
    if headers:
        checks = headers.get("checks", [])
        lines.extend(
            [
                "## 🌐 HTTP Security Headers",
                "",
                "| Header | Present | Severity if Missing | Recommendation |",
                "| :--- | :---: | :---: | :--- |",
            ]
        )
        for c in checks:
            present_icon = "✅ Present" if c.get("present") else "❌ Missing"
            lines.append(
                f"| `{c.get('header')}` | {present_icon} | {c.get('severity', '').upper()} | {c.get('recommendation') or '-'} |"
            )
        lines.append("")

    # DNS Section
    dns = module_results.get("dns")
    if dns:
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        lines.extend(
            [
                "## 📧 Email & DNS Security Posture",
                "",
                f"- **SPF Record:** `{'Configured' if spf.get('present') else 'MISSING'}`",
                f"- **DMARC Record:** `{'Configured' if dmarc.get('present') else 'MISSING'}` (Policy: `{dmarc.get('policy', 'None')}`)",
                f"- **A Records:** `{', '.join(dns.get('a_records', [])) or 'None'}`",
                f"- **MX Records:** `{', '.join(dns.get('mx_records', [])) or 'None'}`",
                "",
            ]
        )

    # Subdomains Section
    subdomains = module_results.get("subdomains")
    if subdomains:
        sub_list = subdomains.get("subdomains", [])
        lines.extend(
            [
                "## 🗺️ Discovered Subdomains (Certificate Transparency)",
                "",
                f"- **Total Subdomains Discovered:** {len(sub_list)}",
                "",
            ]
        )
        if sub_list:
            for s in sub_list[:50]:  # Cap display at 50
                lines.append(f"- `{s}`")
            if len(sub_list) > 50:
                lines.append(f"- *... and {len(sub_list) - 50} more subdomains*")
        lines.append("")

    return "\n".join(lines)


def generate_sarif_report(
    *,
    target: str,
    scan_id: str,
    module_results: dict[str, Any],
) -> dict[str, Any]:
    """Convert scan findings to OASIS SARIF 2.1.0 JSON format."""
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    def add_result(
        rule_id: str,
        name: str,
        level: str,
        message: str,
        description: str,
    ) -> None:
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": description},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"https://{target}"},
                        }
                    }
                ],
            }
        )

    # Convert Headers findings
    headers = module_results.get("headers", {})
    for c in headers.get("checks", []):
        if not c.get("present"):
            sev = c.get("severity", "medium")
            level = "error" if sev == "high" else "warning" if sev == "medium" else "note"
            add_result(
                rule_id=f"headers.missing.{c.get('header', '').lower().replace('-', '_')}",
                name=f"Missing-{c.get('header')}",
                level=level,
                message=f"Missing required security header '{c.get('header')}': {c.get('recommendation')}",
                description=f"Security header {c.get('header')} is not configured.",
            )

    # Convert TLS findings
    tls = module_results.get("tls", {})
    cert = tls.get("certificate")
    if cert:
        if cert.get("expired"):
            add_result(
                rule_id="tls.cert.expired",
                name="TLS-Certificate-Expired",
                level="error",
                message="The TLS certificate for this domain has expired.",
                description="Expired certificates break trust and disrupt encrypted communications.",
            )
        if cert.get("self_signed"):
            add_result(
                rule_id="tls.cert.self_signed",
                name="TLS-Certificate-Self-Signed",
                level="error",
                message="The TLS certificate is self-signed and not trusted by major root stores.",
                description="Self-signed certificates are vulnerable to Man-in-the-Middle attacks.",
            )

    # Convert DNS findings
    dns = module_results.get("dns", {})
    if dns:
        if not dns.get("dmarc", {}).get("present"):
            add_result(
                rule_id="dns.dmarc.missing",
                name="DNS-DMARC-Missing",
                level="warning",
                message="Missing DMARC policy record. Domain is vulnerable to email spoofing.",
                description="DMARC enforces validation of SPF and DKIM signatures.",
            )

    # Convert Ports findings
    ports = module_results.get("ports", {})
    for port in ports.get("open_ports", []):
        from app.services.scoring_service import CRITICAL_PORTS

        if port in CRITICAL_PORTS:
            add_result(
                rule_id=f"port.{port}.critical_exposure",
                name=f"Port-{port}-Exposed",
                level="error",
                message=f"Critical service port {port} ({CRITICAL_PORTS[port]}) is exposed to the internet.",
                description=f"Port {port} represents a high-risk service exposure.",
            )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecuScan Perimeter API",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/h3n-x/secuscan-api",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
