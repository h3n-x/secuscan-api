from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.dns import DNSScanResult
from app.schemas.headers import HeaderScanResult
from app.schemas.ports import PortScanResult
from app.schemas.tls import TLSScanResult

CRITICAL_PORTS = {
    21: "FTP (Plaintext credentials)",
    23: "Telnet (Unencrypted remote administration)",
    445: "SMB (High-risk lateral movement/ransomware vector)",
    1433: "MSSQL (Database exposed to public network)",
    1521: "Oracle DB (Database exposed to public network)",
    3306: "MySQL (Database exposed to public network)",
    3389: "RDP (Remote Desktop exposed)",
    5432: "PostgreSQL (Database exposed to public network)",
    6379: "Redis (No-auth in-memory cache, high RCE risk)",
    9200: "Elasticsearch (Search cluster exposed)",
    27017: "MongoDB (NoSQL database exposed to public network)",
}


class SecurityDeduction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    rule_id: str
    penalty: int
    reason: str
    severity: str


class SecurityPostureScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = Field(..., ge=0, le=100, description="Overall security posture score (0-100)")
    grade: str = Field(..., description="Letter grade: A+, A, B, C, D, or F")
    deductions: list[SecurityDeduction] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


def calculate_posture_score(
    *,
    headers: HeaderScanResult | None = None,
    tls: TLSScanResult | None = None,
    dns: DNSScanResult | None = None,
    ports: PortScanResult | None = None,
) -> SecurityPostureScore:
    """Calculate an executive security posture score and grade from scan modules."""
    score = 100
    deductions: list[SecurityDeduction] = []
    recommendations: list[str] = []

    # 1. Ports Evaluation
    if ports is not None and ports.open_ports:
        for port in ports.open_ports:
            if port in CRITICAL_PORTS:
                desc = CRITICAL_PORTS[port]
                penalty = 25
                score -= penalty
                deductions.append(
                    SecurityDeduction(
                        module="ports",
                        rule_id=f"port.{port}.critical_exposure",
                        penalty=penalty,
                        reason=f"Open dangerous port {port}: {desc}",
                        severity="critical",
                    )
                )
                recommendations.append(
                    f"Close or firewall port {port} ({desc}) from the public internet."
                )
            elif port == 22:
                # SSH open
                penalty = 5
                score -= penalty
                deductions.append(
                    SecurityDeduction(
                        module="ports",
                        rule_id="port.22.ssh_exposed",
                        penalty=penalty,
                        reason="SSH port 22 is exposed to public internet",
                        severity="low",
                    )
                )
                recommendations.append("Restrict SSH (port 22) access to a VPN or bastion host.")

    # 2. TLS Evaluation
    if tls is not None:
        if tls.certificate is not None:
            if tls.certificate.expired:
                penalty = 40
                score -= penalty
                deductions.append(
                    SecurityDeduction(
                        module="tls",
                        rule_id="tls.cert.expired",
                        penalty=penalty,
                        reason="SSL/TLS certificate has expired",
                        severity="critical",
                    )
                )
                recommendations.append("Renew and deploy a valid SSL/TLS certificate immediately.")

            if tls.certificate.self_signed:
                penalty = 25
                score -= penalty
                deductions.append(
                    SecurityDeduction(
                        module="tls",
                        rule_id="tls.cert.self_signed",
                        penalty=penalty,
                        reason="SSL/TLS certificate is self-signed (untrusted CA)",
                        severity="high",
                    )
                )
                recommendations.append(
                    "Replace the self-signed certificate with a certificate from a trusted CA (e.g. Let's Encrypt)."
                )

            if not tls.certificate.expired and tls.certificate.days_until_expiry < 14:
                penalty = 10
                score -= penalty
                deductions.append(
                    SecurityDeduction(
                        module="tls",
                        rule_id="tls.cert.expiring_soon",
                        penalty=penalty,
                        reason=f"SSL/TLS certificate expires in {tls.certificate.days_until_expiry} days",
                        severity="medium",
                    )
                )
                recommendations.append("Prepare certificate renewal before expiration date.")

        if tls.tls_version in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"}:
            penalty = 30
            score -= penalty
            deductions.append(
                SecurityDeduction(
                    module="tls",
                    rule_id="tls.protocol.deprecated",
                    penalty=penalty,
                    reason=f"Obsolete and vulnerable protocol supported: {tls.tls_version}",
                    severity="high",
                )
            )
            recommendations.append("Disable TLS 1.0 and 1.1; enforce TLS 1.2 or TLS 1.3.")

    # 3. Headers Evaluation
    if headers is not None and headers.checks:
        for check in headers.checks:
            if not check.present:
                if check.header.lower() == "strict-transport-security":
                    penalty = 10
                    score -= penalty
                    deductions.append(
                        SecurityDeduction(
                            module="headers",
                            rule_id="headers.missing_hsts",
                            penalty=penalty,
                            reason="Missing HTTP Strict Transport Security (HSTS) header",
                            severity="high",
                        )
                    )
                    recommendations.append("Enable HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains).")
                elif check.header.lower() == "content-security-policy":
                    penalty = 10
                    score -= penalty
                    deductions.append(
                        SecurityDeduction(
                            module="headers",
                            rule_id="headers.missing_csp",
                            penalty=penalty,
                            reason="Missing Content-Security-Policy (CSP) header",
                            severity="medium",
                        )
                    )
                    recommendations.append("Define a strict Content-Security-Policy to mitigate XSS.")
                elif check.header.lower() == "x-content-type-options":
                    penalty = 5
                    score -= penalty
                    deductions.append(
                        SecurityDeduction(
                            module="headers",
                            rule_id="headers.missing_x_content_type_options",
                            penalty=penalty,
                            reason="Missing X-Content-Type-Options: nosniff",
                            severity="low",
                        )
                    )
                    recommendations.append("Add 'X-Content-Type-Options: nosniff' header.")
                elif check.header.lower() == "x-frame-options":
                    penalty = 5
                    score -= penalty
                    deductions.append(
                        SecurityDeduction(
                            module="headers",
                            rule_id="headers.missing_x_frame_options",
                            penalty=penalty,
                            reason="Missing X-Frame-Options header (clickjacking risk)",
                            severity="low",
                        )
                    )
                    recommendations.append("Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.")

    # 4. DNS Evaluation
    if dns is not None:
        if not dns.dmarc.present or not dns.dmarc.valid:
            penalty = 15
            score -= penalty
            deductions.append(
                SecurityDeduction(
                    module="dns",
                    rule_id="dns.dmarc.missing",
                    penalty=penalty,
                    reason="Missing or invalid DMARC record (email spoofing risk)",
                    severity="high",
                )
            )
            recommendations.append("Configure a strict DMARC TXT record (_dmarc.domain.com).")

        if not dns.spf.present or not dns.spf.valid:
            penalty = 10
            score -= penalty
            deductions.append(
                SecurityDeduction(
                    module="dns",
                    rule_id="dns.spf.missing",
                    penalty=penalty,
                    reason="Missing or invalid SPF record",
                    severity="medium",
                )
            )
            recommendations.append("Configure an SPF TXT record (v=spf1 ... -all).")
        elif dns.spf.issues:
            penalty = 5
            score -= penalty
            deductions.append(
                SecurityDeduction(
                    module="dns",
                    rule_id="dns.spf.permissive",
                    penalty=penalty,
                    reason=f"Permissive SPF configuration: {'; '.join(dns.spf.issues)}",
                    severity="medium",
                )
            )
            recommendations.append("Harden SPF policy from '~all' or '?all' to '-all'.")

    # Clamp score
    clamped_score = max(0, min(100, score))

    # Determine grade
    if clamped_score >= 95:
        grade = "A+"
    elif clamped_score >= 85:
        grade = "A"
    elif clamped_score >= 70:
        grade = "B"
    elif clamped_score >= 55:
        grade = "C"
    elif clamped_score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Sort deductions by penalty descending
    deductions.sort(key=lambda d: d.penalty, reverse=True)

    return SecurityPostureScore(
        score=clamped_score,
        grade=grade,
        deductions=deductions,
        recommendations=recommendations,
    )
