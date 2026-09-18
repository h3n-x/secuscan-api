from datetime import datetime, timezone

from app.schemas.dns import DKIMSelectorResult, DMARCResult, DNSScanResult, SPFResult
from app.schemas.headers import HeaderCheck, HeaderScanResult
from app.schemas.ports import PortScanResult
from app.schemas.tls import TLSCertificateInfo, TLSScanResult
from app.services.scoring_service import calculate_posture_score


def test_calculate_posture_score_perfect_grade() -> None:
    now = datetime.now(timezone.utc)
    headers = HeaderScanResult(
        target="secure.example.com",
        scanned_url="https://secure.example.com",
        reachable=True,
        status_code=200,
        checks=[
            HeaderCheck(header="Strict-Transport-Security", present=True, value="max-age=31536000", severity="ok", recommendation=None),
            HeaderCheck(header="Content-Security-Policy", present=True, value="default-src 'self'", severity="ok", recommendation=None),
            HeaderCheck(header="X-Content-Type-Options", present=True, value="nosniff", severity="ok", recommendation=None),
            HeaderCheck(header="X-Frame-Options", present=True, value="DENY", severity="ok", recommendation=None),
        ],
        error=None,
    )
    tls = TLSScanResult(
        target="secure.example.com",
        port=443,
        reachable=True,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=TLSCertificateInfo(
            subject="CN=secure.example.com",
            issuer="CN=Let's Encrypt",
            not_before=now,
            not_after=now,
            days_until_expiry=60,
            expired=False,
            self_signed=False,
            signature_algorithm="sha256WithRSAEncryption",
            serial_number="12345",
        ),
        error=None,
    )
    dns = DNSScanResult(
        target="secure.example.com",
        a_records=["93.184.216.34"],
        aaaa_records=[],
        mx_records=["mail.secure.example.com"],
        ns_records=["ns1.secure.example.com"],
        spf=SPFResult(present=True, record="v=spf1 -all", valid=True, issues=[]),
        dmarc=DMARCResult(present=True, record="v=DMARC1; p=reject", policy="reject", valid=True, issues=[]),
        dkim=[],
        error=None,
    )
    ports = PortScanResult(
        target="secure.example.com",
        start_port=1,
        end_port=1024,
        ports_scanned=1024,
        open_ports=[443],
    )

    result = calculate_posture_score(headers=headers, tls=tls, dns=dns, ports=ports)
    assert result.score == 100
    assert result.grade == "A+"
    assert len(result.deductions) == 0


def test_calculate_posture_score_severe_penalties() -> None:
    now = datetime.now(timezone.utc)
    # Open dangerous port 23 (Telnet) + expired self-signed cert + missing HSTS/CSP + missing DMARC
    headers = HeaderScanResult(
        target="insecure.example.com",
        scanned_url="https://insecure.example.com",
        reachable=True,
        status_code=200,
        checks=[
            HeaderCheck(header="Strict-Transport-Security", present=False, value=None, severity="high", recommendation="Add HSTS"),
            HeaderCheck(header="Content-Security-Policy", present=False, value=None, severity="medium", recommendation="Add CSP"),
        ],
        error=None,
    )
    tls = TLSScanResult(
        target="insecure.example.com",
        port=443,
        reachable=True,
        tls_version="TLSv1.0",  # Deprecated protocol
        cipher="RC4-SHA",
        certificate=TLSCertificateInfo(
            subject="CN=insecure.example.com",
            issuer="CN=insecure.example.com",
            not_before=now,
            not_after=now,
            days_until_expiry=-5,
            expired=True,        # -40 pts
            self_signed=True,    # -25 pts
            signature_algorithm="sha1WithRSAEncryption",
            serial_number="999",
        ),
        error=None,
    )
    dns = DNSScanResult(
        target="insecure.example.com",
        a_records=["1.2.3.4"],
        aaaa_records=[],
        mx_records=[],
        ns_records=[],
        spf=SPFResult(present=False, record=None, valid=False, issues=[]),
        dmarc=DMARCResult(present=False, record=None, policy=None, valid=False, issues=[]),
        dkim=[],
        error=None,
    )
    ports = PortScanResult(
        target="insecure.example.com",
        start_port=1,
        end_port=1024,
        ports_scanned=1024,
        open_ports=[23, 3389],  # Telnet and RDP exposed
    )

    result = calculate_posture_score(headers=headers, tls=tls, dns=dns, ports=ports)
    # Penalties exceed 100, score must clamp to 0 with grade F
    assert result.score == 0
    assert result.grade == "F"
    assert len(result.deductions) > 0
    assert len(result.recommendations) > 0
