import asyncio
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.reporting_service import generate_markdown_report, generate_sarif_report
from app.services.scan_history_service import record_scan
from tests.conftest import _TestSessionLocal

client = TestClient(app)


def _auth_headers(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": "securepassword123"})
    token = client.post("/auth/login", json={"email": email, "password": "securepassword123"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


def test_generate_markdown_and_sarif_reports() -> None:
    sample_modules = {
        "posture": {
            "score": 85,
            "grade": "A",
            "deductions": [
                {
                    "module": "headers",
                    "rule_id": "headers.missing_csp",
                    "penalty": 10,
                    "reason": "Missing Content-Security-Policy",
                    "severity": "medium",
                }
            ],
            "recommendations": ["Add CSP header"],
        },
        "ports": {
            "start_port": 1,
            "end_port": 1024,
            "open_ports": [80, 443],
        },
        "headers": {
            "checks": [
                {
                    "header": "Content-Security-Policy",
                    "present": False,
                    "severity": "medium",
                    "recommendation": "Add CSP header",
                }
            ]
        },
    }

    # 1. Test Markdown Report
    md = generate_markdown_report(
        target="example.com",
        scan_id="scan-12345",
        kind="full",
        module_results=sample_modules,
    )
    assert "# Executive Security Audit Report: example.com" in md
    assert "85 / 100" in md
    assert "Letter Grade" in md
    assert "Missing Content-Security-Policy" in md
    assert "Add CSP header" in md

    # 2. Test SARIF Report
    sarif = generate_sarif_report(
        target="example.com",
        scan_id="scan-12345",
        module_results=sample_modules,
    )
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SecuScan Perimeter API"
    assert len(sarif["runs"][0]["results"]) >= 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "headers.missing.content_security_policy"


def test_get_scan_report_endpoint() -> None:
    auth = _auth_headers("report_user@example.com")
    from app.core.security import decode_access_token
    token = auth["Authorization"].removeprefix("Bearer ")
    user_id = decode_access_token(token)["sub"]

    async def seed():
        async with _TestSessionLocal() as session:
            return await record_scan(
                session,
                user_id,
                "target.example.com",
                kind="full",
                module_results={"ports": {"start_port": 1, "end_port": 1024, "open_ports": [443]}},
            )

    scan_id = asyncio.run(seed())

    # GET Markdown report
    response_md = client.get(f"/scans/{scan_id}/report", headers=auth)
    assert response_md.status_code == 200
    assert response_md.headers["content-type"].startswith("text/markdown")
    assert "Executive Security Audit Report" in response_md.text

    # GET SARIF report
    response_sarif = client.get(f"/scans/{scan_id}/report?format=sarif", headers=auth)
    assert response_sarif.status_code == 200
    body = response_sarif.json()
    assert body["version"] == "2.1.0"
