import pytest
from fastapi.testclient import TestClient

import app.scanners.dns as dns_scanner
from app.main import app

client = TestClient(app)


def _auth_headers(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": "correcthorse"})
    response = client.post("/auth/login", json={"email": email, "password": "correcthorse"})
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _patch_txt(monkeypatch: pytest.MonkeyPatch, records: dict[str, list[tuple[bytes, ...]]]) -> None:
    async def fake_resolve_txt_strings(qname: str) -> list[tuple[bytes, ...]]:
        return records.get(qname, [])

    monkeypatch.setattr(dns_scanner, "_resolve_txt_strings", fake_resolve_txt_strings)


def test_create_domain_verification_requires_auth() -> None:
    response = client.post("/domains", json={"domain": "example.com"})

    assert response.status_code == 401


def test_create_domain_verification_rejects_unknown_field() -> None:
    headers = _auth_headers("domains-a@example.com")

    response = client.post(
        "/domains", json={"domain": "example.com", "auto_verify": True}, headers=headers
    )

    assert response.status_code == 422


def test_create_domain_verification_is_idempotent() -> None:
    headers = _auth_headers("domains-b@example.com")

    first = client.post("/domains", json={"domain": "example.com"}, headers=headers).json()
    second = client.post("/domains", json={"domain": "example.com"}, headers=headers).json()

    assert first["status"] == "pending"
    assert first["txt_record_name"] == "_secuscan-verify.example.com"
    assert first["txt_record_value"].startswith("secuscan-verify=")
    assert first["txt_record_value"] == second["txt_record_value"]  # mismo token, no se regenera


def test_verify_domain_stays_pending_when_txt_not_published(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers("domains-c@example.com")
    client.post("/domains", json={"domain": "example.com"}, headers=headers)

    _patch_txt(monkeypatch, {})

    response = client.post("/domains/example.com/verify", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pending"
    assert body["verified_at"] is None


def test_verify_domain_succeeds_when_txt_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers("domains-d@example.com")
    created = client.post("/domains", json={"domain": "example.com"}, headers=headers).json()

    _patch_txt(
        monkeypatch,
        {"_secuscan-verify.example.com": [(created["txt_record_value"].encode(),)]},
    )

    response = client.post("/domains/example.com/verify", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["verified_at"] is not None


def test_verify_domain_not_requested_returns_404() -> None:
    headers = _auth_headers("domains-e@example.com")

    response = client.post("/domains/never-requested.com/verify", headers=headers)

    assert response.status_code == 404


def test_domain_verification_is_isolated_per_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un usuario no puede disparar/leer la verificación de un dominio pedido por otro usuario."""
    headers_a = _auth_headers("domains-f-owner@example.com")
    headers_b = _auth_headers("domains-f-other@example.com")

    client.post("/domains", json={"domain": "shared-example.com"}, headers=headers_a)

    response = client.post("/domains/shared-example.com/verify", headers=headers_b)

    assert response.status_code == 404
