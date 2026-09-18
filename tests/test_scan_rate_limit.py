from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import app.core.domain_ownership as domain_ownership
import app.core.rate_limit as rate_limit
import app.scanners.dns as dns_scanner
from app.core.config import get_settings
from app.main import app

client = TestClient(app)

# Deliberadamente sin el bypass_scan_guards: acá sí queremos que el rate limit real esté
# en juego. Solo bypasseamos ownership (no es lo que este archivo prueba) para no tener
# que publicar un TXT real por cada caso.


def _auth_headers(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": "correcthorse"})
    token = client.post("/auth/login", json={"email": email, "password": "correcthorse"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


async def _always_verified(session, user_id, target):
    return SimpleNamespace(domain=target, verified_at=None)


@pytest.fixture(autouse=True)
def _bypass_ownership_only(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(domain_ownership, "ensure_domain_verified", _always_verified)


def test_scan_endpoint_enforces_rate_limit_per_user(monkeypatch: pytest.MonkeyPatch) -> None:
    rate_limit._requests.clear()
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "2")
    get_settings.cache_clear()

    headers = _auth_headers("rate-limit-a@example.com")

    try:
        r1 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers)
        r2 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers)
        r3 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers)
    finally:
        get_settings.cache_clear()
        rate_limit._requests.clear()

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers


def test_scan_rate_limit_is_isolated_per_user(monkeypatch: pytest.MonkeyPatch) -> None:
    rate_limit._requests.clear()
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "1")
    get_settings.cache_clear()

    headers_a = _auth_headers("rate-limit-b@example.com")
    headers_b = _auth_headers("rate-limit-c@example.com")

    try:
        ra1 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers_a)
        ra2 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers_a)
        rb1 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers_b)
    finally:
        get_settings.cache_clear()
        rate_limit._requests.clear()

    assert ra1.status_code == 200
    assert ra2.status_code == 429
    assert rb1.status_code == 200  # otro usuario, cupo propio sin consumir


def test_full_scan_counts_as_a_single_rate_limit_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regresión: un escaneo completo (headers+tls+dns+ports) debe consumir 1 sola unidad,
    no 4. Si /scan/full llamara internamente a enforce_rate_limit 4 veces, ya la PRIMERA
    llamada a /scan/full fallaría acá (limit=1, y la 2da invocación interna vería count=1)."""
    rate_limit._requests.clear()

    async def _no_records(qname: str, rdtype: str) -> list[str]:
        return []

    async def _no_txt_strings(qname: str) -> list[tuple[bytes, ...]]:
        return []

    monkeypatch.setattr(dns_scanner, "_resolve", _no_records)
    monkeypatch.setattr(dns_scanner, "_resolve_txt_strings", _no_txt_strings)

    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "1")
    get_settings.cache_clear()

    headers = _auth_headers("rate-limit-full@example.com")

    try:
        r1 = client.post(
            "/scan/full",
            json={"target": "127.0.0.1", "start_port": 1, "end_port": 1},
            headers=headers,
        )
        r2 = client.post("/scan/headers", json={"target": "127.0.0.1"}, headers=headers)
    finally:
        get_settings.cache_clear()
        rate_limit._requests.clear()

    assert r1.status_code == 200, r1.json()
    assert r2.status_code == 429  # confirma que se consumió exactamente 1 unidad, no 0
