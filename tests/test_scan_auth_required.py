import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Deliberadamente SIN el fixture bypass_scan_guards: acá sí queremos que la
# autenticación real esté en juego, para confirmar que los 4 endpoints de escaneo
# efectivamente exigen JWT y no se puede colar un request sin token.


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/scan/headers", {"target": "example.com"}),
        ("/scan/tls", {"target": "example.com"}),
        ("/scan/dns", {"target": "example.com"}),
        ("/scan/ports", {"target": "example.com", "start_port": 1, "end_port": 10}),
        ("/scan/full", {"target": "example.com"}),
    ],
)
def test_scan_endpoint_requires_authentication(path: str, body: dict) -> None:
    response = client.post(path, json=body)

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/scan/headers", {"target": "example.com"}),
        ("/scan/tls", {"target": "example.com"}),
        ("/scan/dns", {"target": "example.com"}),
        ("/scan/ports", {"target": "example.com", "start_port": 1, "end_port": 10}),
        ("/scan/full", {"target": "example.com"}),
    ],
)
def test_scan_endpoint_rejects_invalid_token(path: str, body: dict) -> None:
    response = client.post(path, json=body, headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


def test_scan_endpoint_rejects_unverified_domain() -> None:
    """Con JWT real pero sin haber verificado el dominio, debe rechazar con 403 (no 401:
    el usuario SÍ está autenticado, solo no tiene ownership de ese target)."""
    email = "auth-required-check@example.com"
    client.post("/auth/register", json={"email": email, "password": "correcthorse"})
    token = client.post("/auth/login", json={"email": email, "password": "correcthorse"}).json()[
        "access_token"
    ]

    response = client.post(
        "/scan/headers",
        json={"target": "never-verified.com"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
