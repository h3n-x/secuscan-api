import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/scan/headers", {"target": "127.0.0.1", "ports": [80, 443]}),
        ("/scan/tls", {"target": "127.0.0.1", "ports": [80, 443]}),
        ("/scan/dns", {"target": "127.0.0.1", "ports": [80, 443]}),
        ("/scan/ports", {"target": "127.0.0.1", "ports": [80, 443]}),
    ],
)
def test_unknown_field_is_rejected_instead_of_ignored(path: str, body: dict) -> None:
    """Regresión: un campo desconocido (ej. 'ports' en vez de start_port/end_port) debe
    rechazarse con 422, nunca ignorarse silenciosamente y ejecutar un valor por defecto."""
    response = client.post(path, json=body)

    assert response.status_code == 422
    assert any("ports" in str(error.get("loc")) for error in response.json()["detail"])
