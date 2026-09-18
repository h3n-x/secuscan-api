import socket

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


def test_scan_ports_rejects_range_outside_allowed_bounds() -> None:
    # ALLOWED_PORT_RANGE_END por defecto es 1024 (.env); 2000 debe rechazarse explícitamente.
    response = client.post(
        "/scan/ports",
        json={"target": "127.0.0.1", "start_port": 1, "end_port": 2000},
    )

    assert response.status_code == 400
    assert "fuera del rango permitido" in response.json()["detail"]


def test_scan_ports_detects_open_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # No hace falta accept(): el handshake TCP lo completa el kernel en cuanto hay listen().
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    monkeypatch.setenv("ALLOWED_PORT_RANGE_START", "1")
    monkeypatch.setenv("ALLOWED_PORT_RANGE_END", "65535")
    get_settings.cache_clear()
    try:
        response = client.post(
            "/scan/ports",
            json={"target": "127.0.0.1", "start_port": port, "end_port": port},
        )
    finally:
        sock.close()
        get_settings.cache_clear()

    assert response.status_code == 200
    body = response.json()
    assert body["open_ports"] == [port]
    assert body["ports_scanned"] == 1


def test_scan_ports_reports_closed_port(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nada escuchando -> ECONNREFUSED

    monkeypatch.setenv("ALLOWED_PORT_RANGE_START", "1")
    monkeypatch.setenv("ALLOWED_PORT_RANGE_END", "65535")
    get_settings.cache_clear()
    try:
        response = client.post(
            "/scan/ports",
            json={"target": "127.0.0.1", "start_port": port, "end_port": port},
        )
    finally:
        get_settings.cache_clear()

    assert response.status_code == 200
    body = response.json()
    assert body["open_ports"] == []
    assert body["ports_scanned"] == 1
