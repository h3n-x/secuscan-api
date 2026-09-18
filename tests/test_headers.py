import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


class _SecureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:  # silencia logs de test
        pass


class _BareHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        pass


def _run_server(handler_cls: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def secure_target() -> Iterator[str]:
    yield from _run_server(_SecureHandler)


@pytest.fixture
def bare_target() -> Iterator[str]:
    yield from _run_server(_BareHandler)


@pytest.fixture
def closed_target() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"127.0.0.1:{port}"


def test_scan_headers_detects_missing_security_headers(bare_target: str) -> None:
    response = client.post("/scan/headers", json={"target": bare_target})

    assert response.status_code == 200
    body = response.json()
    assert body["reachable"] is True
    assert body["status_code"] == 200
    assert {c["header"] for c in body["checks"] if not c["present"]} == {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    }
    assert all(c["severity"] != "ok" for c in body["checks"] if not c["present"])


def test_scan_headers_recognizes_present_security_headers(secure_target: str) -> None:
    response = client.post("/scan/headers", json={"target": secure_target})

    assert response.status_code == 200
    body = response.json()
    checks_by_header = {c["header"]: c for c in body["checks"]}

    assert checks_by_header["Strict-Transport-Security"]["present"] is True
    assert checks_by_header["Strict-Transport-Security"]["severity"] == "ok"
    assert checks_by_header["Content-Security-Policy"]["present"] is True
    assert checks_by_header["Referrer-Policy"]["present"] is False
    assert checks_by_header["Referrer-Policy"]["severity"] == "low"


def test_scan_headers_reports_unreachable_target(closed_target: str) -> None:
    response = client.post("/scan/headers", json={"target": closed_target})

    assert response.status_code == 200
    body = response.json()
    assert body["reachable"] is False
    assert body["status_code"] is None
    assert body["checks"] == []
    assert body["error"] is not None


class _RedirectToMetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def redirect_to_metadata_target() -> Iterator[str]:
    yield from _run_server(_RedirectToMetadataHandler)


def test_scan_headers_blocks_redirect_to_metadata(redirect_to_metadata_target: str) -> None:
    import asyncio
    from app.scanners.headers import scan_headers

    result = asyncio.run(scan_headers(redirect_to_metadata_target, allow_private=False))
    assert result.reachable is False
    assert "TargetNotAllowedError" in str(result.error) or "169.254.169.254" in str(result.error)
