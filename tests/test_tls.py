import datetime as dt
import os
import socket
import ssl
import tempfile
import threading
from collections.abc import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


def _generate_self_signed_cert(common_name: str, not_after: dt.datetime) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=60))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


def _run_tls_server(not_after: dt.datetime) -> Iterator[str]:
    cert_pem, key_pem = _generate_self_signed_cert("127.0.0.1", not_after)

    certfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    certfile.write(cert_pem)
    keyfile.write(key_pem)
    certfile.close()
    keyfile.close()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile.name, keyfile.name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    sock.settimeout(0.5)
    port = sock.getsockname()[1]

    stop_event = threading.Event()

    def serve() -> None:
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            try:
                with ssl_context.wrap_socket(conn, server_side=True) as tls_conn:
                    try:
                        tls_conn.recv(1024)
                    except OSError:
                        pass
            except ssl.SSLError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        stop_event.set()
        thread.join(timeout=2)
        sock.close()
        os.unlink(certfile.name)
        os.unlink(keyfile.name)


@pytest.fixture
def valid_tls_target() -> Iterator[str]:
    not_after = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    yield from _run_tls_server(not_after)


@pytest.fixture
def expired_tls_target() -> Iterator[str]:
    not_after = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    yield from _run_tls_server(not_after)


@pytest.fixture
def closed_target() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"127.0.0.1:{port}"


def _host_port(target: str) -> tuple[str, int]:
    host, port = target.split(":")
    return host, int(port)


def test_scan_tls_returns_certificate_details(valid_tls_target: str) -> None:
    host, port = _host_port(valid_tls_target)

    response = client.post("/scan/tls", json={"target": host, "port": port})

    assert response.status_code == 200
    body = response.json()
    assert body["reachable"] is True
    assert body["tls_version"] is not None
    assert body["certificate"] is not None
    assert body["certificate"]["expired"] is False
    assert 25 <= body["certificate"]["days_until_expiry"] <= 30
    assert body["certificate"]["self_signed"] is True
    assert "127.0.0.1" in body["certificate"]["subject"]


def test_scan_tls_flags_expired_certificate(expired_tls_target: str) -> None:
    host, port = _host_port(expired_tls_target)

    response = client.post("/scan/tls", json={"target": host, "port": port})

    assert response.status_code == 200
    body = response.json()
    assert body["reachable"] is True
    assert body["certificate"]["expired"] is True
    assert body["certificate"]["days_until_expiry"] < 0


def test_scan_tls_reports_unreachable_target(closed_target: str) -> None:
    host, port = _host_port(closed_target)

    response = client.post("/scan/tls", json={"target": host, "port": port})

    assert response.status_code == 200
    body = response.json()
    assert body["reachable"] is False
    assert body["certificate"] is None
    assert body["error"] is not None
