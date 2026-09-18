import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import app.services.full_scan_service as full_scan_service
from app.main import app
from app.schemas.dns import DKIMSelectorResult, DMARCResult, DNSScanResult, SPFResult
from app.schemas.headers import HeaderScanResult
from app.schemas.ports import PortScanResult
from app.schemas.tls import TLSScanResult

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")

_FAKE_DELAY = 0.2


async def _fake_scan_headers(target: str) -> HeaderScanResult:
    await asyncio.sleep(_FAKE_DELAY)
    return HeaderScanResult(
        target=target,
        scanned_url=f"https://{target}",
        reachable=True,
        status_code=200,
        checks=[],
        error=None,
    )


async def _fake_scan_tls(target: str, port: int) -> TLSScanResult:
    await asyncio.sleep(_FAKE_DELAY)
    return TLSScanResult(
        target=target,
        port=port,
        reachable=True,
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        certificate=None,
        error=None,
    )


async def _fake_scan_dns(target: str, dkim_selectors: list[str]) -> DNSScanResult:
    await asyncio.sleep(_FAKE_DELAY)
    return DNSScanResult(
        target=target,
        a_records=[],
        aaaa_records=[],
        mx_records=[],
        ns_records=[],
        spf=SPFResult(present=False, record=None, valid=False, issues=[]),
        dmarc=DMARCResult(present=False, record=None, policy=None, valid=False, issues=[]),
        dkim=[DKIMSelectorResult(selector=s, present=False, record=None) for s in dkim_selectors],
        error=None,
    )


async def _fake_scan_ports(target: str, start_port: int, end_port: int) -> PortScanResult:
    await asyncio.sleep(_FAKE_DELAY)
    return PortScanResult(
        target=target,
        start_port=start_port,
        end_port=end_port,
        ports_scanned=end_port - start_port + 1,
        open_ports=[],
    )


def _patch_all_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(full_scan_service, "scan_headers", _fake_scan_headers)
    monkeypatch.setattr(full_scan_service, "scan_tls", _fake_scan_tls)
    monkeypatch.setattr(full_scan_service, "scan_dns", _fake_scan_dns)
    monkeypatch.setattr(full_scan_service, "scan_ports", _fake_scan_ports)


def test_full_scan_runs_modules_in_parallel_and_assembles_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_all_scanners(monkeypatch)

    start = time.monotonic()
    response = client.post("/scan/full", json={"target": "example.com"})
    elapsed = time.monotonic() - start

    assert response.status_code == 200
    # Los 4 mocks duermen 0.2s cada uno; en paralelo el total ronda 0.2s, en secuencial ~0.8s.
    assert elapsed < 0.6, f"tardó {elapsed:.2f}s — no parece haber corrido en paralelo"

    body = response.json()
    assert body["target"] == "example.com"
    assert body["headers"]["reachable"] is True
    assert body["tls"]["tls_version"] == "TLSv1.3"
    assert body["dns"]["error"] is None
    assert len(body["dns"]["dkim"]) == 4  # DEFAULT_DKIM_SELECTORS
    assert body["ports"]["ports_scanned"] == 1024


def test_full_scan_rejects_unknown_field() -> None:
    response = client.post("/scan/full", json={"target": "example.com", "ports": [80, 443]})

    assert response.status_code == 422


def test_full_scan_respects_port_range_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    # scan_headers/tls/dns quedan mockeados (no nos interesa su resultado acá); scan_ports
    # queda real a propósito, para que su propio chequeo de rango dispare.
    monkeypatch.setattr(full_scan_service, "scan_headers", _fake_scan_headers)
    monkeypatch.setattr(full_scan_service, "scan_tls", _fake_scan_tls)
    monkeypatch.setattr(full_scan_service, "scan_dns", _fake_scan_dns)

    response = client.post("/scan/full", json={"target": "example.com", "end_port": 2000})

    assert response.status_code == 400
    assert "fuera del rango permitido" in response.json()["detail"]
