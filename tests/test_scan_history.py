import asyncio
import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.main import app
from app.models.scan import Scan, ScanModuleResult
from app.models.user import User
from app.schemas.headers import HeaderScanResult
from app.services.scan_history_service import record_scan
from tests.conftest import FAKE_SCANNER_TEST_USER_ID, _TestSessionLocal

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


def _run(coro):
    return asyncio.run(coro)


async def _scans_for(user_id: str) -> list[Scan]:
    async with _TestSessionLocal() as session:
        return list(await session.scalars(select(Scan).where(Scan.user_id == user_id)))


async def _modules_for(scan_id: str) -> list[ScanModuleResult]:
    async with _TestSessionLocal() as session:
        return list(await session.scalars(select(ScanModuleResult).where(ScanModuleResult.scan_id == scan_id)))


def _dummy_header_result(target: str) -> HeaderScanResult:
    return HeaderScanResult(
        target=target, scanned_url=None, reachable=False, status_code=None, checks=[], error="test"
    )


def test_scan_module_results_scan_id_is_indexed() -> None:
    assert ScanModuleResult.__table__.columns["scan_id"].index is True


def test_scans_user_id_is_indexed() -> None:
    assert Scan.__table__.columns["user_id"].index is True


def test_scan_headers_writes_history() -> None:
    target = "127.0.0.1:1"  # puerto casi seguro cerrado: el scan igual "completa" (reachable=False)
    response = client.post("/scan/headers", json={"target": target})
    assert response.status_code == 200

    scans = [s for s in _run(_scans_for(FAKE_SCANNER_TEST_USER_ID)) if s.target == target]
    assert len(scans) == 1
    assert scans[0].kind == "headers"

    modules = _run(_modules_for(scans[0].id))
    assert len(modules) == 1
    assert modules[0].module == "headers"
    assert modules[0].result["target"] == target


def test_full_scan_writes_history_with_four_module_results(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.full_scan_service as full_scan_service
    from app.schemas.dns import DKIMSelectorResult, DMARCResult, DNSScanResult, SPFResult
    from app.schemas.ports import PortScanResult
    from app.schemas.tls import TLSScanResult

    target = "history-full-test.local"

    async def _fake_headers(target: str) -> HeaderScanResult:
        return _dummy_header_result(target)

    async def _fake_tls(target: str, port: int) -> TLSScanResult:
        return TLSScanResult(
            target=target, port=port, reachable=False, tls_version=None, cipher=None,
            certificate=None, error="test",
        )

    async def _fake_dns(target: str, dkim_selectors: list[str]) -> DNSScanResult:
        return DNSScanResult(
            target=target, a_records=[], aaaa_records=[], mx_records=[], ns_records=[],
            spf=SPFResult(present=False, record=None, valid=False, issues=[]),
            dmarc=DMARCResult(present=False, record=None, policy=None, valid=False, issues=[]),
            dkim=[DKIMSelectorResult(selector=s, present=False, record=None) for s in dkim_selectors],
            error=None,
        )

    async def _fake_ports(target: str, start_port: int, end_port: int) -> PortScanResult:
        return PortScanResult(
            target=target, start_port=start_port, end_port=end_port,
            ports_scanned=end_port - start_port + 1, open_ports=[],
        )

    monkeypatch.setattr(full_scan_service, "scan_headers", _fake_headers)
    monkeypatch.setattr(full_scan_service, "scan_tls", _fake_tls)
    monkeypatch.setattr(full_scan_service, "scan_dns", _fake_dns)
    monkeypatch.setattr(full_scan_service, "scan_ports", _fake_ports)

    response = client.post("/scan/full", json={"target": target})
    assert response.status_code == 200

    scans = [s for s in _run(_scans_for(FAKE_SCANNER_TEST_USER_ID)) if s.target == target]
    assert len(scans) == 1
    assert scans[0].kind == "full"

    modules = _run(_modules_for(scans[0].id))
    assert {m.module for m in modules} == {"headers", "tls", "dns", "ports"}


def test_record_scan_is_best_effort_and_logs_scan_id_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    """Regresión: si falla el INSERT (acá, FK a un user_id inexistente), record_scan no debe
    propagar la excepción, pero el log de warning debe incluir scan_id y el motivo real."""
    missing_user_id = "user-that-does-not-exist"

    async def _attempt() -> None:
        async with _TestSessionLocal() as session:
            await record_scan(
                session,
                missing_user_id,
                "example.com",
                kind="headers",
                module_results={"headers": _dummy_header_result("example.com")},
            )

    with caplog.at_level(logging.WARNING, logger="app.services.scan_history_service"):
        _run(_attempt())  # no debe lanzar

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "Failed to persist scan history" in message
    assert f"user_id={missing_user_id}" in message
    assert "scan_id=" in message
    assert "reason=" in message

    assert _run(_scans_for(missing_user_id)) == []


def test_deleting_user_with_scan_history_is_restricted() -> None:
    """RESTRICT en scans.user_id: borrar un usuario con historial debe fallar explícito,
    no silenciarse ni cascadear el borrado del historial."""
    user_id = str(uuid.uuid4())

    async def _setup_and_attempt_delete() -> None:
        async with _TestSessionLocal() as session:
            session.add(User(id=user_id, email=f"{user_id}@example.com", hashed_password="unused"))
            await session.commit()

        async with _TestSessionLocal() as session:
            await record_scan(
                session,
                user_id,
                "example.com",
                kind="headers",
                module_results={"headers": _dummy_header_result("example.com")},
            )

        async with _TestSessionLocal() as session:
            user = await session.get(User, user_id)
            await session.delete(user)
            with pytest.raises(SQLAlchemyError):
                await session.commit()

    _run(_setup_and_attempt_delete())
