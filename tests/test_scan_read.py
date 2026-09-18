import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.core.security import decode_access_token
from app.main import app
from app.models.scan import Scan, ScanModuleResult
from app.schemas.headers import HeaderScanResult
from app.services.scan_history_service import record_scan
from tests.conftest import _TestSessionLocal

client = TestClient(app)


def _run(coro):
    return asyncio.run(coro)


def _auth_headers(email: str) -> dict[str, str]:
    client.post("/auth/register", json={"email": email, "password": "correcthorse"})
    token = client.post("/auth/login", json={"email": email, "password": "correcthorse"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


def _user_id_from(headers: dict[str, str]) -> str:
    token = headers["Authorization"].removeprefix("Bearer ")
    return decode_access_token(token)["sub"]


def _dummy_result(target: str) -> HeaderScanResult:
    return HeaderScanResult(
        target=target, scanned_url=None, reachable=False, status_code=None, checks=[], error=None
    )


async def _seed_scan(user_id: str, target: str, kind: str = "headers") -> str:
    async with _TestSessionLocal() as session:
        scan_id = await record_scan(
            session, user_id, target, kind=kind, module_results={"headers": _dummy_result(target)}
        )
    assert scan_id is not None
    return scan_id


async def _seed_scan_at(user_id: str, target: str, requested_at: datetime) -> str:
    scan_id = str(uuid.uuid4())
    async with _TestSessionLocal() as session:
        session.add(Scan(id=scan_id, user_id=user_id, target=target, kind="headers", requested_at=requested_at))
        session.add(
            ScanModuleResult(
                scan_id=scan_id, module="headers", result=_dummy_result(target).model_dump(mode="json")
            )
        )
        await session.commit()
    return scan_id


def test_list_scans_requires_auth() -> None:
    response = client.get("/scans")
    assert response.status_code == 401


def test_get_scan_requires_auth() -> None:
    response = client.get("/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 401


def test_list_scans_returns_only_own_scans_ordered_by_requested_at_desc() -> None:
    headers_a = _auth_headers("scan-list-a@example.com")
    headers_b = _auth_headers("scan-list-b@example.com")
    user_a_id = _user_id_from(headers_a)
    user_b_id = _user_id_from(headers_b)

    now = datetime.now(timezone.utc)
    _run(_seed_scan_at(user_b_id, "not-mine.example.com", now))  # de otro usuario: no debe salir

    id_older = _run(_seed_scan_at(user_a_id, "first.example.com", now - timedelta(minutes=5)))
    id_newer = _run(_seed_scan_at(user_a_id, "second.example.com", now))

    response = client.get("/scans", headers=headers_a)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] == [id_newer, id_older]


def test_list_scans_respects_limit_and_offset() -> None:
    headers = _auth_headers("scan-list-paging@example.com")
    user_id = _user_id_from(headers)

    now = datetime.now(timezone.utc)
    ids = [_run(_seed_scan_at(user_id, f"target-{i}.example.com", now - timedelta(minutes=i))) for i in range(5)]
    # ids[0] es el más nuevo (now - 0min), ids[4] el más viejo

    response = client.get("/scans", params={"limit": 2, "offset": 1}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 5
    assert body["limit"] == 2
    assert body["offset"] == 1
    assert [item["id"] for item in body["items"]] == [ids[1], ids[2]]


def test_list_scans_is_empty_for_a_user_with_no_history() -> None:
    headers = _auth_headers("scan-list-empty@example.com")

    response = client.get("/scans", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_get_scan_returns_detail_with_module_results() -> None:
    headers = _auth_headers("scan-detail@example.com")
    user_id = _user_id_from(headers)

    scan_id = _run(_seed_scan(user_id, "detail-target.example.com"))

    response = client.get(f"/scans/{scan_id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == scan_id
    assert body["target"] == "detail-target.example.com"
    assert body["kind"] == "headers"
    assert len(body["module_results"]) == 1
    assert body["module_results"][0]["module"] == "headers"
    assert body["module_results"][0]["result"]["target"] == "detail-target.example.com"


def test_get_scan_404_is_identical_whether_owned_by_another_user_or_nonexistent() -> None:
    """La propiedad de seguridad pedida: un scan_id de otro usuario y un scan_id que no
    existe deben ser indistinguibles para quien pregunta — mismo status, mismo shape de
    mensaje, para no filtrar si ese id existe o no."""
    headers_a = _auth_headers("scan-404-owner@example.com")
    headers_b = _auth_headers("scan-404-other@example.com")
    user_a_id = _user_id_from(headers_a)

    other_users_scan_id = _run(_seed_scan(user_a_id, "owner-only.example.com"))
    nonexistent_scan_id = "00000000-0000-0000-0000-000000000000"

    r_other = client.get(f"/scans/{other_users_scan_id}", headers=headers_b)
    r_ghost = client.get(f"/scans/{nonexistent_scan_id}", headers=headers_b)

    assert r_other.status_code == 404
    assert r_ghost.status_code == 404

    template_other = r_other.json()["detail"].replace(other_users_scan_id, "<id>")
    template_ghost = r_ghost.json()["detail"].replace(nonexistent_scan_id, "<id>")
    assert template_other == template_ghost
