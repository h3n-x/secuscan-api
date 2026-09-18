import asyncio
import pytest
from fastapi.testclient import TestClient

import app.scanners.subdomains as subdomains_scanner
import app.services.subdomains_service as subdomains_service
from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


def test_scan_subdomains_parses_crtsh_response() -> None:
    fake_payload = [
        {"name_value": "api.example.com\nadmin.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "staging.example.com"},
        {"name_value": "unrelated.other.com"},  # Should be filtered out
    ]

    class FakeResponse:
        status_code = 200

        def json(self) -> list[dict[str, str]]:
            return fake_payload

    class FakeAsyncClient:
        async def get(self, *args, **kwargs) -> FakeResponse:  # type: ignore[no-untyped-def]
            return FakeResponse()

        async def aclose(self) -> None:
            pass

    discovered = asyncio.run(
        subdomains_scanner.scan_subdomains(
            "example.com", client=FakeAsyncClient()  # type: ignore[arg-type]
        )
    )

    assert "admin.example.com" in discovered
    assert "api.example.com" in discovered
    assert "example.com" in discovered
    assert "staging.example.com" in discovered
    assert "unrelated.other.com" not in discovered


def test_subdomains_endpoint_returns_success(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_scan(domain: str) -> list[str]:
        return ["api.example.test", "mail.example.test"]

    monkeypatch.setattr(subdomains_service, "scan_subdomains", fake_scan)

    response = client.post("/scan/subdomains", json={"target": "example.test"})
    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "example.test"
    assert body["count"] == 2
    assert body["subdomains"] == ["api.example.test", "mail.example.test"]
