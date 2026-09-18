import pytest
from fastapi.testclient import TestClient

import app.scanners.dns as dns_scanner
from app.main import app

client = TestClient(app)
pytestmark = pytest.mark.usefixtures("bypass_scan_guards")


def _patch_resolver(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[tuple[str, str], list[str]],
    txt_records: dict[str, list[tuple[bytes, ...]]] | None = None,
) -> None:
    async def fake_resolve(qname: str, rdtype: str) -> list[str]:
        return records.get((qname, rdtype), [])

    async def fake_resolve_txt_strings(qname: str) -> list[tuple[bytes, ...]]:
        return (txt_records or {}).get(qname, [])

    monkeypatch.setattr(dns_scanner, "_resolve", fake_resolve)
    monkeypatch.setattr(dns_scanner, "_resolve_txt_strings", fake_resolve_txt_strings)


def test_scan_dns_reports_well_configured_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(
        monkeypatch,
        records={
            ("example.test", "A"): ["203.0.113.10"],
            ("example.test", "MX"): ["10 mail.example.test."],
            ("example.test", "NS"): ["ns1.example.test.", "ns2.example.test."],
        },
        txt_records={
            "example.test": [(b"v=spf1 include:_spf.example.test -all",)],
            "_dmarc.example.test": [(b"v=DMARC1; p=reject; rua=mailto:dmarc@example.test",)],
            "default._domainkey.example.test": [(b"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w",)],
        },
    )

    response = client.post(
        "/scan/dns",
        json={"target": "example.test", "dkim_selectors": ["default", "google"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["error"] is None
    assert body["a_records"] == ["203.0.113.10"]
    assert body["mx_records"] == ["10 mail.example.test."]

    assert body["spf"]["present"] is True
    assert body["spf"]["valid"] is True

    assert body["dmarc"]["present"] is True
    assert body["dmarc"]["policy"] == "reject"
    assert body["dmarc"]["valid"] is True

    dkim_by_selector = {d["selector"]: d for d in body["dkim"]}
    assert dkim_by_selector["default"]["present"] is True
    assert dkim_by_selector["google"]["present"] is False


def test_scan_dns_reassembles_multi_fragment_txt_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regresión: un TXT largo llega partido por DNS en varios character-strings que no
    coinciden con límites de palabra. Deben concatenarse directamente, sin comillas ni
    espacios intermedios, para no corromper valores como una IP en un mecanismo 'ip4:'."""
    _patch_resolver(
        monkeypatch,
        records={("example.test", "A"): ["203.0.113.10"]},
        txt_records={
            "example.test": [(b"v=spf1 ip4:62.253.2", b"27.114 ~all")],
        },
    )

    response = client.post("/scan/dns", json={"target": "example.test"})

    assert response.status_code == 200
    body = response.json()
    assert body["spf"]["present"] is True
    assert body["spf"]["record"] == "v=spf1 ip4:62.253.227.114 ~all"
    assert body["spf"]["valid"] is True


def test_scan_dns_flags_permissive_spf_and_missing_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(
        monkeypatch,
        records={("example.test", "A"): ["203.0.113.10"]},
        txt_records={"example.test": [(b"v=spf1 include:_spf.example.test +all",)]},
    )

    response = client.post("/scan/dns", json={"target": "example.test"})

    assert response.status_code == 200
    body = response.json()

    assert body["spf"]["present"] is True
    assert body["spf"]["valid"] is False
    assert any("+all" in issue for issue in body["spf"]["issues"])

    assert body["dmarc"]["present"] is False
    assert body["dmarc"]["valid"] is False


def test_scan_dns_flags_multiple_spf_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(
        monkeypatch,
        records={("example.test", "A"): ["203.0.113.10"]},
        txt_records={
            "example.test": [
                (b"v=spf1 include:_spf.example.test -all",),
                (b"v=spf1 include:_spf2.example.test -all",),
            ]
        },
    )

    response = client.post("/scan/dns", json={"target": "example.test"})

    assert response.status_code == 200
    body = response.json()
    assert body["spf"]["present"] is True
    assert body["spf"]["valid"] is False
    assert any("múltiples" in issue for issue in body["spf"]["issues"])


def test_scan_dns_sets_error_when_no_basic_records_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, records={})

    response = client.post("/scan/dns", json={"target": "example.test"})

    assert response.status_code == 200
    body = response.json()
    assert body["error"] is not None
    assert body["a_records"] == []
