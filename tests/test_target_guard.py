import asyncio

import pytest

import app.core.target_guard as target_guard
from app.core.target_guard import TargetNotAllowedError, ensure_public_target


def _patch_resolution(monkeypatch: pytest.MonkeyPatch, ips: list[str]) -> None:
    async def fake_resolve(target: str) -> list[str]:
        return ips

    monkeypatch.setattr(target_guard, "_resolve_addresses", fake_resolve)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # RFC 1918
        "172.16.0.5",  # RFC 1918
        "192.168.1.1",  # RFC 1918
        "169.254.169.254",  # link-local: IP de metadata de la nube
        "::1",  # loopback IPv6
        "::ffff:127.0.0.1",  # loopback IPv4-mapeada en IPv6
    ],
)
def test_ensure_public_target_blocks_private_and_link_local(monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
    _patch_resolution(monkeypatch, [ip])

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_public_target("some-target.test", allow_private=False))


def test_ensure_public_target_allows_public_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolution(monkeypatch, ["203.113.5.10"])

    asyncio.run(ensure_public_target("some-target.test", allow_private=False))


def test_ensure_public_target_allows_private_when_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolution(monkeypatch, ["127.0.0.1"])

    asyncio.run(ensure_public_target("some-target.test", allow_private=True))


def test_ensure_public_target_skips_check_when_resolution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(target: str) -> list[str]:
        return []

    monkeypatch.setattr(target_guard, "_resolve_addresses", fake_resolve)

    asyncio.run(ensure_public_target("does-not-resolve.test", allow_private=False))
