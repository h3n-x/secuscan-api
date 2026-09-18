import asyncio
import ipaddress
import logging

logger = logging.getLogger(__name__)

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetNotAllowedError(Exception):
    def __init__(self, target: str, ip: str, reason: str) -> None:
        self.target = target
        self.ip = ip
        self.reason = reason
        super().__init__(f"Target '{target}' resuelve a {ip} ({reason}); no permitido.")


async def _resolve_addresses(target: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target, None)
    except OSError:
        # No se pudo resolver: se deja que el scanner correspondiente lo reporte como target
        # inalcanzable. Este guard solo evalúa riesgo de SSRF, no existencia del target.
        return []
    return [info[4][0] for info in infos]


def _classify(ip: _IPAddress) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    return None


async def ensure_public_target(target: str, *, allow_private: bool) -> str | None:
    """Rechaza el target si resuelve a una IP privada/loopback/link-local/reservada.

    Mitiga SSRF hacia infraestructura interna (incluida la IP de metadata de la nube,
    169.254.169.254, clasificada como link-local). Devuelve la IP pública resuelta si está permitida.
    """
    if allow_private:
        return None

    host = target.split(":", 1)[0] if ":" in target and not target.startswith("[") else target
    resolved_ips = await _resolve_addresses(host)

    for raw_ip in resolved_ips:
        ip = ipaddress.ip_address(raw_ip)
        reason = _classify(ip)
        if reason is not None:
            logger.warning("Blocked SSRF-risk target: target=%s ip=%s reason=%s", target, ip, reason)
            raise TargetNotAllowedError(target, str(ip), reason)

    return resolved_ips[0] if resolved_ips else None
