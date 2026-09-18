import asyncio
from datetime import datetime, timezone

from app.core.config import get_settings
from app.schemas.ports import PortScanResult


class PortRangeNotAllowedError(Exception):
    def __init__(self, start_port: int, end_port: int, allowed_start: int, allowed_end: int) -> None:
        self.start_port = start_port
        self.end_port = end_port
        self.allowed_start = allowed_start
        self.allowed_end = allowed_end
        super().__init__(
            f"Rango solicitado {start_port}-{end_port} fuera del rango permitido "
            f"{allowed_start}-{allowed_end}."
        )


async def _check_port(target: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


async def scan_ports(
    target: str, start_port: int, end_port: int, *, target_ip: str | None = None
) -> PortScanResult:
    """Escanea [start_port, end_port] con TCP connect scan, acotado por ALLOWED_PORT_RANGE_*."""
    settings = get_settings()
    if start_port < settings.allowed_port_range_start or end_port > settings.allowed_port_range_end:
        raise PortRangeNotAllowedError(
            start_port, end_port, settings.allowed_port_range_start, settings.allowed_port_range_end
        )

    scanned_at = datetime.now(timezone.utc)
    semaphore = asyncio.Semaphore(settings.port_scan_concurrency)
    ports = list(range(start_port, end_port + 1))
    connect_host = target_ip if target_ip else target

    results = await asyncio.gather(
        *(_check_port(connect_host, port, settings.port_scan_timeout_seconds, semaphore) for port in ports)
    )
    open_ports = [port for port, is_open in zip(ports, results) if is_open]

    return PortScanResult(
        target=target,
        start_port=start_port,
        end_port=end_port,
        ports_scanned=len(ports),
        open_ports=open_ports,
        scanned_at=scanned_at,
    )
