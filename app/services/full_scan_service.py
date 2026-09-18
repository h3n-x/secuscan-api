import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession

import app.core.domain_ownership as domain_ownership
import app.core.rate_limit as rate_limit
from app.core.config import get_settings
from app.core.target_guard import ensure_public_target
from app.scanners.dns import scan_dns
from app.scanners.headers import scan_headers
from app.scanners.ports import scan_ports
from app.scanners.tls import scan_tls
from app.schemas.full_scan import FullScanResult
from app.services.scan_history_service import record_scan

logger = logging.getLogger(__name__)


async def run_full_scan(
    session: AsyncSession,
    user_id: str,
    target: str,
    *,
    tls_port: int,
    dkim_selectors: list[str],
    start_port: int,
    end_port: int,
) -> FullScanResult:
    # Un escaneo completo cuenta como 1 sola unidad de rate limit, no 4 (decisión explícita).
    # Por eso este orquestador llama a los scanners "crudos" directamente en vez de reusar
    # run_header_scan/run_tls_scan/run_dns_scan/run_port_scan: cada uno de esos hace su propio
    # rate-limit + ownership + SSRF guard, y reusarlos aquí habría consumido 4 unidades y
    # repetido la resolución DNS/consulta a domain_verifications 4 veces para el mismo target.
    await rate_limit.enforce_rate_limit(user_id)
    verification = await domain_ownership.ensure_domain_verified(session, user_id, target)

    settings = get_settings()
    verified_ip = await ensure_public_target(target, allow_private=settings.allow_private_targets)

    logger.warning(
        "Full scan executed for verified domain — user_id=%s domain=%s verified_at=%s",
        user_id,
        verification.domain,
        verification.verified_at,
    )

    headers_result, tls_result, dns_result, ports_result = await asyncio.gather(
        scan_headers(target),
        scan_tls(target, tls_port),
        scan_dns(target, dkim_selectors),
        scan_ports(target, start_port, end_port),
    )

    from app.services.scoring_service import calculate_posture_score

    posture_score = calculate_posture_score(
        headers=headers_result,
        tls=tls_result,
        dns=dns_result,
        ports=ports_result,
    )

    await record_scan(
        session,
        user_id,
        target,
        kind="full",
        module_results={
            "headers": headers_result,
            "tls": tls_result,
            "dns": dns_result,
            "ports": ports_result,
        },
    )

    return FullScanResult(
        target=target,
        headers=headers_result,
        tls=tls_result,
        dns=dns_result,
        ports=ports_result,
        posture=posture_score,
    )
