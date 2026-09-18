import logging

from sqlalchemy.ext.asyncio import AsyncSession

import app.core.domain_ownership as domain_ownership
import app.core.rate_limit as rate_limit
from app.core.config import get_settings
from app.core.target_guard import ensure_public_target
from app.scanners.ports import scan_ports
from app.schemas.ports import PortScanResult
from app.services.scan_history_service import record_scan

logger = logging.getLogger(__name__)


async def run_port_scan(
    session: AsyncSession, user_id: str, target: str, start_port: int, end_port: int
) -> PortScanResult:
    await rate_limit.enforce_rate_limit(user_id)
    verification = await domain_ownership.ensure_domain_verified(session, user_id, target)

    settings = get_settings()
    verified_ip = await ensure_public_target(target, allow_private=settings.allow_private_targets)

    logger.warning(
        "Scan executed for verified domain — user_id=%s domain=%s verified_at=%s",
        user_id,
        verification.domain,
        verification.verified_at,
    )

    result = await scan_ports(target, start_port, end_port, target_ip=verified_ip)
    await record_scan(session, user_id, target, kind="ports", module_results={"ports": result})
    return result
