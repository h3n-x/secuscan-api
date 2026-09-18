from __future__ import annotations

import logging
from sqlalchemy.ext.asyncio import AsyncSession

import app.core.domain_ownership as domain_ownership
import app.core.rate_limit as rate_limit
from app.core.config import get_settings
from app.core.target_guard import ensure_public_target
from app.scanners.subdomains import scan_subdomains
from app.schemas.subdomains import SubdomainScanResult
from app.services.scan_history_service import record_scan

logger = logging.getLogger(__name__)


async def run_subdomain_scan(
    session: AsyncSession,
    user_id: str,
    target: str,
) -> SubdomainScanResult:
    await rate_limit.enforce_rate_limit(user_id)
    verification = await domain_ownership.ensure_domain_verified(session, user_id, target)

    settings = get_settings()
    await ensure_public_target(target, allow_private=settings.allow_private_targets)

    logger.warning(
        "Subdomain scan executed for verified domain — user_id=%s domain=%s verified_at=%s",
        user_id,
        verification.domain,
        verification.verified_at,
    )

    subdomains = await scan_subdomains(target)
    result = SubdomainScanResult(
        target=target,
        subdomains=subdomains,
        count=len(subdomains),
    )

    await record_scan(
        session,
        user_id,
        target,
        kind="subdomains",
        module_results={"subdomains": result},
    )
    return result
