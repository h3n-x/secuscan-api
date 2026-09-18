from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.dns import DNSScanRequest, DNSScanResult
from app.services.dns_service import run_dns_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/dns", response_model=DNSScanResult)
async def scan_dns_endpoint(
    request: DNSScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> DNSScanResult:
    return await run_dns_scan(session, current_user.id, request.target, request.dkim_selectors)
