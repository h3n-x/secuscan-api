from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.subdomains import SubdomainScanRequest, SubdomainScanResult
from app.services.subdomains_service import run_subdomain_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/subdomains", response_model=SubdomainScanResult)
async def scan_subdomains_endpoint(
    request: SubdomainScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> SubdomainScanResult:
    return await run_subdomain_scan(session, current_user.id, request.target)
