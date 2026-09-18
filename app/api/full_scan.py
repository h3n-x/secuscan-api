from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.full_scan import FullScanRequest, FullScanResult
from app.services.full_scan_service import run_full_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/full", response_model=FullScanResult)
async def scan_full_endpoint(
    request: FullScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> FullScanResult:
    return await run_full_scan(
        session,
        current_user.id,
        request.target,
        tls_port=request.tls_port,
        dkim_selectors=request.dkim_selectors,
        start_port=request.start_port,
        end_port=request.end_port,
    )
