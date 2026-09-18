from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.headers import HeaderScanRequest, HeaderScanResult
from app.services.headers_service import run_header_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/headers", response_model=HeaderScanResult)
async def scan_headers_endpoint(
    request: HeaderScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> HeaderScanResult:
    return await run_header_scan(session, current_user.id, request.target)
