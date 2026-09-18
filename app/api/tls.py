from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.tls import TLSScanRequest, TLSScanResult
from app.services.tls_service import run_tls_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/tls", response_model=TLSScanResult)
async def scan_tls_endpoint(
    request: TLSScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> TLSScanResult:
    return await run_tls_scan(session, current_user.id, request.target, request.port)
