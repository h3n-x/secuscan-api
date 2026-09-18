from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.ports import PortScanRequest, PortScanResult
from app.services.ports_service import run_port_scan

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/ports", response_model=PortScanResult)
async def scan_ports_endpoint(
    request: PortScanRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PortScanResult:
    return await run_port_scan(session, current_user.id, request.target, request.start_port, request.end_port)
