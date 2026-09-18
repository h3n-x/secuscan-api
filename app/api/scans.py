from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.scan_history import (
    ScanDetailResponse,
    ScanListResponse,
    ScanModuleResultResponse,
    ScanSummaryResponse,
)
from app.services.scan_history_service import get_scan, list_scans

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=ScanListResponse)
async def list_scans_endpoint(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanListResponse:
    scans, total = await list_scans(session, current_user.id, limit, offset)
    return ScanListResponse(
        items=[
            ScanSummaryResponse(id=s.id, target=s.target, kind=s.kind, requested_at=s.requested_at)
            for s in scans
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_endpoint(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanDetailResponse:
    scan, modules = await get_scan(session, current_user.id, scan_id)
    return ScanDetailResponse(
        id=scan.id,
        target=scan.target,
        kind=scan.kind,
        requested_at=scan.requested_at,
        module_results=[ScanModuleResultResponse(module=m.module, result=m.result) for m in modules],
    )


@router.get("/{scan_id}/report")
async def get_scan_report_endpoint(
    scan_id: str,
    format: str = Query("markdown", pattern="^(markdown|sarif)$"),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    from fastapi.responses import PlainTextResponse
    from app.services.reporting_service import generate_markdown_report, generate_sarif_report

    scan, modules = await get_scan(session, current_user.id, scan_id)
    module_dict = {m.module: m.result for m in modules}

    if format == "sarif":
        return generate_sarif_report(
            target=scan.target,
            scan_id=scan.id,
            module_results=module_dict,
        )

    md_content = generate_markdown_report(
        target=scan.target,
        scan_id=scan.id,
        kind=scan.kind,
        module_results=module_dict,
    )
    return PlainTextResponse(md_content, media_type="text/markdown")
