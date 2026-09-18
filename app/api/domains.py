from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db_session
from app.core.deps import get_current_user
from app.models.domain_verification import DomainVerification
from app.models.user import User
from app.schemas.domains import DomainVerificationRequest, DomainVerificationResponse
from app.services.domain_verification_service import (
    check_domain_verification,
    request_domain_verification,
    txt_record_name,
    txt_record_value,
)

router = APIRouter(prefix="/domains", tags=["domains"])


def _to_response(verification: DomainVerification) -> DomainVerificationResponse:
    return DomainVerificationResponse(
        domain=verification.domain,
        status=verification.status,
        txt_record_name=txt_record_name(verification.domain),
        txt_record_value=txt_record_value(verification.token),
        created_at=verification.created_at,
        verified_at=verification.verified_at,
    )


@router.post("", response_model=DomainVerificationResponse, status_code=201)
async def create_domain_verification(
    request: DomainVerificationRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> DomainVerificationResponse:
    verification = await request_domain_verification(session, current_user.id, request.domain)
    return _to_response(verification)


@router.post("/{domain}/verify", response_model=DomainVerificationResponse)
async def verify_domain(
    domain: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> DomainVerificationResponse:
    verification = await check_domain_verification(session, current_user.id, domain)
    return _to_response(verification)
