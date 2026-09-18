import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain_verification import DomainVerification
from app.scanners.dns import get_txt_records

TXT_VALUE_PREFIX = "secuscan-verify="


class DomainVerificationNotFoundError(Exception):
    pass


def txt_record_name(domain: str) -> str:
    return f"_secuscan-verify.{domain}"


def txt_record_value(token: str) -> str:
    return f"{TXT_VALUE_PREFIX}{token}"


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower()


async def _get_for_user(session: AsyncSession, user_id: str, domain: str) -> DomainVerification | None:
    return await session.scalar(
        select(DomainVerification).where(
            DomainVerification.user_id == user_id, DomainVerification.domain == domain
        )
    )


async def request_domain_verification(
    session: AsyncSession, user_id: str, domain: str
) -> DomainVerification:
    """Crea (o devuelve, si ya existía) la verificación pendiente para user_id + domain."""
    domain = _normalize_domain(domain)

    existing = await _get_for_user(session, user_id, domain)
    if existing is not None:
        return existing

    verification = DomainVerification(
        user_id=user_id, domain=domain, token=secrets.token_hex(16), status="pending"
    )
    session.add(verification)
    await session.commit()
    await session.refresh(verification)
    return verification


async def check_domain_verification(
    session: AsyncSession, user_id: str, domain: str
) -> DomainVerification:
    """Reconsulta el TXT de verificación y marca 'verified' si coincide con el token guardado."""
    domain = _normalize_domain(domain)

    verification = await _get_for_user(session, user_id, domain)
    if verification is None:
        raise DomainVerificationNotFoundError(domain)

    if verification.status == "verified":
        return verification

    txt_records = await get_txt_records(txt_record_name(domain))
    if txt_record_value(verification.token) in txt_records:
        verification.status = "verified"
        verification.verified_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(verification)

    return verification
