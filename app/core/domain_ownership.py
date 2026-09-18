from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain_verification import DomainVerification


class DomainNotVerifiedError(Exception):
    def __init__(self, domain: str) -> None:
        self.domain = domain
        super().__init__(f"El dominio '{domain}' no está verificado para este usuario.")


def _extract_host(target: str) -> str:
    # 'target' en headers puede venir como 'host:puerto' (ej. 'localhost:8000'); tls/dns/ports
    # ya reciben el host solo, con el puerto en un campo aparte. No se toca un target con más
    # de un ':' (posible literal IPv6) — fuera de alcance por ahora.
    if target.count(":") == 1:
        return target.split(":", 1)[0]
    return target


async def ensure_domain_verified(session: AsyncSession, user_id: str, target: str) -> DomainVerification:
    """Rechaza el escaneo si 'target' no corresponde a un dominio verificado de este usuario.

    Nota: solo hay verificación por dominio (vía TXT DNS). Un target que sea una IP cruda
    nunca va a matchear ninguna fila de domain_verifications, así que hoy no hay forma de
    autorizar el escaneo de una IP directamente — es una limitación conocida, no un bug.
    """
    domain = _extract_host(target).strip().lower()

    verification = await session.scalar(
        select(DomainVerification).where(
            DomainVerification.user_id == user_id,
            DomainVerification.domain == domain,
            DomainVerification.status == "verified",
        )
    )
    if verification is None:
        raise DomainNotVerifiedError(domain)

    return verification
