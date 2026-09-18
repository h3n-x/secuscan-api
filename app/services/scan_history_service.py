import logging
import uuid

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanModuleResult

logger = logging.getLogger(__name__)


class ScanNotFoundError(Exception):
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        super().__init__(f"No se encontró el scan '{scan_id}'.")


async def record_scan(
    session: AsyncSession,
    user_id: str,
    target: str,
    kind: str,
    module_results: dict[str, BaseModel],
) -> str | None:
    """Persiste el escaneo en scans + scan_module_results. Best-effort a propósito: el
    historial es secundario frente al resultado que ya se le devuelve al usuario, así que un
    fallo acá no debe tumbar la request — pero se loguea con scan_id y motivo explícitos para
    que un fallo recurrente en producción se note en los logs, no se pierda para siempre.

    Devuelve el scan_id si se guardó, o None si falló (best-effort)."""
    scan_id = str(uuid.uuid4())

    try:
        scan = Scan(id=scan_id, user_id=user_id, target=target, kind=kind)
        session.add(scan)

        for module, result in module_results.items():
            serialized = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
            session.add(
                ScanModuleResult(
                    scan_id=scan_id,
                    module=module,
                    result=serialized,
                )
            )

        await session.commit()
        return scan_id
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.warning(
            "Failed to persist scan history — scan_id=%s user_id=%s target=%s kind=%s reason=%s: %s",
            scan_id,
            user_id,
            target,
            kind,
            exc.__class__.__name__,
            exc,
        )
        return None


async def list_scans(
    session: AsyncSession, user_id: str, limit: int, offset: int
) -> tuple[list[Scan], int]:
    total = await session.scalar(
        select(func.count()).select_from(Scan).where(Scan.user_id == user_id)
    )
    scans = await session.scalars(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.requested_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(scans), total or 0


async def get_scan(session: AsyncSession, user_id: str, scan_id: str) -> tuple[Scan, list[ScanModuleResult]]:
    # Filtra por user_id en la MISMA query: un scan_id de otro usuario debe comportarse
    # exactamente igual que uno que no existe (404 no-enumerable), nunca 403 ni datos filtrados.
    scan = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    if scan is None:
        raise ScanNotFoundError(scan_id)

    modules = list(
        await session.scalars(select(ScanModuleResult).where(ScanModuleResult.scan_id == scan_id))
    )
    return scan, modules
