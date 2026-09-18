import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # RESTRICT (no CASCADE ni SET NULL): borrar un usuario con historial debe fallar
    # explícitamente hasta que se decida a propósito qué hacer con ese historial, en vez de
    # perderlo silenciosamente como efecto secundario de borrar la cuenta.
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # headers|tls|dns|ports|full
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ScanModuleResult(Base):
    __tablename__ = "scan_module_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # CASCADE: un scan_module_result no tiene sentido sin su Scan padre (a diferencia de la
    # relación user->scans, esto es pura composición).
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(String(16), nullable=False)  # headers|tls|dns|ports
    # JSON genérico (no JSONB de Postgres): compila a JSONB en Postgres y a JSON1/TEXT en
    # SQLite, que es lo que usan los tests.
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
