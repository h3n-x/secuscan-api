from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.dns import DEFAULT_DKIM_SELECTORS, DNSScanResult
from app.schemas.headers import HeaderScanResult
from app.schemas.ports import PortScanResult
from app.schemas.tls import TLSScanResult
from app.services.scoring_service import SecurityPostureScore


class FullScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        ...,
        description=(
            "Dominio autorizado, sin esquema (ej. 'example.com'). Se escanea con los 4 "
            "módulos (headers, TLS, DNS, puertos) contra este mismo target."
        ),
    )
    tls_port: int = Field(443, ge=1, le=65535, description="Puerto TLS a verificar.")
    dkim_selectors: list[str] = Field(
        default_factory=lambda: list(DEFAULT_DKIM_SELECTORS),
        description="Selectores DKIM a probar (ver DNSScanRequest).",
    )
    start_port: int = Field(1, ge=1, le=65535)
    end_port: int = Field(1024, ge=1, le=65535)

    @model_validator(mode="after")
    def _validate_port_range(self) -> "FullScanRequest":
        if self.start_port > self.end_port:
            raise ValueError("start_port no puede ser mayor que end_port.")
        return self


class FullScanResult(BaseModel):
    target: str
    headers: HeaderScanResult
    tls: TLSScanResult
    dns: DNSScanResult
    ports: PortScanResult
    posture: SecurityPostureScore | None = None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
