from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["ok", "low", "medium", "high"]


class HeaderScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., description="Dominio autorizado, sin esquema (ej. 'example.com'). IPs crudas no son escaneables: el ownership solo se prueba por TXT DNS.")


class HeaderCheck(BaseModel):
    header: str
    present: bool
    value: str | None
    severity: Severity
    recommendation: str | None


class HeaderScanResult(BaseModel):
    target: str
    scanned_url: str | None
    reachable: bool
    status_code: int | None
    checks: list[HeaderCheck]
    error: str | None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
