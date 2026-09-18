from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ScanModuleResultResponse(BaseModel):
    module: str
    # Passthrough del JSON tal como se guardó (ya era un Pydantic model validado al escribirlo).
    # No se re-tipa por módulo acá: simplicidad MVP, mismo criterio que llevó a guardarlo como
    # JSON en vez de columnas relacionales por módulo.
    result: dict[str, Any]


class ScanSummaryResponse(BaseModel):
    id: str
    target: str
    kind: str
    requested_at: datetime


class ScanDetailResponse(ScanSummaryResponse):
    module_results: list[ScanModuleResultResponse]


class ScanListResponse(BaseModel):
    items: list[ScanSummaryResponse]
    total: int
    limit: int
    offset: int
