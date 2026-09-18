from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PortScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., description="Dominio autorizado, sin esquema. IPs crudas no son escaneables: el ownership solo se prueba por TXT DNS.")
    start_port: int = Field(1, ge=1, le=65535)
    end_port: int = Field(1024, ge=1, le=65535)

    @model_validator(mode="after")
    def _validate_range(self) -> "PortScanRequest":
        if self.start_port > self.end_port:
            raise ValueError("start_port no puede ser mayor que end_port.")
        return self


class PortScanResult(BaseModel):
    target: str
    start_port: int
    end_port: int
    ports_scanned: int
    open_ports: list[int]
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
