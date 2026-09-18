from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field


class SubdomainScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        ...,
        description="Dominio verificado a enumerar pasivamente (ej. 'example.com').",
    )


class SubdomainScanResult(BaseModel):
    target: str
    subdomains: list[str]
    count: int
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
