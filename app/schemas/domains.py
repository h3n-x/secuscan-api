from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DomainVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., description="Dominio a verificar, sin esquema (ej. 'example.com').")


class DomainVerificationResponse(BaseModel):
    domain: str
    status: Literal["pending", "verified"]
    txt_record_name: str
    txt_record_value: str
    created_at: datetime
    verified_at: datetime | None
