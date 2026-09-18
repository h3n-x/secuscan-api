from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class TLSScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., description="Dominio autorizado, sin esquema (ej. 'example.com'). IPs crudas no son escaneables: el ownership solo se prueba por TXT DNS.")
    port: int = Field(443, description="Puerto TLS a verificar.", ge=1, le=65535)


class TLSCertificateInfo(BaseModel):
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    expired: bool
    self_signed: bool
    signature_algorithm: str
    serial_number: str


class TLSScanResult(BaseModel):
    target: str
    port: int
    reachable: bool
    tls_version: str | None
    cipher: str | None
    certificate: TLSCertificateInfo | None
    error: str | None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
