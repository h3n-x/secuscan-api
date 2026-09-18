from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2"]


class DNSScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., description="Dominio autorizado a verificar (ej. 'example.com').")
    dkim_selectors: list[str] = Field(
        default_factory=lambda: list(DEFAULT_DKIM_SELECTORS),
        description=(
            "Selectores DKIM a probar (se consulta '<selector>._domainkey.<target>'). "
            "DNS no permite enumerar selectores existentes: solo se prueban los indicados/comunes."
        ),
    )


class SPFResult(BaseModel):
    present: bool
    record: str | None
    valid: bool
    issues: list[str]


class DMARCResult(BaseModel):
    present: bool
    record: str | None
    policy: str | None
    valid: bool
    issues: list[str]


class DKIMSelectorResult(BaseModel):
    selector: str
    present: bool
    record: str | None


class DNSScanResult(BaseModel):
    target: str
    a_records: list[str]
    aaaa_records: list[str]
    mx_records: list[str]
    ns_records: list[str]
    spf: SPFResult
    dmarc: DMARCResult
    dkim: list[DKIMSelectorResult]
    error: str | None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
