from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception

from app.schemas.dns import (
    DKIMSelectorResult,
    DMARCResult,
    DNSScanResult,
    SPFResult,
)

_LIFETIME = 10.0


async def _resolve(qname: str, rdtype: str) -> list[str]:
    try:
        answer = await dns.asyncresolver.resolve(qname, rdtype, lifetime=_LIFETIME)
    except (dns.exception.DNSException, OSError):
        return []
    return [rdata.to_text() for rdata in answer]


async def _resolve_txt_strings(qname: str) -> list[tuple[bytes, ...]]:
    try:
        answer = await dns.asyncresolver.resolve(qname, "TXT", lifetime=_LIFETIME)
    except (dns.exception.DNSException, OSError):
        return []
    # rdata.strings expone los fragmentos crudos (sin comillas ni escapado de to_text()) de
    # cada registro TXT. Un TXT largo puede venir partido en varios character-strings de hasta
    # 255 bytes cada uno; deben concatenarse directamente (sin separador) para reconstruir el
    # valor original, ya que DNS parte el texto en cualquier punto, no en límites de palabra.
    return [rdata.strings for rdata in answer]


async def get_txt_records(qname: str) -> list[str]:
    raw = await _resolve_txt_strings(qname)
    return [b"".join(fragments).decode("utf-8", errors="replace") for fragments in raw]


def _evaluate_spf(txt_records: list[str]) -> SPFResult:
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return SPFResult(present=False, record=None, valid=False, issues=["No se encontró registro SPF."])

    issues: list[str] = []
    if len(spf_records) > 1:
        issues.append("Se encontraron múltiples registros SPF (inválido según RFC 7208; debe haber solo uno).")

    record = spf_records[0]
    lowered = record.lower()
    if "+all" in lowered:
        issues.append("Usa '+all': permite que cualquier servidor envíe correo en nombre del dominio.")
    elif not any(tag in lowered for tag in ("-all", "~all", "?all")):
        issues.append("No define un mecanismo 'all' final; el comportamiento por defecto queda indefinido.")

    return SPFResult(present=True, record=record, valid=len(issues) == 0, issues=issues)


def _evaluate_dmarc(txt_records: list[str]) -> DMARCResult:
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return DMARCResult(
            present=False, record=None, policy=None, valid=False, issues=["No se encontró registro DMARC."]
        )

    record = dmarc_records[0]
    policy: str | None = None
    for tag in record.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            policy = tag.split("=", 1)[1].strip().lower()
            break

    issues: list[str] = []
    if policy is None:
        issues.append("El registro DMARC no define una política 'p'.")
    elif policy == "none":
        issues.append("Política 'p=none': solo monitoreo, no rechaza ni pone en cuarentena correo fraudulento.")

    if "rua=" not in record.lower():
        issues.append("No define dirección de reporte agregado (rua).")

    return DMARCResult(present=True, record=record, policy=policy, valid=len(issues) == 0, issues=issues)


async def _check_dkim_selector(domain: str, selector: str) -> DKIMSelectorResult:
    qname = f"{selector}._domainkey.{domain}"
    txt_records = await get_txt_records(qname)
    dkim_records = [r for r in txt_records if "p=" in r.lower()]
    record = dkim_records[0] if dkim_records else (txt_records[0] if txt_records else None)
    return DKIMSelectorResult(selector=selector, present=bool(txt_records), record=record)


async def scan_dns(target: str, dkim_selectors: list[str]) -> DNSScanResult:
    """Consulta registros básicos y evalúa SPF/DMARC/DKIM (por selectores conocidos)."""
    scanned_at = datetime.now(timezone.utc)

    a_records = await _resolve(target, "A")
    aaaa_records = await _resolve(target, "AAAA")
    mx_records = await _resolve(target, "MX")
    ns_records = await _resolve(target, "NS")
    apex_txt = await get_txt_records(target)
    dmarc_txt = await get_txt_records(f"_dmarc.{target}")
    dkim_results = [await _check_dkim_selector(target, selector) for selector in dkim_selectors]

    error: str | None = None
    if not (a_records or aaaa_records or mx_records or ns_records):
        error = "El dominio no resolvió ningún registro básico (A/AAAA/MX/NS); puede no existir o no ser resoluble."

    return DNSScanResult(
        target=target,
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records,
        ns_records=ns_records,
        spf=_evaluate_spf(apex_txt),
        dmarc=_evaluate_dmarc(dmarc_txt),
        dkim=dkim_results,
        error=error,
        scanned_at=scanned_at,
    )
