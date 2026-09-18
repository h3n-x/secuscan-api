import asyncio
import ssl
from datetime import datetime, timezone

from cryptography import x509

from app.schemas.tls import TLSCertificateInfo, TLSScanResult

_TIMEOUT = 10.0


def _build_client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # No validamos la cadena de confianza: el objetivo es reportar validez/expiración del
    # certificado tal como lo presenta el servidor, no decidir si un cliente confiaría en él.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _parse_certificate(der_cert: bytes, scanned_at: datetime) -> TLSCertificateInfo:
    cert = x509.load_der_x509_certificate(der_cert)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    sig_hash = cert.signature_hash_algorithm
    signature_algorithm = sig_hash.name if sig_hash is not None else cert.signature_algorithm_oid.dotted_string

    return TLSCertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=(not_after - scanned_at).days,
        expired=not_after < scanned_at,
        self_signed=cert.subject == cert.issuer,
        signature_algorithm=signature_algorithm,
        serial_number=str(cert.serial_number),
    )


async def scan_tls(target: str, port: int = 443) -> TLSScanResult:
    """Conecta por TLS al target:port y reporta versión/cipher negociados y datos del certificado."""
    scanned_at = datetime.now(timezone.utc)
    ssl_context = _build_client_context()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=ssl_context, server_hostname=target),
            timeout=_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return TLSScanResult(
            target=target,
            port=port,
            reachable=False,
            tls_version=None,
            cipher=None,
            certificate=None,
            error=f"{exc.__class__.__name__}: {exc}",
            scanned_at=scanned_at,
        )

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der_cert = ssl_object.getpeercert(binary_form=True)
        tls_version = ssl_object.version()
        cipher_info = ssl_object.cipher()
        cipher = cipher_info[0] if cipher_info else None
    finally:
        writer.close()
        await writer.wait_closed()

    if der_cert is None:
        return TLSScanResult(
            target=target,
            port=port,
            reachable=True,
            tls_version=tls_version,
            cipher=cipher,
            certificate=None,
            error="No se pudo obtener el certificado del peer.",
            scanned_at=scanned_at,
        )

    return TLSScanResult(
        target=target,
        port=port,
        reachable=True,
        tls_version=tls_version,
        cipher=cipher,
        certificate=_parse_certificate(der_cert, scanned_at),
        error=None,
        scanned_at=scanned_at,
    )
