from datetime import datetime, timezone

import httpx

from urllib.parse import urljoin, urlparse

from app.core.config import get_settings
from app.core.target_guard import TargetNotAllowedError, ensure_public_target
from app.schemas.headers import HeaderCheck, HeaderScanResult, Severity

# (nombre de cabecera, severidad si falta, por qué importa)
_SECURITY_HEADERS: list[tuple[str, Severity, str]] = [
    ("Strict-Transport-Security", "high", "Fuerza HTTPS y previene downgrade/SSL-stripping."),
    ("Content-Security-Policy", "high", "Mitiga XSS restringiendo el origen de scripts/recursos."),
    ("X-Content-Type-Options", "medium", "Previene MIME-sniffing (usar 'nosniff')."),
    ("X-Frame-Options", "medium", "Previene clickjacking (usar 'DENY' o 'SAMEORIGIN')."),
    ("Referrer-Policy", "low", "Controla qué información de referer se filtra a terceros."),
    ("Permissions-Policy", "low", "Restringe acceso a APIs sensibles del navegador."),
]

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_REDIRECTS = 5


async def scan_headers(target: str, *, allow_private: bool | None = None) -> HeaderScanResult:
    """Solicita el target por HTTPS (fallback a HTTP) y evalúa cabeceras de seguridad con protección anti-SSRF en redirecciones."""
    scanned_at = datetime.now(timezone.utc)
    response: httpx.Response | None = None
    error: str | None = None

    if allow_private is None:
        allow_private = get_settings().allow_private_targets

    for scheme in ("https", "http"):
        current_url = f"{scheme}://{target}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
                redirect_count = 0
                while redirect_count <= _MAX_REDIRECTS:
                    resp = await client.get(current_url)
                    if resp.is_redirect and "location" in resp.headers:
                        raw_loc = resp.headers["location"]
                        resolved_url = urljoin(current_url, raw_loc)
                        parsed = urlparse(resolved_url)
                        redirect_host = parsed.hostname or ""

                        # Valida que el host de redirección no apunte a IPs privadas o cloud metadata (169.254.169.254)
                        await ensure_public_target(redirect_host, allow_private=allow_private)

                        current_url = resolved_url
                        redirect_count += 1
                        response = resp
                    else:
                        response = resp
                        break
            error = None
            break
        except (httpx.HTTPError, TargetNotAllowedError) as exc:
            error = f"{current_url}: {exc.__class__.__name__}: {exc}"
            continue

    if response is None:
        return HeaderScanResult(
            target=target,
            scanned_url=None,
            reachable=False,
            status_code=None,
            checks=[],
            error=error,
            scanned_at=scanned_at,
        )

    checks = [
        HeaderCheck(
            header=name,
            present=name in response.headers,
            value=response.headers.get(name),
            severity="ok" if name in response.headers else severity,
            recommendation=None if name in response.headers else recommendation,
        )
        for name, severity, recommendation in _SECURITY_HEADERS
    ]

    return HeaderScanResult(
        target=target,
        scanned_url=str(response.url),
        reachable=True,
        status_code=response.status_code,
        checks=checks,
        error=None,
        scanned_at=scanned_at,
    )
