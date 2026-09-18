from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.auth import router as auth_router
from app.api.dns import router as dns_router
from app.api.domains import router as domains_router
from app.api.full_scan import router as full_scan_router
from app.api.headers import router as headers_router
from app.api.health import router as health_router
from app.api.ports import router as ports_router
from app.api.scans import router as scans_router
from app.api.subdomains import router as subdomains_router
from app.api.tls import router as tls_router
from app.core.domain_ownership import DomainNotVerifiedError
from app.core.rate_limit import RateLimitExceededError
from app.core.target_guard import TargetNotAllowedError
from app.scanners.ports import PortRangeNotAllowedError
from app.services.auth_service import EmailAlreadyRegisteredError, InvalidCredentialsError
from app.services.domain_verification_service import DomainVerificationNotFoundError
from app.services.scan_history_service import ScanNotFoundError

# Desde el Paso 10, el esquema lo gestiona Alembic (alembic/) — ya no hay
# Base.metadata.create_all acá. Correr "alembic upgrade head" es un paso explícito de
# arranque/despliegue, no algo que la app haga sola en cada boot (evita aplicar DDL sin
# querer en cada restart, y evita que dos réplicas corran migraciones en paralelo).
app = FastAPI(title="SecuScan API")

app.include_router(health_router)
app.include_router(headers_router)
app.include_router(tls_router)
app.include_router(dns_router)
app.include_router(ports_router)
app.include_router(subdomains_router)
app.include_router(full_scan_router)
app.include_router(auth_router)
app.include_router(domains_router)
app.include_router(scans_router)


@app.exception_handler(TargetNotAllowedError)
async def target_not_allowed_handler(request: Request, exc: TargetNotAllowedError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(PortRangeNotAllowedError)
async def port_range_not_allowed_handler(request: Request, exc: PortRangeNotAllowedError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(EmailAlreadyRegisteredError)
async def email_already_registered_handler(
    request: Request, exc: EmailAlreadyRegisteredError
) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": f"El email '{exc}' ya está registrado."})


@app.exception_handler(InvalidCredentialsError)
async def invalid_credentials_handler(request: Request, exc: InvalidCredentialsError) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": "Email o contraseña incorrectos."})


@app.exception_handler(DomainVerificationNotFoundError)
async def domain_verification_not_found_handler(
    request: Request, exc: DomainVerificationNotFoundError
) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"detail": f"No hay una verificación solicitada para '{exc}'. Pide una con POST /domains primero."},
    )


@app.exception_handler(DomainNotVerifiedError)
async def domain_not_verified_handler(request: Request, exc: DomainNotVerifiedError) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(RateLimitExceededError)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceededError) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": str(exc)},
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


@app.exception_handler(ScanNotFoundError)
async def scan_not_found_handler(request: Request, exc: ScanNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})
