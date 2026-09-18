import asyncio
import os
from types import SimpleNamespace

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# La suite de tests escanea deliberadamente servidores locales en 127.0.0.1 (headers/tls/ports)
# para no depender de red externa ni de dominios de terceros. Se activa aquí el mismo bypass
# documentado en .env.example, solo para el proceso de tests, antes de que algo llame a
# get_settings() por primera vez (que queda cacheada con @lru_cache).
os.environ.setdefault("ALLOW_PRIVATE_TARGETS", "true")

# JWT_SECRET_KEY en .env.example queda vacío a propósito (cada dev genera el suyo); los tests
# no deben depender de que el .env local ya lo tenga seteado, así que fijamos uno determinístico
# solo para el proceso de pytest.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-pytest-only-not-for-production")

import app.core.domain_ownership as domain_ownership  # noqa: E402  (después del setdefault de arriba)
import app.core.rate_limit as rate_limit  # noqa: E402
from app.core.db import Base, get_db_session  # noqa: E402
from app.core.deps import get_current_user  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402

FAKE_SCANNER_TEST_USER_ID = "scanner-test-user"

# StaticPool: una base ":memory:" normal crea una BD nueva por cada conexión del pool y
# los datos "desaparecen" entre queries. Con StaticPool todas las conexiones comparten la
# misma conexión física, así la BD en memoria persiste durante todo el test.
_test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSessionLocal = async_sessionmaker(_test_engine, expire_on_commit=False)


@event.listens_for(_test_engine.sync_engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
    # SQLite trae el enforcement de FK apagado por defecto por conexión; sin esto,
    # ondelete="RESTRICT"/"CASCADE" no se comportarían como en Postgres durante los tests.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async def _override_get_db_session():
    async with _TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db_session] = _override_get_db_session


@pytest.fixture(autouse=True)
def _reset_test_database():
    async def _reset() -> None:
        async with _test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_reset())
    yield


@pytest.fixture
def bypass_scan_guards(monkeypatch: pytest.MonkeyPatch, _reset_test_database):
    """Para los tests de los 4 scanners (headers/tls/dns/ports): esos tests no re-verifican
    auth, ownership de dominio ni rate limiting (cubierto a fondo en test_auth.py,
    test_domains.py y test_scan_rate_limit.py) — solo necesitan pasar esas capas para poder
    probar la lógica de escaneo en sí. Todos comparten el mismo user_id fijo entre tests, así
    que sin este bypass el rate limit (default 10/hora) rompería la suite por acumulación."""
    fake_user = SimpleNamespace(id=FAKE_SCANNER_TEST_USER_ID, email="scanner-tests@example.com")
    app.dependency_overrides[get_current_user] = lambda: fake_user

    # record_scan (Paso 9) necesita que user_id exista de verdad en 'users' — con FK
    # enforcement encendido, si no, cada escaneo de estos tests fallaría a persistir su
    # historial por violación de FK (silenciosamente, por el propio diseño best-effort).
    async def _ensure_fake_user_exists() -> None:
        async with _TestSessionLocal() as session:
            existing = await session.get(User, FAKE_SCANNER_TEST_USER_ID)
            if existing is None:
                session.add(
                    User(id=FAKE_SCANNER_TEST_USER_ID, email=fake_user.email, hashed_password="unused")
                )
                await session.commit()

    asyncio.run(_ensure_fake_user_exists())

    async def _always_verified(session, user_id, target):
        return SimpleNamespace(domain=target, verified_at=None)

    async def _no_rate_limit(user_id):
        return None

    monkeypatch.setattr(domain_ownership, "ensure_domain_verified", _always_verified)
    monkeypatch.setattr(rate_limit, "enforce_rate_limit", _no_rate_limit)

    yield

    del app.dependency_overrides[get_current_user]
