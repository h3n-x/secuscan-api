from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models.user import User


class EmailAlreadyRegisteredError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


def _normalize_email(email: str) -> str:
    return email.strip().lower()


async def register_user(session: AsyncSession, email: str, password: str) -> User:
    email = _normalize_email(email)

    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise EmailAlreadyRegisteredError(email)

    user = User(email=email, hashed_password=hash_password(password))
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as exc:
        # Ventana de carrera: dos registros concurrentes con el mismo email pueden pasar
        # ambos el chequeo anterior; la constraint UNIQUE en DB es la garantía real.
        await session.rollback()
        raise EmailAlreadyRegisteredError(email) from exc

    await session.refresh(user)
    return user


async def authenticate_user(session: AsyncSession, email: str, password: str) -> User:
    email = _normalize_email(email)

    user = await session.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.hashed_password):
        raise InvalidCredentialsError(email)

    return user
