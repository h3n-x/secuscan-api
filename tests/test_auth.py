from fastapi.testclient import TestClient

from app.core.security import create_access_token, decode_access_token
from app.main import app

client = TestClient(app)


def test_register_creates_user() -> None:
    response = client.post("/auth/register", json={"email": "dev@example.com", "password": "correcthorse"})

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "dev@example.com"
    assert "id" in body
    assert "password" not in body
    assert "hashed_password" not in body


def test_register_rejects_duplicate_email_case_insensitive() -> None:
    client.post("/auth/register", json={"email": "dup@example.com", "password": "correcthorse"})

    response = client.post("/auth/register", json={"email": "DUP@example.com", "password": "anotherpass"})

    assert response.status_code == 409


def test_register_rejects_short_password() -> None:
    response = client.post("/auth/register", json={"email": "short@example.com", "password": "1234567"})

    assert response.status_code == 422


def test_register_rejects_unknown_field() -> None:
    response = client.post(
        "/auth/register",
        json={"email": "extra@example.com", "password": "correcthorse", "is_admin": True},
    )

    assert response.status_code == 422


def test_login_returns_access_token() -> None:
    client.post("/auth/register", json={"email": "login@example.com", "password": "correcthorse"})

    response = client.post("/auth/login", json={"email": "login@example.com", "password": "correcthorse"})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]

    payload = decode_access_token(body["access_token"])
    assert payload["type"] == "access"


def test_login_is_case_insensitive_on_email() -> None:
    client.post("/auth/register", json={"email": "case@example.com", "password": "correcthorse"})

    response = client.post("/auth/login", json={"email": "CASE@example.com", "password": "correcthorse"})

    assert response.status_code == 200


def test_login_rejects_wrong_password() -> None:
    client.post("/auth/register", json={"email": "wrongpass@example.com", "password": "correcthorse"})

    response = client.post("/auth/login", json={"email": "wrongpass@example.com", "password": "nope"})

    assert response.status_code == 401


def test_login_rejects_unknown_email() -> None:
    response = client.post("/auth/login", json={"email": "ghost@example.com", "password": "correcthorse"})

    assert response.status_code == 401


def test_access_token_roundtrip() -> None:
    token = create_access_token(subject="user-123")

    payload = decode_access_token(token)

    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"
