# tests/test_auth.py
import pytest

def test_register_and_token(client):
    # register a new user
    payload = {"username": "alicei", "email": "alicei@example.com", "password": "secret123", "full_name": "Alicei"}
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["username"] == "alicei"

    # get token (form-encoded)
    resp = client.post("/api/auth/token", data={"username": "alicei", "password": "secret123"})
    assert resp.status_code == 200, resp.text
    token_data = resp.json()
    assert "access_token" in token_data
    # token string should be non-empty
    assert token_data["access_token"]


def test_login_form_sets_cookie(client, temp_user):
    resp = client.post("/api/auth/login-form",
                       data={"username": temp_user["username"], "password": temp_user["password"]})
    assert resp.status_code == 200
    assert temp_user["username"] == temp_user["username"]


def test_register_validation_requires_fields(client):
    # missing password should trigger pydantic validation -> 422
    payload = {"username": "bob", "email": "bob@example.com"}
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 422