import pytest
from datetime import datetime, timedelta

from app import database as app_database


def test_token_includes_refresh_token(client):
    # register and request token
    payload = {"username": "refresh_user", "email": "refresh_user@example.com", "password": "secret123"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 200, r.text

    r2 = client.post("/api/auth/token", data={"username": "refresh_user", "password": "secret123"})
    assert r2.status_code == 200, r2.text
    data = r2.json()
    assert "access_token" in data and data["access_token"]
    assert "refresh_token" in data and data["refresh_token"]


def test_refresh_rotates_tokens(client):
    # register and get initial tokens
    payload = {"username": "rotater", "email": "rotater@example.com", "password": "pwrotate"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 200, r.text

    r2 = client.post("/api/auth/token", data={"username": "rotater", "password": "pwrotate"})
    assert r2.status_code == 200, r2.text
    td = r2.json()
    old_refresh = td.get("refresh_token")
    assert old_refresh

    # use refresh endpoint to rotate
    r3 = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert r3.status_code == 200, r3.text
    new_td = r3.json()
    assert "access_token" in new_td and new_td["access_token"]
    new_refresh = new_td.get("refresh_token")
    # rotation should issue a new refresh token (if storage succeeded)
    assert new_refresh != old_refresh

    # old refresh should no longer work
    r4 = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert r4.status_code == 401


def test_refresh_via_cookie(client, temp_user):
    # login-form sets cookies (access_token and refresh_token)
    resp = client.post("/api/auth/login-form", data={"username": temp_user["username"], "password": temp_user["password"]})
    assert resp.status_code == 200, resp.text

    # ensure cookie present
    assert client.cookies.get("refresh_token") is not None

    # call refresh without body - should read cookie and rotate
    r = client.post("/api/auth/refresh", json={})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "access_token" in data and data["access_token"]
    # client cookie jar should be updated to new refresh token (if server set cookie)
    assert client.cookies.get("refresh_token") is not None


def test_expired_refresh_token_is_rejected(client):
    # create an expired refresh token record directly in DB
    db = app_database.db
    token = "expired_refresh_token_test"
    now = datetime.utcnow()
    past = now - timedelta(days=7)
    db.create_record(
        "refresh_tokens",
        {"token": token, "user_id": "noone", "created_at": past.isoformat(sep=" "), "expires_at": past.isoformat(sep=" ")},
        id_field="id",
    )

    # attempt to use expired token
    r = client.post("/api/auth/refresh", json={"refresh_token": token})
    # some test environments may validate body differently (form vs json) — try form-encoded fallback
    if r.status_code == 422:
        r = client.post("/api/auth/refresh", data={"refresh_token": token})
    assert r.status_code == 401, r.text