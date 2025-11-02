# tests/test_password_reset.py
import pytest
from datetime import datetime, timedelta

from app import database as app_database


def test_password_reset_request_and_confirm(client, temp_user):
    # request password reset by email
    resp = client.post("/api/auth/password-reset/request", json={"email": temp_user["email"]})
    assert resp.status_code == 200

    # find the reset token in DB
    row = app_database.db.get_record("password_reset_tokens", "user_id", str(temp_user["row"]["id"]))
    assert row is not None, "password reset token row should exist"
    token = row.get("token")
    assert token

    # confirm reset with new password
    new_password = "new_password_123"
    resp2 = client.post("/api/auth/password-reset/confirm", json={"token": token, "password": new_password})
    assert resp2.status_code == 200

    # old password should no longer work; new password should produce a token
    r = client.post("/api/auth/token", data={"username": temp_user["username"], "password": new_password})
    assert r.status_code == 200
    data = r.json()
    assert data.get("access_token")


def test_password_reset_token_expired_or_invalid(client, temp_user):
    # request new token
    resp = client.post("/api/auth/password-reset/request", json={"email": temp_user["email"]})
    assert resp.status_code == 200

    row = app_database.db.get_record("password_reset_tokens", "user_id", str(temp_user["row"]["id"]))
    assert row is not None
    token = row.get("token")
    assert token

    # expire the token by replacing the record with a past expires_at (best-effort)
    past = (datetime.utcnow() - timedelta(minutes=10)).isoformat(sep=" ")
    try:
        # remove existing and recreate with expired timestamp
        app_database.db.delete_record("password_reset_tokens", "token", token)
    except Exception:
        pass
    app_database.db.create_record(
        "password_reset_tokens",
        {"token": token, "user_id": str(temp_user["row"]["id"]), "created_at": past, "expires_at": past},
        id_field="id",
    )

    # confirm should fail due to expiry
    resp2 = client.post("/api/auth/password-reset/confirm", json={"token": token, "password": "whatever"})
    assert resp2.status_code == 401

    # invalid token should also fail
    resp3 = client.post("/api/auth/password-reset/confirm", json={"token": "no-such-token", "password": "x"})
    assert resp3.status_code == 401