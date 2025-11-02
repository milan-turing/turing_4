import pytest
from datetime import datetime, timedelta

from app import database as app_database


def test_revoke_access_token(client, temp_user):
    """Test revoking an access token makes it unusable."""
    # get access token
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    access_token = token_data["access_token"]

    # token should work initially
    headers = {"Authorization": f"Bearer {access_token}"}
    # assuming there's a protected endpoint that validates tokens
    # for this test, we'll just verify the token isn't blacklisted yet

    # revoke the token
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": access_token, "token_type": "access"}
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["message"] == "Token revoked successfully"

    # verify token is now blacklisted by checking the database
    db = app_database.db
    blacklist_record = db.get_record("blacklisted_tokens", "token", access_token)
    assert blacklist_record is not None
    assert blacklist_record["token_type"] == "access"


def test_revoke_refresh_token(client, temp_user):
    """Test revoking a refresh token removes it from active tokens and blacklists it."""
    # get tokens
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    refresh_token = token_data["refresh_token"]

    # verify refresh token exists in database
    db = app_database.db
    refresh_record = db.get_record("refresh_tokens", "token", refresh_token)
    assert refresh_record is not None

    # revoke the refresh token
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": refresh_token, "token_type": "refresh"}
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["message"] == "Token revoked successfully"

    # verify token is removed from refresh_tokens table
    refresh_record_after = db.get_record("refresh_tokens", "token", refresh_token)
    assert refresh_record_after is None

    # verify token is blacklisted
    blacklist_record = db.get_record("blacklisted_tokens", "token", refresh_token)
    assert blacklist_record is not None
    assert blacklist_record["token_type"] == "refresh"

    # verify revoked refresh token cannot be used
    refresh_resp = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 401


def test_revoke_invalid_token(client):
    """Test revoking an invalid token returns appropriate error."""
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": "invalid_token", "token_type": "access"}
    )
    assert revoke_resp.status_code == 400
    assert "Invalid token format" in revoke_resp.json()["detail"]


def test_revoke_already_revoked_token(client, temp_user):
    """Test revoking an already revoked token returns appropriate error."""
    # get access token
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    access_token = token_data["access_token"]

    # revoke the token first time
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": access_token, "token_type": "access"}
    )
    assert revoke_resp.status_code == 200

    # try to revoke again
    revoke_resp2 = client.post(
        "/api/auth/revoke", json={"token": access_token, "token_type": "access"}
    )
    assert revoke_resp2.status_code == 400
    assert "already revoked" in revoke_resp2.json()["detail"]


def test_revoke_nonexistent_refresh_token(client):
    """Test revoking a nonexistent refresh token returns appropriate error."""
    revoke_resp = client.post(
        "/api/auth/revoke",
        json={"token": "nonexistent_refresh_token", "token_type": "refresh"},
    )
    assert revoke_resp.status_code == 400
    assert "Invalid refresh token" in revoke_resp.json()["detail"]


def test_revoke_token_missing_token(client):
    """Test revoke endpoint with missing token field."""
    revoke_resp = client.post("/api/auth/revoke", json={"token_type": "access"})
    assert revoke_resp.status_code == 422  # validation error


def test_revoke_token_invalid_type(client, temp_user):
    """Test revoke endpoint with invalid token_type."""
    # get access token
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    access_token = token_data["access_token"]

    # try to revoke with invalid token_type
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": access_token, "token_type": "invalid"}
    )
    assert revoke_resp.status_code == 400
    assert "Invalid token_type" in revoke_resp.json()["detail"]


def test_revoke_all_tokens(client, temp_user):
    """Test revoking all refresh tokens for a user."""
    # get multiple tokens (simulate multiple logins)
    resp1 = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp1.status_code == 200
    token_data1 = resp1.json()
    access_token1 = token_data1["access_token"]
    refresh_token1 = token_data1["refresh_token"]

    resp2 = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp2.status_code == 200
    token_data2 = resp2.json()
    refresh_token2 = token_data2["refresh_token"]

    # verify both refresh tokens exist
    db = app_database.db
    assert db.get_record("refresh_tokens", "token", refresh_token1) is not None
    assert db.get_record("refresh_tokens", "token", refresh_token2) is not None

    # revoke all tokens using first access token
    headers = {"Authorization": f"Bearer {access_token1}"}
    revoke_all_resp = client.post("/api/auth/revoke-all", headers=headers)
    assert revoke_all_resp.status_code == 200
    assert "Revoked" in revoke_all_resp.json()["message"]

    # verify both refresh tokens are blacklisted and removed
    assert db.get_record("refresh_tokens", "token", refresh_token1) is None
    assert db.get_record("refresh_tokens", "token", refresh_token2) is None
    assert db.get_record("blacklisted_tokens", "token", refresh_token1) is not None
    assert db.get_record("blacklisted_tokens", "token", refresh_token2) is not None


def test_revoke_all_tokens_no_auth(client):
    """Test revoke-all endpoint without authorization header."""
    revoke_all_resp = client.post("/api/auth/revoke-all")
    assert revoke_all_resp.status_code == 401
    assert "Authorization header required" in revoke_all_resp.json()["detail"]


def test_revoke_all_tokens_invalid_auth(client):
    """Test revoke-all endpoint with invalid authorization token."""
    headers = {"Authorization": "Bearer invalid_token"}
    revoke_all_resp = client.post("/api/auth/revoke-all", headers=headers)
    assert revoke_all_resp.status_code == 401
    assert "Invalid token" in revoke_all_resp.json()["detail"]


def test_revoke_all_tokens_with_revoked_token(client, temp_user):
    """Test revoke-all endpoint using a revoked access token."""
    # get access token
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    access_token = token_data["access_token"]

    # revoke the access token
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": access_token, "token_type": "access"}
    )
    assert revoke_resp.status_code == 200

    # try to use revoked token for revoke-all
    headers = {"Authorization": f"Bearer {access_token}"}
    revoke_all_resp = client.post("/api/auth/revoke-all", headers=headers)
    assert revoke_all_resp.status_code == 401
    assert "Token has been revoked" in revoke_all_resp.json()["detail"]


def test_blacklisted_token_cleanup(client):
    """Test that expired blacklist entries are cleaned up."""
    db = app_database.db

    # create an expired blacklist entry directly
    expired_token = "expired_blacklisted_token"
    past_time = datetime.utcnow() - timedelta(days=1)
    db.create_record(
        "blacklisted_tokens",
        {
            "token": expired_token,
            "token_type": "access",
            "user_id": "test_user",
            "blacklisted_at": past_time.isoformat(sep=" "),
            "expires_at": past_time.isoformat(sep=" "),
        },
        id_field="id",
    )

    # verify entry exists
    assert db.get_record("blacklisted_tokens", "token", expired_token) is not None

    # import the function to test cleanup
    from app.api.routes.auth import _is_token_blacklisted

    # check if token is blacklisted (should trigger cleanup)
    is_blacklisted = _is_token_blacklisted(db, expired_token)
    assert is_blacklisted == False  # should return False and clean up

    # verify entry is removed
    assert db.get_record("blacklisted_tokens", "token", expired_token) is None


def test_refresh_with_blacklisted_token(client, temp_user):
    """Test that refresh endpoint rejects blacklisted refresh tokens."""
    # get tokens
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    refresh_token = token_data["refresh_token"]

    # revoke the refresh token
    revoke_resp = client.post(
        "/api/auth/revoke", json={"token": refresh_token, "token_type": "refresh"}
    )
    assert revoke_resp.status_code == 200

    # try to use the revoked refresh token
    refresh_resp = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 401
    assert "Token has been revoked" in refresh_resp.json()["detail"]


def test_token_revocation_default_type(client, temp_user):
    """Test that token revocation defaults to access token type."""
    # get access token
    resp = client.post(
        "/api/auth/token",
        data={"username": temp_user["username"], "password": temp_user["password"]},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    access_token = token_data["access_token"]

    # revoke without specifying token_type (should default to access)
    revoke_resp = client.post("/api/auth/revoke", json={"token": access_token})
    assert revoke_resp.status_code == 200

    # verify it was treated as access token
    db = app_database.db
    blacklist_record = db.get_record("blacklisted_tokens", "token", access_token)
    assert blacklist_record is not None
    assert blacklist_record["token_type"] == "access"


def test_revoke_refresh_token_prevents_refresh(client):
    # register and get initial tokens
    payload = {"username": "revoker", "email": "revoker@example.com", "password": "pwrev"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 200, r.text

    r2 = client.post("/api/auth/token", data={"username": "revoker", "password": "pwrev"})
    assert r2.status_code == 200, r2.text
    td = r2.json()
    old_refresh = td.get("refresh_token")
    assert old_refresh

    # revoke the refresh token
    rr = client.post("/api/auth/revoke", json={"refresh_token": old_refresh})
    assert rr.status_code == 200, rr.text
    jr = rr.json()
    assert jr.get("revoked", {}).get("refresh_token") is True

    # attempt to use revoked refresh token
    r3 = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    # some environments may parse differently (form vs json); try form fallback
    if r3.status_code == 422:
        r3 = client.post("/api/auth/refresh", data={"refresh_token": old_refresh})
    assert r3.status_code == 401


def test_revoke_access_token_blacklists_token(client):
    # register and get token
    payload = {"username": "blacklister", "email": "blacklister@example.com", "password": "pwblack"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 200, r.text

    r2 = client.post("/api/auth/token", data={"username": "blacklister", "password": "pwblack"})
    assert r2.status_code == 200, r2.text
    td = r2.json()
    access = td.get("access_token")
    assert access

    # calling protected endpoint with token works
    resp_ok = client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert resp_ok.status_code == 200

    # revoke access token
    rr = client.post("/api/auth/revoke", json={"access_token": access})
    assert rr.status_code == 200, rr.text
    jr = rr.json()
    assert jr.get("revoked", {}).get("access_token") is True

    # subsequent calls with same token should be rejected
    resp_bad = client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert resp_bad.status_code == 401