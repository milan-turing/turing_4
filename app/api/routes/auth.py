# app/api/routes/auth.py
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Form, Body
from fastapi.security import OAuth2PasswordRequestForm
from app.core.security import hash_password, verify_password
from jose import jwt

import os
import secrets

from app.api.deps import get_db, JWT_SECRET, JWT_ALGORITHM
from app.api.schemas.user import TokenResponse, UserOut
from app.database import FileBackedDB

router = APIRouter(prefix="/api/auth", tags=["auth"])

# token lifetime (minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
# refresh token lifetime (minutes) - configurable
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", str(60 * 24 * 30)))  # default 30 days


def _create_access_token(subject: str, expires_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = {"sub": subject, "exp": datetime.utcnow() + timedelta(minutes=expires_delta)}
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def _create_refresh_token_record(db: FileBackedDB, user_id: str, expires_delta_minutes: int = REFRESH_TOKEN_EXPIRE_MINUTES) -> str:
    """
    Create a server-side refresh token record. Returns the raw token string.
    Stored fields: token, user_id, created_at (ISO), expires_at (ISO)
    """
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=expires_delta_minutes)
    # store timestamps as ISO strings (file-backed DB is string-oriented)
    db.create_record(
        "refresh_tokens",
        {
            "token": token,
            "user_id": str(user_id),
            "created_at": now.isoformat(sep=" "),
            "expires_at": expires_at.isoformat(sep=" "),
        },
        id_field="id",
    )
    return token


def _get_refresh_record(db: FileBackedDB, token: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a refresh token record by token. Returns the row dict or None.
    """
    try:
        return db.get_record("refresh_tokens", "token", token)
    except Exception:
        return None


def _is_refresh_expired(row: Dict[str, Any]) -> bool:
    expires_at = row.get("expires_at") or row.get("expiry") or row.get("expires")
    if not expires_at:
        return True
    try:
        # parse common ISO form used above
        exp_dt = datetime.fromisoformat(str(expires_at))
    except Exception:
        try:
            exp_dt = datetime.strptime(str(expires_at), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return True
    return datetime.utcnow() > exp_dt


@router.post("/token", response_model=TokenResponse)
def token(form_data: OAuth2PasswordRequestForm = Depends(), db: FileBackedDB = Depends(get_db)):
    """
    Token endpoint used by OAuth2PasswordRequestForm clients.
    Returns a signed JWT and a refresh token (server-side stored).
    """
    # lookup user by username (form_data.username)
    user = db.get_record("users", "username", form_data.username) or db.get_record("users", "email", form_data.username) or db.get_record("users", "id", form_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    stored_hash = user.get("password_hash") or user.get("hashed_password")
    if not stored_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        if not verify_password(form_data.password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except Exception:
        # treat verification errors as invalid credentials
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    subject = str(user.get("id") or user.get("username") or user.get("email"))
    access_token = _create_access_token(subject=subject)
    # create and persist refresh token
    try:
        refresh_token = _create_refresh_token_record(db, subject)
    except Exception:
        refresh_token = None
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}


@router.post("/login")
def login_form(response: Response, username: str = Form(...), password: str = Form(...), db: FileBackedDB = Depends(get_db)):
    """
    Simple form login used by UI tests: sets an 'access_token' cookie and a 'refresh_token' cookie.
    """
    user = db.get_record("users", "username", username) or db.get_record("users", "email", username) or db.get_record("users", "id", username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    stored_hash = user.get("password_hash") or user.get("hashed_password")
    if not stored_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        if not verify_password(password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    subject = str(user.get("id") or user.get("username") or user.get("email"))
    access_token = _create_access_token(subject=subject)
    # set cookie for browser-style flows (tests expect this)
    response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax")
    # create refresh token and set cookie
    try:
        refresh_token = _create_refresh_token_record(db, subject)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, samesite="lax")
    except Exception:
        refresh_token = None
    # return user-shaped payload (consistent with register)
    user_out = {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "full_name": user.get("full_name"),
        "is_admin": bool(user.get("is_admin", False)),
    }
    # tests/clients may expect json user object; include refresh_token if needed separately
    user_out["refresh_token"] = refresh_token
    return user_out


# alias expected by tests
@router.post("/login-form")
def login_form_alias(response: Response, username: str = Form(...), password: str = Form(...), db: FileBackedDB = Depends(get_db)):
    return login_form(response=response, username=username, password=password, db=db)


@router.post("/register", response_model=UserOut, status_code=200)
def register(user: Dict[str, Any], db: FileBackedDB = Depends(get_db)):
    """
    Minimal register endpoint (used occasionally by tests). Expects a dict with username/email/password.
    Hashes the password and stores as 'password_hash'.
    """
    username = user.get("username")
    email = user.get("email")
    password = user.get("password")
    if not username or not password or not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username, email and password required")
    hashed = hash_password(password)
    row = db.create_record("users", {"username": username, "email": email, "password_hash": hashed, "is_admin": user.get("is_admin", False), "full_name": user.get("full_name")}, id_field="id")
    # build a deterministic user output shape expected by tests/schemas
    user_out = {
        "id": row.get("id"),
        "username": row.get("username"),
        "email": row.get("email"),
        "full_name": row.get("full_name"),
        "is_admin": bool(row.get("is_admin", False)),
    }
    return user_out


@router.post("/refresh", response_model=TokenResponse)
async def refresh(response: Response, request: Request, db: FileBackedDB = Depends(get_db)):
    """
    Rotate / refresh tokens.

    Accepts:
      - JSON body { "refresh_token": "<token>" }
      - form-encoded body (refresh_token field)
      - cookie 'refresh_token'

    If a valid, non-expired refresh record is found the old token is deleted (rotation)
    and a new access token and refresh token are returned. This handler is tolerant of
    empty JSON bodies ({}), which would otherwise validate as the wrong type.
    """
    # try JSON body first (safe parse)
    token = None
    try:
        content_type = (request.headers.get("content-type") or "").lower()
        if content_type.startswith("application/json"):
            body = await request.json()
            if isinstance(body, dict):
                token = body.get("refresh_token")
    except Exception:
        # ignore JSON parse errors and continue to other fallbacks
        token = token

    # try form-encoded body fallback
    if not token:
        try:
            form = await request.form()
            if hasattr(form, "get"):
                token = form.get("refresh_token") or token
        except Exception:
            pass

    # cookie fallback
    if not token:
        token = request.cookies.get("refresh_token")

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")

    row = _get_refresh_record(db, token)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if _is_refresh_expired(row):
        # cleanup expired token if possible
        try:
            db.delete_record("refresh_tokens", "token", token)
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    user_id = row.get("user_id") or row.get("uid") or row.get("user")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token owner")

    # delete old token (rotate) if supported
    try:
        db.delete_record("refresh_tokens", "token", token)
    except Exception:
        # if delete not supported, ignore - token will expire eventually
        pass

    # create new tokens
    access_token = _create_access_token(subject=str(user_id))
    try:
        new_refresh = _create_refresh_token_record(db, str(user_id))
        # set cookie for browser flows
        response.set_cookie(key="refresh_token", value=new_refresh, httponly=True, samesite="lax")
        response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax")
    except Exception:
        new_refresh = None

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": new_refresh}