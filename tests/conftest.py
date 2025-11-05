# tests/conftest.py
import os
import sys
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import io
from PIL import Image

import pytest
from fastapi.testclient import TestClient

# ensure project root is importable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# create a dedicated temp data dir at import time so all imports (app/database/app.main)
# pick up the test DATA_DIR before they are imported by tests
_tmp_data_dir = tempfile.mkdtemp(prefix="test_data_")
from app import config as app_config  # keep after tmpdir creation
_orig_settings_data_dir = app_config.settings.DATA_DIR
app_config.settings.DATA_DIR = Path(_tmp_data_dir)

# import database module after overriding settings so it initializes against tmp dir
from app import database as app_database
# ensure module-level DATA_DIR aligns
app_database.DATA_DIR = Path(_tmp_data_dir)
app_database.DATA_DIR.mkdir(parents=True, exist_ok=True)

# now import the FastAPI app
from app.main import app  # noqa: E402

from app.core.security import hash_password


@pytest.fixture(autouse=True)
def temp_data_dir():
    """
    Ensures tests run against an isolated temp data directory.
    Restores original settings and removes temp dir after test session.
    """
    try:
        yield Path(_tmp_data_dir)
    finally:
        # restore original setting
        app_config.settings.DATA_DIR = _orig_settings_data_dir
        # cleanup tmp dir
        try:
            shutil.rmtree(_tmp_data_dir)
        except Exception:
            pass


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_header():
    """
    Helper that returns a callable to build Authorization header from a token or user id.
    Usage: hdr = auth_header(user_or_token)
    """
    def _h(tok: str):
        return {"Authorization": f"Bearer {tok}"}
    return _h


@pytest.fixture
def register_and_token(client):
    """
    Register a user via the API and return the access token.
    Usage: token = register_and_token(username="u", email=None, password="pw")
    """
    def _fn(username="user", email=None, password="pass123"):
        if email is None:
            email = f"{username}@example.com"
        r = client.post("/api/auth/register", json={"username": username, "email": email, "password": password})
        assert r.status_code in (200, 201), r.text
        r2 = client.post("/api/auth/token", data={"username": username, "password": password})
        assert r2.status_code == 200, r2.text
        return r2.json().get("access_token")
    return _fn


@pytest.fixture
def token_for(client):
    """
    Obtain an OAuth token for an existing username/password.
    Usage: token = token_for(username, password)
    """
    def _fn(username: str, password: str):
        resp = client.post("/api/auth/token", data={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        return resp.json().get("access_token")
    return _fn


@pytest.fixture
def admin_auth_header(client):
    """
    Create admin in DB (if not present) and return an Authorization header for admin.
    Usage: hdr = admin_auth_header(username="admin", password="adminpass")
    """
    def _fn(username="admin", password="adminpass", email="admin@example.com"):
        # create admin row if missing
        create_admin_in_db(username=username, password=password, email=email)
        resp = client.post("/api/auth/token", data={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        token = resp.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}
    return _fn


@pytest.fixture
def make_sample_jpeg_bytes():
    """
    Return a callable that generates JPEG bytes for tests that need image uploads.
    Usage: jpg = make_sample_jpeg_bytes(size=(200,200))
    """
    def _fn(size=(200, 200), color=(180, 120, 60)):
        bio = io.BytesIO()
        im = Image.new("RGB", size, color)
        im.save(bio, format="JPEG", quality=85)
        bio.seek(0)
        return bio.read()
    return _fn


def create_admin_in_db(username="admin", password="adminpass", email="admin@example.com"):
    """
    Utility to create an admin user in the file-backed DB.
    Returns the created row dict.
    """
    hashed = hash_password(password)
    row = app_database.db.create_record(
        "users",
        {"username": username, "email": email, "password_hash": hashed, "is_admin": True},
        id_field="id",
    )
    return row


@pytest.fixture
def seeded_admin():
    return create_admin_in_db()


@pytest.fixture
def temp_user():
    """
    Create a temporary non-admin user and yield its details.
    Returns {"row": <user_row>, "password": <plain_password>, "username": ..., "email": ...}
    """
    password = "testpass"
    hashed = hash_password(password)
    user = app_database.db.create_record(
        "users",
        {"username": f"user_{os.urandom(4).hex()}", "email": f"user_{os.urandom(4).hex()}@example.com", "password_hash": hashed, "is_admin": False},
        id_field="id",
    )
    yield {"row": user, "password": password, "username": user.get("username"), "email": user.get("email")}