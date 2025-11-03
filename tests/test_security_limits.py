import os
import json
import pytest

def make_large_string(n):
    return "x" * n

def test_large_json_payload_rejected(client):
    # create a JSON body larger than the default 2KB limit
    large = {"username": "u", "email": "e@x.com", "password": make_large_string(3 * 1024)}
    resp = client.post("/api/auth/register", json=large)
    assert resp.status_code == 413
    assert "Payload too large" in resp.json().get("detail", "") or "Payload too large" in json.dumps(resp.json())

def test_too_many_query_params_rejected(client):
    # craft URL with many query params (exceeds default 20)
    q = "&".join(f"p{i}=1" for i in range(30))
    resp = client.post(f"/api/auth/refresh?{q}", json={})
    assert resp.status_code == 400
    assert "Too many query parameters" in resp.json().get("detail", "")

def test_too_many_form_fields_rejected(client):
    # send many urlencoded form fields to token endpoint
    data = {f"f{i}": "v" for i in range(300)}
    # oauth token endpoint expects username/password; we just want to hit middleware
    resp = client.post("/api/auth/token", data=data)
    # middleware should reject before route handling
    assert resp.status_code in (400, 413)
    assert any(s in resp.json().get("detail", "") for s in ("Too many form fields", "Payload too large", "Too many form fields (multipart)"))