# tests/test_image_validation.py
import io
from pathlib import Path
from fastapi import status

def make_sample_jpeg_bytes(size=(200, 200), color=(180, 120, 60)):
    import io
    from PIL import Image
    bio = io.BytesIO()
    im = Image.new("RGB", size, color)
    im.save(bio, format="JPEG", quality=85)
    bio.seek(0)
    return bio.read()

def create_product_as_admin(client, admin_header, title="ImgValTest", price=10.0):
    payload = {
        "title": title,
        "description": "validation test product",
        "category": "test",
        "price": price,
        "stock": 1,
    }
    resp = client.post("/api/products/", json=payload, headers=admin_header)
    assert resp.status_code == 200, resp.text
    return resp.json()

def get_admin_header(client):
    # ensure admin exists and obtain token
    client.post("/api/auth/register", json={"username": "admin", "email": "admin@example.com", "password": "adminpass"})
    resp = client.post("/api/auth/token", data={"username": "admin", "password": "adminpass"})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_reject_non_image_content_type(client, seeded_admin):
    admin_header = get_admin_header(client)
    product = create_product_as_admin(client, admin_header)
    pid = product["id"]

    jpg_bytes = make_sample_jpeg_bytes()
    # send with wrong content-type
    files = {"file": ("test.jpg", io.BytesIO(jpg_bytes), "text/plain")}
    resp = client.post(f"/api/products/{pid}/upload-image", files=files, headers=admin_header)
    assert resp.status_code == 400, resp.text
    assert "Unsupported content" in resp.json().get("detail", "") or "Unsupported content type" in resp.json().get("detail", "")

def test_reject_bad_extension(client, seeded_admin):
    admin_header = get_admin_header(client)
    product = create_product_as_admin(client, admin_header)
    pid = product["id"]

    jpg_bytes = make_sample_jpeg_bytes()
    # correct content-type but bad extension
    files = {"file": ("test.txt", io.BytesIO(jpg_bytes), "image/jpeg")}
    resp = client.post(f"/api/products/{pid}/upload-image", files=files, headers=admin_header)
    assert resp.status_code == 400, resp.text
    assert "Unsupported file extension" in resp.json().get("detail", "")

def test_reject_malicious_filename(client, seeded_admin):
    admin_header = get_admin_header(client)
    product = create_product_as_admin(client, admin_header)
    pid = product["id"]

    jpg_bytes = make_sample_jpeg_bytes()
    # filename tries path traversal
    files = {"file": ("../evil.jpg", io.BytesIO(jpg_bytes), "image/jpeg")}
    resp = client.post(f"/api/products/{pid}/upload-image", files=files, headers=admin_header)
    assert resp.status_code == 400, resp.text
    assert "Invalid filename" in resp.json().get("detail", "")