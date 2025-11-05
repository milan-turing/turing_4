import pytest
from app.database import db as file_db
from fastapi.testclient import TestClient


def register_and_token(client: TestClient, username="res_user", email=None, password="pass123"):
    if email is None:
        email = f"{username}@example.com"
    r = client.post("/api/auth/register", json={"username": username, "email": email, "password": password})
    assert r.status_code in (200, 201), r.text
    r2 = client.post("/api/auth/token", data={"username": username, "password": password})
    assert r2.status_code == 200, r2.text
    return r2.json().get("access_token")


def test_reserve_decrements_stock(client: TestClient, seeded_admin):
    prod = file_db.create_record("products", {"title": "ResChair", "price": 100.0, "stock": 5}, id_field="id")
    pid = prod["id"]

    token = register_and_token(client, username="res_user1")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/orders/", json={"items": [{"product_id": pid, "unit_price": 100.0, "quantity": 2}]}, headers=headers)
    assert resp.status_code == 201, resp.text

    p = file_db.get_record("products", "id", pid)
    assert int(float(p.get("stock", 0))) == 3


def test_insufficient_stock_returns_400_and_no_change(client: TestClient, seeded_admin):
    prod = file_db.create_record("products", {"title": "LowStock", "price": 20.0, "stock": 1}, id_field="id")
    pid = prod["id"]

    token = register_and_token(client, username="res_user2")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/orders/", json={"items": [{"product_id": pid, "unit_price": 20.0, "quantity": 2}]}, headers=headers)
    assert resp.status_code == 400, resp.text

    p = file_db.get_record("products", "id", pid)
    assert int(float(p.get("stock", 0))) == 1


def test_reservation_rolls_back_on_persist_failure(client: TestClient, seeded_admin, monkeypatch):
    prod = file_db.create_record("products", {"title": "RollbackChair", "price": 75.0, "stock": 2}, id_field="id")
    pid = prod["id"]

    token = register_and_token(client, username="res_user3")
    headers = {"Authorization": f"Bearer {token}"}

    orig_create = file_db.create_record

    def fake_create(table, record, id_field="id"):
        # simulate persist failure for orders only
        if table == "orders":
            return None
        return orig_create(table, record, id_field=id_field)

    monkeypatch.setattr(file_db, "create_record", fake_create)

    resp = client.post("/api/orders/", json={"items": [{"product_id": pid, "unit_price": 75.0, "quantity": 1}]}, headers=headers)
    # endpoint should return 500 on create failure and stock should be rolled back
    assert resp.status_code == 500, resp.text

    p = file_db.get_record("products", "id", pid)
    assert int(float(p.get("stock", 0))) == 2


def test_multiple_items_reserve_cumulative(client: TestClient, seeded_admin):
    p1 = file_db.create_record("products", {"title": "MultiA", "price": 10.0, "stock": 4}, id_field="id")
    p2 = file_db.create_record("products", {"title": "MultiB", "price": 5.0, "stock": 6}, id_field="id")

    token = register_and_token(client, username="res_user4")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/orders/",
        json={
            "items": [
                {"product_id": p1["id"], "unit_price": 10.0, "quantity": 1},
                {"product_id": p2["id"], "unit_price": 5.0, "quantity": 2},
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text

    a = file_db.get_record("products", "id", p1["id"])
    b = file_db.get_record("products", "id", p2["id"])
    assert int(float(a.get("stock", 0))) == 3
    assert int(float(b.get("stock", 0))) == 4