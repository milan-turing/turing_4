import uuid

from app.database import db as file_db


def test_add_and_list_wishlist(temp_user, client, auth_header):
    # temp_user fixture yields {"username","password","email","row"}
    user_row = temp_user["row"]
    user_id = user_row["id"]

    # create a product
    product = file_db.create_record(
        "products",
        {"name": "Test Lamp", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "19.99"},
        id_field="id",
    )
    product_id = product["id"]

    # add to wishlist
    resp = client.post("/api/wishlist", json={"product_id": product_id}, headers=auth_header(user_id))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["user_id"] == user_id
    assert created["product_id"] == product_id
    assert "id" in created

    # list wishlist for this user
    resp = client.get("/api/wishlist", headers=auth_header(user_id))
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert any(item.get("id") == created["id"] for item in items)


def test_add_nonexistent_product_returns_404(temp_user, client, auth_header):
    user_id = temp_user["row"]["id"]
    resp = client.post("/api/wishlist", json={"product_id": "nonexistent-id"}, headers=auth_header(user_id))
    assert resp.status_code == 404


def test_delete_wishlist_item_and_permissions(temp_user, client, auth_header):
    user1 = temp_user["row"]
    user1_id = user1["id"]

    # create another user (user2)
    other = file_db.create_record(
        "users",
        {"username": f"u2_{uuid.uuid4().hex[:6]}", "email": f"u2@example.com"},
        id_field="id",
    )
    user2_id = other["id"]

    # create product
    product = file_db.create_record(
        "products",
        {"name": "Decor Vase", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "29.99"},
        id_field="id",
    )
    product_id = product["id"]

    # user1 adds an item
    resp = client.post("/api/wishlist", json={"product_id": product_id}, headers=auth_header(user1_id))
    assert resp.status_code == 201, resp.text
    item = resp.json()
    item_id = item["id"]

    # user2 attempts to delete -> forbidden
    resp = client.delete(f"/api/wishlist/{item_id}", headers=auth_header(user2_id))
    assert resp.status_code == 403

    # user1 deletes -> success (204)
    resp = client.delete(f"/api/wishlist/{item_id}", headers=auth_header(user1_id))
    assert resp.status_code == 204

    # ensure item no longer listed
    resp = client.get("/api/wishlist", headers=auth_header(user1_id))
    assert resp.status_code == 200
    assert not any(i.get("id") == item_id for i in resp.json())