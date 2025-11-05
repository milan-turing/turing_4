import uuid

from app.database import db as file_db


def test_move_wishlist_item_to_cart_success(temp_user, client, auth_header):
    user = temp_user["row"]
    user_id = user["id"]

    product = file_db.create_record(
        "products",
        {"name": "Movable Lamp", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "25.00"},
        id_field="id",
    )
    product_id = product["id"]

    # create wishlist item directly in DB
    wish = file_db.create_record(
        "wishlists",
        {"user_id": user_id, "product_id": product_id, "added_at": "now"},
        id_field="id",
    )
    wish_id = wish["id"]

    resp = client.post(f"/api/wishlist/{wish_id}/move-to-cart", headers=auth_header(user_id))
    assert resp.status_code == 201, resp.text
    cart_item = resp.json()
    assert cart_item["user_id"] == user_id
    assert cart_item["product_id"] == product_id
    assert "id" in cart_item

    # wishlist item should be gone
    assert file_db.get_record("wishlists", "id", wish_id) is None


def test_move_nonexistent_wishlist_item_returns_404(temp_user, client, auth_header):
    user_id = temp_user["row"]["id"]
    resp = client.post(f"/api/wishlist/nonexistent-id/move-to-cart", headers=auth_header(user_id))
    assert resp.status_code == 404


def test_move_other_users_wishlist_item_forbidden(temp_user, client, auth_header):
    user1 = temp_user["row"]
    user1_id = user1["id"]

    # create second user
    other = file_db.create_record(
        "users",
        {"username": f"u2_{uuid.uuid4().hex[:6]}", "email": f"u2@example.com"},
        id_field="id",
    )
    user2_id = other["id"]

    product = file_db.create_record(
        "products",
        {"name": "Another Product", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "12.00"},
        id_field="id",
    )
    product_id = product["id"]

    # wishlist owned by user1
    wish = file_db.create_record(
        "wishlists",
        {"user_id": user1_id, "product_id": product_id},
        id_field="id",
    )
    wish_id = wish["id"]

    # user2 attempts to move it
    resp = client.post(f"/api/wishlist/{wish_id}/move-to-cart", headers=auth_header(user2_id))
    assert resp.status_code == 403