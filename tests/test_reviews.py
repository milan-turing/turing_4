import uuid

from app.database import db as file_db


def test_create_review_success(temp_user, client, auth_header):
    user = temp_user["row"]
    user_id = user["id"]

    product = file_db.create_record(
        "products",
        {"name": "Reviewable Lamp", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "45.00"},
        id_field="id",
    )
    product_id = product["id"]

    resp = client.post(f"/api/products/{product_id}/reviews", json={"rating": 5, "body": "Great!"}, headers=auth_header(user_id))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["product_id"] == product_id
    assert created["user_id"] == user_id
    assert int(created["rating"]) == 5
    assert "id" in created


def test_create_review_invalid_rating(temp_user, client, auth_header):
    user_id = temp_user["row"]["id"]
    product = file_db.create_record(
        "products",
        {"name": "Bad Rating Product", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "5.00"},
        id_field="id",
    )
    product_id = product["id"]

    resp = client.post(f"/api/products/{product_id}/reviews", json={"rating": 10}, headers=auth_header(user_id))
    assert resp.status_code == 422


def test_list_reviews_returns_all(temp_user, client, auth_header):
    user1 = temp_user["row"]
    user1_id = user1["id"]
    # create another user
    other = file_db.create_record(
        "users",
        {"username": f"u2_{uuid.uuid4().hex[:6]}", "email": f"u2@example.com"},
        id_field="id",
    )
    user2_id = other["id"]

    product = file_db.create_record(
        "products",
        {"name": "Multi Review Product", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "15.00"},
        id_field="id",
    )
    product_id = product["id"]

    r1 = client.post(f"/api/products/{product_id}/reviews", json={"rating": 4}, headers=auth_header(user1_id))
    assert r1.status_code == 201
    r2 = client.post(f"/api/products/{product_id}/reviews", json={"rating": 3}, headers=auth_header(user2_id))
    assert r2.status_code == 201

    resp = client.get(f"/api/products/{product_id}/reviews")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 2
    ratings = [int(x.get("rating")) for x in items if x.get("product_id") == product_id]
    assert 4 in ratings and 3 in ratings


def test_delete_review_permissions(temp_user, client, auth_header):
    user1 = temp_user["row"]
    user1_id = user1["id"]
    other = file_db.create_record(
        "users",
        {"username": f"u2_{uuid.uuid4().hex[:6]}", "email": f"u2@example.com"},
        id_field="id",
    )
    user2_id = other["id"]

    product = file_db.create_record(
        "products",
        {"name": "Delete Test Product", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "9.99"},
        id_field="id",
    )
    product_id = product["id"]

    create_resp = client.post(f"/api/products/{product_id}/reviews", json={"rating": 5}, headers=auth_header(user1_id))
    assert create_resp.status_code == 201
    review = create_resp.json()
    review_id = review["id"]

    # other user attempts delete -> forbidden
    resp = client.delete(f"/api/products/{product_id}/reviews/{review_id}", headers=auth_header(user2_id))
    assert resp.status_code == 403

    # owner deletes -> 204
    resp = client.delete(f"/api/products/{product_id}/reviews/{review_id}", headers=auth_header(user1_id))
    assert resp.status_code == 204

    # ensure removed
    resp = client.get(f"/api/products/{product_id}/reviews")
    assert all(r.get("id") != review_id for r in resp.json())


def test_reviews_summary_average_and_count(temp_user, client, auth_header):
    user1 = temp_user["row"]
    user1_id = user1["id"]

    product = file_db.create_record(
        "products",
        {"name": "Summary Product", "sku": f"sku-{uuid.uuid4().hex[:6]}", "price": "20.00"},
        id_field="id",
    )
    product_id = product["id"]

    client.post(f"/api/products/{product_id}/reviews", json={"rating": 5}, headers=auth_header(user1_id))
    # create second user and review
    other = file_db.create_record(
        "users",
        {"username": f"u2_{uuid.uuid4().hex[:6]}", "email": f"u2@example.com"},
        id_field="id",
    )
    user2_id = other["id"]
    client.post(f"/api/products/{product_id}/reviews", json={"rating": 3}, headers=auth_header(user2_id))

    resp = client.get(f"/api/products/{product_id}/reviews/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    # average of 5 and 3 = 4.0
    assert abs(float(data["average"]) - 4.0) < 0.01