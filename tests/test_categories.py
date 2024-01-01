from fastapi.testclient import TestClient
from main import app  # Adjust this import based on the location of your FastAPI app

client = TestClient(app)

def get_user_token():
    test_username = "testuser"
    test_password = "testpassword"

    response = client.post(
        "/v1/login",
        json={"username": test_username, "password": test_password}
    )

    # Check if the response is successful and contains a token
    if response.status_code == 200 and "access_token" in response.json():
        return response.json()["access_token"]
    else:
        raise Exception("Failed to obtain test user token")

def test_create_category():
    token = get_user_token()
    response = client.post(
        "/v1/categories/create",
        headers={"Authorization": f"Bearer {token}"},
        json={"category": "New Category"}
    )
    assert response.status_code == 201
    assert "message" in response.json()
    assert response.json()["message"] == "Category created successfully"

def test_list_categories():
    token = get_user_token()
    response = client.get(
        "/v1/categories/",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_edit_category():
    token = get_user_token()
    category_id = 1  # Replace with a valid category ID
    response = client.put(
        f"/v1/categories/edit/{category_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"category": "Updated Category"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "Category updated successfully"

def test_delete_category():
    token = get_user_token()
    category_id = 1  # Replace with a valid category ID
    response = client.delete(
        f"/v1/categories/delete/{category_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "Category deleted successfully"
