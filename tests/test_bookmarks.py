from fastapi.testclient import TestClient
from main import app  # Adjust this import based on the location of your FastAPI app

client = TestClient(app)

def get_user_token():
    # Replace with your actual login details or token retrieval logic
    test_username = "testuser"
    test_password = "testpassword"
    response = client.post(
        "/v1/login",
        json={"username": test_username, "password": test_password}
    )
    return response.json()["access_token"]

def test_create_bookmark():
    token = get_user_token()
    response = client.post(
        "/v1/bookmark/create",
        headers={"Authorization": f"Bearer {token}"},
        json={"url": "https://example.com"}
    )
    assert response.status_code == 201
    assert "message" in response.json()
    assert response.json()["message"] == "bookmark added successfully"

def test_edit_bookmark():
    token = get_user_token()
    bookmark_id = 1  # Replace with a valid bookmark ID for the test
    response = client.put(
        f"/v1/bookmark/edit/{bookmark_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"url": "https://updatedexample.com"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "Bookmark updated successfully"

def test_delete_bookmark():
    token = get_user_token()
    bookmark_id = 1  # Replace with a valid bookmark ID for the test
    response = client.delete(
        f"/v1/bookmark/delete/{bookmark_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "Bookmark deleted successfully"
