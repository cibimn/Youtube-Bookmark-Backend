from fastapi.testclient import TestClient
from main import app  # Adjust this import based on the location of your FastAPI app

client = TestClient(app)

def test_create_user():
    response = client.post(
        "/v1/register",
        json={"username": "newuser", "email": "newuser@example.com", "password": "yourpassword"}
    )
    assert response.status_code == 201
    assert "username" in response.json()
    assert response.json()["username"] == "newuser"

def test_login_user():
    # Assuming the user 'newuser' was successfully created in the previous test
    response = client.post(
        "/v1/login",
        json={"username": "newuser", "password": "yourpassword"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "Login successful"

def test_reset_password():
    # This test might need adjustments based on your password reset logic
    response = client.post(
        "/v1/reset-password",
        json={"email": "newuser@example.com"}
    )
    assert response.status_code == 200
    assert "message" in response.json()
    assert "Password reset link sent" in response.json()["message"]
