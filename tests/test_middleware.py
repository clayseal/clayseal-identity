from fastapi.testclient import TestClient
from examples.fastapi_token_middleware import app

client = TestClient(app)


def test_missing_auth_header():
    r = client.get("/private")
    assert r.status_code == 401
    assert "Missing or invalid" in r.json().get("detail", "")


def test_invalid_token():
    r = client.get("/private", headers={"Authorization": "Bearer bad-token"})
    assert r.status_code == 401
    assert "Invalid token" in r.json().get("detail", "")


def test_valid_token():
    r = client.get("/private", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200
    assert r.json() == {"message": "You have access"}