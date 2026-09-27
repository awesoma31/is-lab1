import pytest

from app import create_app, get_db

PASSWORD = "S3cure-passw0rd"


@pytest.fixture
def client(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "test.db"), "TESTING": True})
    with app.test_client() as client:
        client.application = app
        yield client


def register(client, username="alice", password=PASSWORD):
    return client.post("/auth/register", json={"username": username, "password": password})


def login(client, username="alice", password=PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth_header(client):
    register(client)
    token = login(client).get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_register_and_login(client):
    assert register(client).status_code == 201
    resp = login(client)
    assert resp.status_code == 200
    assert resp.get_json()["token_type"] == "Bearer"


def test_duplicate_username(client):
    register(client)
    assert register(client).status_code == 409


def test_weak_input_rejected(client):
    assert register(client, password="short").status_code == 400
    assert register(client, username="<script>").status_code == 400
    assert client.post("/auth/register", data="not json").status_code == 400


def test_wrong_password(client):
    register(client)
    resp = login(client, password="wrong-password")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid username or password"


def test_unknown_user_same_error(client):
    resp = login(client, username="nobody")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid username or password"


def test_password_is_hashed(client):
    register(client)
    with client.application.app_context():
        stored = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert PASSWORD.encode() not in stored
    assert stored.startswith(b"$2b$12$")


@pytest.mark.parametrize("path", ["/api/data", "/api/me"])
def test_protected_without_token(client, path):
    assert client.get(path).status_code == 401


def test_protected_with_bad_token(client):
    resp = client.get("/api/data", headers={"Authorization": "Bearer abc.def.ghi"})
    assert resp.status_code == 401


def test_forged_token_rejected(client):
    import jwt

    forged = jwt.encode({"sub": "1", "type": "access"}, "attacker-controlled-secret-0123456789abcdef", algorithm="HS256")
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_alg_none_rejected(client):
    import jwt

    forged = jwt.encode({"sub": "1", "type": "access"}, None, algorithm="none")
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_data_with_token(client):
    resp = client.get("/api/data", headers=auth_header(client))
    assert resp.status_code == 200
    assert resp.get_json() == {"posts": []}


@pytest.mark.parametrize(
    "payload",
    ["' OR '1'='1", "alice' --", "' UNION SELECT id, password_hash FROM users --"],
)
def test_sql_injection_in_login(client, payload):
    register(client)
    resp = login(client, username=payload, password="anything")
    assert resp.status_code == 401
    resp = login(client, username="alice", password=payload)
    assert resp.status_code == 401


def test_sql_injection_stored_as_text(client):
    headers = auth_header(client)
    payload = "x'); DROP TABLE users; --"
    assert client.post("/api/posts", json={"title": payload, "body": "b"}, headers=headers).status_code == 201
    assert login(client).status_code == 200  # таблица users на месте


def test_xss_is_escaped(client):
    headers = auth_header(client)
    payload = '<script>alert("xss")</script>'
    resp = client.post("/api/posts", json={"title": payload, "body": "<img src=x onerror=alert(1)>"}, headers=headers)
    assert resp.status_code == 201
    post = client.get("/api/data", headers=headers).get_json()["posts"][0]
    assert "<script>" not in post["title"]
    assert post["title"] == "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;"
    assert post["body"] == "&lt;img src=x onerror=alert(1)&gt;"


def test_post_validation(client):
    headers = auth_header(client)
    assert client.post("/api/posts", json={"title": "", "body": "b"}, headers=headers).status_code == 400
    assert client.post("/api/posts", json={"title": "t" * 201, "body": "b"}, headers=headers).status_code == 400
    assert client.post("/api/posts", json={"title": 1, "body": "b"}, headers=headers).status_code == 400


def test_security_headers(client):
    resp = client.get("/api/data")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
