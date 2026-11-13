from app.auth import DemoAuth, SESSION_COOKIE, hash_password, verify_password
from app.config import Settings
from app.main import app


ORIGIN = "https://frontend.test"


def enable_demo_auth(clock=None, **overrides):
    values = {
        "auth_mode": "demo",
        "demo_username": "analyst",
        "demo_password_hash": hash_password("correct-horse-battery-staple"),
        "cors_origins": ORIGIN,
        "cookie_samesite": "none",
        "demo_login_attempts": 8,
    }
    values.update(overrides)
    settings = Settings(**values)
    app.state.auth_mode = "demo"
    app.state.demo_auth = DemoAuth(settings, clock=clock) if clock else DemoAuth(settings)


def login(client, username="analyst", password="correct-horse-battery-staple"):
    return client.post(
        "/api/auth/login",
        headers={"Origin": ORIGIN},
        json={"username": username, "password": password},
    )


def test_scrypt_password_verification() -> None:
    encoded = hash_password("temporary-test-password")
    assert verify_password("temporary-test-password", encoded)
    assert not verify_password("different-password", encoded)


def test_server_session_expiry_invalidation_csrf_and_throttle() -> None:
    now = [10.0]
    settings = Settings(
        auth_mode="demo",
        demo_username="analyst",
        demo_password_hash=hash_password("temporary-test-password"),
        demo_session_ttl_seconds=300,
        demo_login_attempts=1,
        cors_origins=ORIGIN,
        cookie_samesite="none",
    )
    auth = DemoAuth(settings, clock=lambda: now[0])
    token, session = auth.create_session()
    assert auth.get_session(token) == session
    assert auth.csrf_valid(session, session.csrf_token)
    assert not auth.csrf_valid(session, "invalid")
    auth.invalidate(token)
    assert auth.get_session(token) is None
    expiring_token, _ = auth.create_session()
    now[0] += 301
    assert auth.get_session(expiring_token) is None
    assert auth.allow_login_attempt("test-peer")
    assert not auth.allow_login_attempt("test-peer")


def test_demo_auth_protects_sensitive_api_and_accepts_configured_user(client) -> None:
    enable_demo_auth()
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/health").status_code == 200

    response = login(client)
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert response.json()["username"] == "analyst"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=none" in cookie
    assert client.get("/api/auth/session").json()["authenticated"] is True
    assert client.get("/api/events").status_code == 200


def test_demo_auth_rejects_invalid_credentials(client) -> None:
    enable_demo_auth()
    response = login(client, password="wrong-password")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password."}
    assert "set-cookie" not in response.headers


def test_expired_and_unknown_sessions_are_rejected(client) -> None:
    now = [100.0]
    enable_demo_auth(clock=lambda: now[0], demo_session_ttl_seconds=300)
    client.cookies.set(SESSION_COOKIE, "not-a-session", domain="testserver")
    assert client.get("/api/events").status_code == 401
    client.cookies.clear()

    assert login(client).status_code == 200
    now[0] += 301
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/auth/session").json()["authenticated"] is False


def test_logout_invalidates_server_session(client) -> None:
    enable_demo_auth()
    session = login(client).json()
    response = client.post(
        "/api/auth/logout",
        headers={"Origin": ORIGIN, "X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 204
    assert client.get("/api/events").status_code == 401


def test_csrf_origin_and_demo_admin_restrictions(client) -> None:
    enable_demo_auth()
    session = login(client).json()
    assert client.post(
        "/api/events",
        headers={"Origin": ORIGIN, "X-CSRF-Token": "invalid"},
        json={"username": "alice", "source_ip": "192.0.2.10", "event_type": "login", "status": "success"},
    ).status_code == 403
    assert client.patch(
        "/api/settings/detection",
        headers={"Origin": ORIGIN, "X-CSRF-Token": session["csrf_token"]},
        json={"monitoring_enabled": False},
    ).status_code == 403
    assert client.post(
        "/api/events",
        headers={"Origin": "https://attacker.test", "X-CSRF-Token": session["csrf_token"]},
        json={"username": "alice", "source_ip": "192.0.2.10", "event_type": "login", "status": "success"},
    ).status_code == 403


def test_login_rate_limiting(client) -> None:
    enable_demo_auth(demo_login_attempts=2, demo_global_login_attempts=4)
    assert login(client, password="wrong").status_code == 401
    assert login(client, password="wrong").status_code == 401
    limited = login(client, password="wrong")
    assert limited.status_code == 429
    assert limited.json() == {"detail": "Unable to sign in right now. Try again later."}
    assert limited.headers["retry-after"]
