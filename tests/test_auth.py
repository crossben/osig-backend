"""Auth: tokens, refresh, refresh-token misuse, profile, password change."""


def test_register_returns_token_pair(user):
    _, body = user
    assert body["access_token"] and body["refresh_token"]
    assert body["expires_in"] > 0


def test_me_with_access_token(client, user):
    headers, body = user
    r = client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 200
    assert r.json()["email"] == body["user"]["email"]


def test_refresh_token_cannot_be_used_as_access_token(client, user):
    _, body = user
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['refresh_token']}"})
    assert r.status_code == 401


def test_refresh_issues_new_pair(client, user):
    _, body = user
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_access_token_rejected_by_refresh(client, user):
    _, body = user
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": body["access_token"]})
    assert r.status_code == 401


def test_wrong_password_is_401(client, user):
    _, body = user
    r = client.post("/api/v1/auth/login", json={"email": body["user"]["email"], "password": "nope-nope-1"})
    assert r.status_code == 401


def test_profile_update(client, user):
    headers, _ = user
    r = client.patch("/api/v1/auth/me", headers=headers, json={"full_name": "Ada Lovelace"})
    assert r.status_code == 200 and r.json()["full_name"] == "Ada Lovelace"


def test_avatar_must_be_https(client, user):
    headers, _ = user
    r = client.patch("/api/v1/auth/me", headers=headers, json={"avatar_url": "http://insecure.example/a.png"})
    assert r.status_code == 422


def test_password_change_revokes_old_refresh_tokens(client, user):
    headers, body = user
    r = client.post("/api/v1/auth/change-password", headers=headers,
                    json={"current_password": "Passw0rd!x", "new_password": "N3wPassw0rd!"})
    assert r.status_code == 200
    # old refresh token no longer works, the new one does
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": r.json()["refresh_token"]}).status_code == 200


def test_password_change_needs_current_password(client, user):
    headers, _ = user
    r = client.post("/api/v1/auth/change-password", headers=headers,
                    json={"current_password": "wrong-one-1", "new_password": "N3wPassw0rd!"})
    assert r.status_code == 400
