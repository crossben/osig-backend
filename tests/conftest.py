"""
Test setup: a separate Postgres database (osig_test), rebuilt per session,
rate limits relaxed, and scan dispatch replaced so no real scans run.
"""
import os

os.environ.setdefault("TEST_DATABASE_URL", "postgresql://osig:osig_dev_pass@localhost:5434/osig_test")
os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
os.environ["RATE_LIMIT_AUTH"] = "1000/minute"
os.environ["RATE_LIMIT_SCANS"] = "1000/minute"
os.environ["RATE_LIMIT_EMAIL"] = "1000/minute"
os.environ["RATE_LIMIT_FOOTPRINT_REFRESH"] = "1000/minute"
os.environ["SCAN_EXECUTOR"] = "thread"

import uuid  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401  (register all tables)
from app.db.session import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def no_real_scans(monkeypatch):
    """Scans are created but never executed (no network, no worker)."""
    dispatched = []
    monkeypatch.setattr("app.workers.scan_tasks.dispatch_scan", lambda scan_id: dispatched.append(scan_id))
    return dispatched


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def user(client):
    """A fresh registered user: returns (headers, body)."""
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={
        "email": f"user{tag}@gmail.com", "username": f"user{tag}", "password": "Passw0rd!x",
    })
    assert r.status_code == 201, r.text
    body = r.json()
    from app.models.user import User
    session = SessionLocal()
    # Enterprise so feature tests aren't blocked by plan limits (tests/test_billing.py covers those)
    session.query(User).filter(User.id == body["user"]["id"]).update({"email_verified": True, "plan": "ENTERPRISE"})
    session.commit()
    session.close()
    return {"Authorization": f"Bearer {body['access_token']}"}, body


@pytest.fixture
def unverified_user(client):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={
        "email": f"unv{tag}@gmail.com", "username": f"unv{tag}", "password": "Passw0rd!x",
    })
    body = r.json()
    return {"Authorization": f"Bearer {body['access_token']}"}, body
