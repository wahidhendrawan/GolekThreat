"""User accounts, login tokens and role checks; the shared API token stays an admin."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from golekthreat import auth
from golekthreat.config import settings
from golekthreat.db import get_db
from golekthreat.main import app
from golekthreat.models import Role, User, UserToken

PASSWORD = "correct-horse-battery"
API_TOKEN = {"Authorization": f"Bearer {settings.golek_api_token}"}
PLAYBOOK = {
    "slug": "gt-auth-test",
    "title": "Auth Test Playbook",
    "hypothesis": "A test hypothesis.",
    "tactic": "Discovery",
    "technique": "System Information Discovery",
    "technique_id": "T1082",
    "data_sources": "Process telemetry",
    "expected_evidence": "Command line evidence.",
    "false_positives": "Administrative scripts.",
    "response": "Validate and document.",
    "steps": [{"title": "Review commands", "instruction": "Inspect process commands."}],
    "queries": [{"platform": "KQL", "query": "DeviceProcessEvents | take 1"}],
}


@pytest.fixture()
def client(db: Session) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _login(client: TestClient, username: str, password: str = PASSWORD) -> dict[str, str]:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture()
def users(client: TestClient, db: Session) -> dict[str, dict[str, str]]:
    headers = {}
    for role in Role:
        created = client.post(
            "/users",
            json={"username": role.value, "password": PASSWORD, "role": role.value},
            headers=API_TOKEN,
        )
        assert created.status_code == 201, created.text
        headers[role.value] = _login(client, role.value)
    return headers


def test_password_hashing_roundtrip() -> None:
    stored = auth.hash_password(PASSWORD)
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert auth.verify_password(PASSWORD, stored)
    assert not auth.verify_password("wrong-password-1", stored)
    assert not auth.verify_password(PASSWORD, "garbage")
    assert auth.hash_password(PASSWORD) != stored  # fresh salt each time


def test_login_rejects_bad_credentials(client: TestClient, users: dict) -> None:
    for payload in [
        {"username": "viewer", "password": "wrong-password-1"},
        {"username": "nobody", "password": PASSWORD},
    ]:
        assert client.post("/auth/login", json=payload).status_code == 401
    assert client.post("/auth/login", json={"username": "viewer"}).status_code == 422


def test_shared_api_token_is_admin(client: TestClient) -> None:
    assert client.get("/auth/me", headers=API_TOKEN).json() == {
        "username": "api-token",
        "role": "admin",
    }
    assert client.post("/auth/logout", headers=API_TOKEN).status_code == 204
    assert client.get("/auth/me", headers=API_TOKEN).status_code == 200  # cannot be revoked


def test_roles_gate_reads_hunts_and_deletes(client: TestClient, users: dict) -> None:
    viewer, analyst, admin = users["viewer"], users["analyst"], users["admin"]
    assert client.get("/auth/me", headers=viewer).json() == {"username": "viewer", "role": "viewer"}
    assert client.get("/playbooks", headers=viewer).status_code == 200
    assert client.get("/coverage", headers=viewer).status_code == 200

    forbidden = client.post("/playbooks", json=PLAYBOOK, headers=viewer)
    assert forbidden.status_code == 403 and "analyst" in forbidden.json()["detail"]
    assert client.post("/sessions", json={"playbook_id": 1}, headers=viewer).status_code == 403

    created = client.post("/playbooks", json=PLAYBOOK, headers=analyst)
    assert created.status_code == 201
    playbook_id = created.json()["id"]
    session = client.post(
        "/sessions",
        json={"playbook_id": playbook_id, "analyst": "a", "scope": "s"},
        headers=analyst,
    )
    assert session.status_code == 201
    step_id = session.json()["steps"][0]["id"]
    assert (
        client.patch(
            f"/session-steps/{step_id}", json={"status": "running", "notes": "x"}, headers=analyst
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/session-steps/{step_id}", json={"status": "running", "notes": "x"}, headers=viewer
        ).status_code
        == 403
    )
    assert client.delete(f"/sessions/{session.json()['id']}", headers=analyst).status_code == 204

    assert client.delete(f"/playbooks/{playbook_id}", headers=analyst).status_code == 403
    assert client.delete(f"/playbooks/{playbook_id}", headers=admin).status_code == 204


def test_logout_revokes_only_that_token(client: TestClient, users: dict, db: Session) -> None:
    first, second = users["analyst"], _login(client, "analyst")
    assert db.query(UserToken).count() == 4
    assert client.post("/auth/logout", headers=first).status_code == 204
    assert client.get("/auth/me", headers=first).status_code == 401
    assert client.get("/auth/me", headers=second).status_code == 200
    assert (
        client.get(
            "/auth/me", headers={"Authorization": "Bearer not-a-real-token-value"}
        ).status_code
        == 401
    )


def test_user_management_is_admin_only(client: TestClient, users: dict, db: Session) -> None:
    for headers in (users["viewer"], users["analyst"]):
        assert client.get("/users", headers=headers).status_code == 403
        assert (
            client.post(
                "/users",
                json={"username": "x.y", "password": PASSWORD, "role": "viewer"},
                headers=headers,
            ).status_code
            == 403
        )

    listed = client.get("/users", headers=users["admin"])
    assert [u["username"] for u in listed.json()] == ["admin", "analyst", "viewer"]
    assert "password_hash" not in listed.json()[0]

    assert (
        client.post(
            "/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
            headers=users["admin"],
        ).status_code
        == 409
    )
    for bad in [
        {"username": "ab", "password": PASSWORD},
        {"username": "ok-name", "password": "short"},
        {"username": "bad name!", "password": PASSWORD},
        {"username": "ok-name", "password": PASSWORD, "role": "root"},
    ]:
        assert client.post("/users", json=bad, headers=users["admin"]).status_code == 422

    me = db.query(User).filter(User.username == "admin").one()
    assert client.delete(f"/users/{me.id}", headers=users["admin"]).status_code == 409
    assert client.delete("/users/999", headers=users["admin"]).status_code == 404
    analyst_id = db.query(User).filter(User.username == "analyst").one().id
    assert client.delete(f"/users/{analyst_id}", headers=users["admin"]).status_code == 204
    assert (
        client.get("/auth/me", headers=users["analyst"]).status_code == 401
    )  # tokens go with the user
    assert db.query(UserToken).join(User).filter(User.username == "analyst").count() == 0


def test_bootstrap_admin_runs_once_and_only_with_a_password(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "golek_admin_password", None)
    assert auth.bootstrap_admin(db) is None and db.query(User).count() == 0
    monkeypatch.setattr(settings, "golek_admin_password", PASSWORD)
    monkeypatch.setattr(settings, "golek_admin_username", "first-admin")
    created = auth.bootstrap_admin(db)
    assert created is not None and created.role == Role.admin
    assert auth.authenticate(db, "first-admin", PASSWORD) is not None
    assert auth.bootstrap_admin(db) is None and db.query(User).count() == 1  # never a second time
