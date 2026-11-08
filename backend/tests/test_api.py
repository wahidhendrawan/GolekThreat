import re
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from golekthreat.config import Settings, settings
from golekthreat.db import get_db
from golekthreat.main import app

AUTH = {"Authorization": f"Bearer {settings.golek_api_token}"}
# Every documented operation except /health and /auth/login, so new routes are covered too.
PROTECTED = [
    (method.upper(), re.sub(r"\{[^}]+\}", "1", path))
    for path, operations in app.openapi()["paths"].items()
    if path not in {"/health", "/auth/login"}
    for method in operations
]
PLAYBOOK = {
    "slug": "gt-api-test",
    "title": "API Test Playbook",
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


def test_health_is_open(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_all_api_routes_are_protected() -> None:
    assert len(PROTECTED) >= 16


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-token-0123456789"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer t\xe9st".encode("latin-1")},
    ],
    ids=["missing", "wrong", "basic", "non-ascii"],
)
@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_missing_or_wrong_token_is_401(
    client: TestClient, method: str, path: str, headers: dict
) -> None:
    response = client.request(method, path, headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_token_is_accepted(client: TestClient) -> None:
    assert client.get("/playbooks", headers=AUTH).status_code == 200
    created = client.post("/playbooks", json=PLAYBOOK, headers=AUTH)
    assert created.status_code == 201
    assert created.json()["steps"][0]["instruction"] == "Inspect process commands."


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("steps", [{"title": "No instruction"}]),
        ("steps", ["not an object"]),
        ("queries", [{"platform": "KQL"}]),
    ],
)
def test_malformed_steps_or_queries_are_422(client: TestClient, field: str, value: list) -> None:
    response = client.post("/playbooks", json=PLAYBOOK | {field: value}, headers=AUTH)
    assert response.status_code == 422


@pytest.mark.parametrize("token", [None, "", "too-short"])
def test_settings_refuse_missing_or_short_token(
    monkeypatch: pytest.MonkeyPatch, token: str | None
) -> None:
    if token is None:
        monkeypatch.delenv("GOLEK_API_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GOLEK_API_TOKEN", token)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
