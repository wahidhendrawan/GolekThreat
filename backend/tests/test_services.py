from collections.abc import Generator

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from golekthreat.db import Base
from golekthreat.schemas import (
    EvidenceCreate,
    EvidenceUpdate,
    HuntSessionCreate,
    HuntSessionUpdate,
    PlaybookCreate,
    PlaybookUpdate,
    SessionStepUpdate,
)
from golekthreat.services import (
    add_evidence,
    coverage,
    create_playbook,
    delete_evidence,
    delete_playbook,
    delete_session,
    list_sessions,
    render_markdown_report,
    start_session,
    update_evidence,
    update_playbook,
    update_session,
    update_session_step,
)
from golekthreat.models import SessionStatus, StepStatus


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def playbook_payload(slug: str = "gt-test-playbook") -> PlaybookCreate:
    return PlaybookCreate(
        slug=slug,
        title="Test Playbook",
        hypothesis="A test hypothesis.",
        severity="medium",
        tactic="Discovery",
        technique="System Information Discovery",
        technique_id="T1082",
        data_sources="Process telemetry",
        expected_evidence="Command line evidence.",
        false_positives="Administrative scripts.",
        response="Validate and document.",
        steps=[{"title": "Review commands", "instruction": "Inspect process commands."}],
        queries=[{"platform": "KQL", "query": "DeviceProcessEvents | take 1"}],
    )


def test_playbook_session_evidence_lifecycle(db: Session) -> None:
    playbook = create_playbook(db, playbook_payload())
    assert playbook.id

    update_payload = PlaybookUpdate(**playbook_payload().model_dump())
    update_payload.title = "Updated Test Playbook"
    updated_playbook = update_playbook(db, playbook.id, update_payload)
    assert updated_playbook.title == "Updated Test Playbook"

    session = start_session(
        db,
        HuntSessionCreate(
            playbook_id=playbook.id,
            analyst="Test Analyst",
            scope="Unit test scope",
        ),
    )
    assert session.steps[0].status == StepStatus.pending

    updated_session = update_session(
        db,
        session.id,
        HuntSessionUpdate(
            title="Updated Hunt Session",
            analyst="Test Analyst",
            scope="Updated scope",
            status=SessionStatus.completed,
        ),
    )
    assert updated_session.status == SessionStatus.completed

    updated_step = update_session_step(
        db,
        session.steps[0].id,
        SessionStepUpdate(status=StepStatus.evidence_found, notes="Found matching telemetry."),
    )
    assert updated_step.notes == "Found matching telemetry."

    evidence = add_evidence(
        db,
        session.id,
        EvidenceCreate(title="Evidence", note="Relevant event.", artifact_ref="case-1"),
    )
    updated_evidence = update_evidence(
        db,
        evidence.id,
        EvidenceUpdate(title="Updated Evidence", note="Updated note.", artifact_ref="case-2"),
    )
    assert updated_evidence.title == "Updated Evidence"

    report = render_markdown_report(updated_session)
    assert "Updated Hunt Session" in report
    assert coverage(db)[0]["technique_id"] == "T1082"

    delete_evidence(db, evidence.id)
    delete_session(db, session.id)
    delete_playbook(db, playbook.id)
    assert list_sessions(db) == []


def test_delete_playbook_with_sessions_returns_conflict(db: Session) -> None:
    playbook = create_playbook(db, playbook_payload("gt-conflict-playbook"))
    start_session(
        db,
        HuntSessionCreate(playbook_id=playbook.id, analyst="Test Analyst", scope="Conflict"),
    )

    with pytest.raises(HTTPException) as exc:
        delete_playbook(db, playbook.id)

    assert exc.value.status_code == 409
    assert "Delete those sessions" in exc.value.detail
