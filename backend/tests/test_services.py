import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

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


def test_editing_a_playbook_that_has_sessions_keeps_them(db: Session) -> None:
    playbook = create_playbook(db, playbook_payload("gt-edit-with-session"))
    session = start_session(db, HuntSessionCreate(playbook_id=playbook.id, analyst="a", scope="s"))

    payload = PlaybookUpdate(
        **playbook_payload("gt-edit-with-session").model_dump()
        | {"steps": [{"title": "New step", "instruction": "Changed after the hunt started."}]}
    )
    updated = update_playbook(db, playbook.id, payload)

    assert [step.title for step in updated.steps] == ["New step"]
    assert [step.title for step in list_sessions(db)[0].steps] == [
        "Review commands"
    ]  # hunt keeps its copy
    assert session.id == list_sessions(db)[0].id


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
