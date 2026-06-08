from collections import Counter

from fastapi import HTTPException
from sqlalchemy.orm import Session, joinedload

from .models import (
    EvidenceItem,
    HuntSession,
    Playbook,
    PlaybookQuery,
    PlaybookStep,
    SessionStep,
    SessionStatus,
)
from .schemas import EvidenceCreate, HuntSessionCreate, PlaybookCreate, SessionStepUpdate


def list_playbooks(db: Session) -> list[Playbook]:
    return (
        db.query(Playbook)
        .options(joinedload(Playbook.steps), joinedload(Playbook.queries))
        .order_by(Playbook.severity.desc(), Playbook.title)
        .all()
    )


def get_playbook(db: Session, playbook_id: int) -> Playbook:
    playbook = (
        db.query(Playbook)
        .options(joinedload(Playbook.steps), joinedload(Playbook.queries))
        .filter(Playbook.id == playbook_id)
        .first()
    )
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


def create_playbook(db: Session, payload: PlaybookCreate) -> Playbook:
    if db.query(Playbook).filter(Playbook.slug == payload.slug).first():
        raise HTTPException(status_code=409, detail="Playbook slug already exists")

    playbook = Playbook(**payload.model_dump(exclude={"steps", "queries"}))
    db.add(playbook)
    db.flush()

    for index, step in enumerate(payload.steps, start=1):
        db.add(
            PlaybookStep(
                playbook_id=playbook.id,
                position=index,
                title=step["title"],
                instruction=step["instruction"],
            )
        )

    for query in payload.queries:
        db.add(
            PlaybookQuery(
                playbook_id=playbook.id,
                platform=query["platform"],
                query=query["query"],
            )
        )

    db.commit()
    db.refresh(playbook)
    return get_playbook(db, playbook.id)


def start_session(db: Session, payload: HuntSessionCreate) -> HuntSession:
    playbook = get_playbook(db, payload.playbook_id)
    session = HuntSession(
        playbook_id=playbook.id,
        title=f"Hunt: {playbook.title}",
        analyst=payload.analyst,
        scope=payload.scope,
        status=SessionStatus.running,
    )
    db.add(session)
    db.flush()

    for step in playbook.steps:
        db.add(
            SessionStep(
                session_id=session.id,
                playbook_step_id=step.id,
                position=step.position,
                title=step.title,
                instruction=step.instruction,
            )
        )

    db.commit()
    return get_session(db, session.id)


def list_sessions(db: Session) -> list[HuntSession]:
    return (
        db.query(HuntSession)
        .options(
            joinedload(HuntSession.playbook).joinedload(Playbook.steps),
            joinedload(HuntSession.playbook).joinedload(Playbook.queries),
            joinedload(HuntSession.steps),
            joinedload(HuntSession.evidence),
        )
        .order_by(HuntSession.started_at.desc())
        .all()
    )


def get_session(db: Session, session_id: int) -> HuntSession:
    session = (
        db.query(HuntSession)
        .options(
            joinedload(HuntSession.playbook).joinedload(Playbook.steps),
            joinedload(HuntSession.playbook).joinedload(Playbook.queries),
            joinedload(HuntSession.steps),
            joinedload(HuntSession.evidence),
        )
        .filter(HuntSession.id == session_id)
        .first()
    )
    if not session:
        raise HTTPException(status_code=404, detail="Hunt session not found")
    return session


def update_session_step(db: Session, step_id: int, payload: SessionStepUpdate) -> SessionStep:
    step = db.query(SessionStep).filter(SessionStep.id == step_id).first()
    if not step:
        raise HTTPException(status_code=404, detail="Session step not found")
    step.status = payload.status
    step.notes = payload.notes
    db.commit()
    db.refresh(step)
    return step


def add_evidence(db: Session, session_id: int, payload: EvidenceCreate) -> EvidenceItem:
    get_session(db, session_id)
    evidence = EvidenceItem(session_id=session_id, **payload.model_dump())
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def coverage(db: Session) -> list[dict[str, str | int]]:
    playbooks = db.query(Playbook).all()
    counter = Counter((item.tactic, item.technique_id, item.technique) for item in playbooks)
    return [
        {
            "tactic": tactic,
            "technique_id": technique_id,
            "technique": technique,
            "playbook_count": count,
        }
        for (tactic, technique_id, technique), count in sorted(counter.items())
    ]


def render_markdown_report(session: HuntSession) -> str:
    evidence = "\n".join(
        f"- **{item.title}**: {item.note} ({item.artifact_ref or 'no artifact reference'})"
        for item in session.evidence
    ) or "- No evidence recorded."
    steps = "\n".join(
        f"- [{step.status.value}] **{step.title}** - {step.notes or step.instruction}"
        for step in session.steps
    )
    return f"""# {session.title}

## Executive Summary

Threat hunt executed by **{session.analyst}** against scope: `{session.scope}`.

## Hypothesis

{session.playbook.hypothesis}

## ATT&CK Mapping

- Tactic: {session.playbook.tactic}
- Technique: {session.playbook.technique_id} - {session.playbook.technique}

## Hunt Steps

{steps}

## Evidence

{evidence}

## Expected Evidence

{session.playbook.expected_evidence}

## False Positive Notes

{session.playbook.false_positives}

## Recommended Actions

{session.playbook.response}
"""
