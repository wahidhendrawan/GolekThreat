from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .db import Base, SessionLocal, engine, get_db
from .schemas import (
    CoverageItem,
    EvidenceCreate,
    EvidenceRead,
    HuntSessionCreate,
    HuntSessionRead,
    PlaybookCreate,
    PlaybookRead,
    SessionStepRead,
    SessionStepUpdate,
)
from .seed import seed_playbooks
from .services import (
    add_evidence,
    coverage,
    create_playbook,
    get_playbook,
    get_session,
    list_playbooks,
    list_sessions,
    render_markdown_report,
    start_session,
    update_session_step,
)

app = FastAPI(
    title="GolekThreat API",
    description="Threat hunting playbook engine API.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_playbooks(db)
    finally:
        db.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/playbooks", response_model=list[PlaybookRead])
def api_list_playbooks(db: Session = Depends(get_db)) -> list:
    return list_playbooks(db)


@app.post("/playbooks", response_model=PlaybookRead, status_code=201)
def api_create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    return create_playbook(db, payload)


@app.get("/playbooks/{playbook_id}", response_model=PlaybookRead)
def api_get_playbook(playbook_id: int, db: Session = Depends(get_db)):
    return get_playbook(db, playbook_id)


@app.post("/sessions", response_model=HuntSessionRead, status_code=201)
def api_start_session(payload: HuntSessionCreate, db: Session = Depends(get_db)):
    return start_session(db, payload)


@app.get("/sessions", response_model=list[HuntSessionRead])
def api_list_sessions(db: Session = Depends(get_db)) -> list:
    return list_sessions(db)


@app.get("/sessions/{session_id}", response_model=HuntSessionRead)
def api_get_session(session_id: int, db: Session = Depends(get_db)):
    return get_session(db, session_id)


@app.patch("/session-steps/{step_id}", response_model=SessionStepRead)
def api_update_session_step(
    step_id: int, payload: SessionStepUpdate, db: Session = Depends(get_db)
):
    return update_session_step(db, step_id, payload)


@app.post("/sessions/{session_id}/evidence", response_model=EvidenceRead, status_code=201)
def api_add_evidence(session_id: int, payload: EvidenceCreate, db: Session = Depends(get_db)):
    return add_evidence(db, session_id, payload)


@app.get("/coverage", response_model=list[CoverageItem])
def api_coverage(db: Session = Depends(get_db)) -> list[dict[str, str | int]]:
    return coverage(db)


@app.get("/sessions/{session_id}/report.md")
def api_report(session_id: int, db: Session = Depends(get_db)) -> Response:
    session = get_session(db, session_id)
    return Response(render_markdown_report(session), media_type="text/markdown")
