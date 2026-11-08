from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .auth import (
    Principal,
    authenticate,
    bootstrap_admin,
    clear_login_failures,
    create_user,
    current_principal,
    issue_token,
    locked_until,
    record_login_failure,
    require_role,
    revoke_token,
)
from .config import settings
from .db import Base, SessionLocal, engine, get_db
from .models import Role, User
from .schemas import (
    CoverageItem,
    EvidenceCreate,
    EvidenceRead,
    EvidenceUpdate,
    HuntSessionCreate,
    HuntSessionRead,
    HuntSessionUpdate,
    LoginRequest,
    LoginResponse,
    MeRead,
    PlaybookCreate,
    PlaybookRead,
    PlaybookUpdate,
    SessionStepRead,
    SessionStepUpdate,
    UserCreate,
    UserRead,
)
from .seed import seed_playbooks
from .services import (
    add_evidence,
    coverage,
    create_playbook,
    delete_evidence,
    delete_playbook,
    delete_session,
    get_playbook,
    get_session,
    list_playbooks,
    list_sessions,
    render_markdown_report,
    start_session,
    update_evidence,
    update_playbook,
    update_session,
    update_session_step,
)


def drop_legacy_columns(bind=engine) -> None:
    """session_steps.playbook_step_id (removed) made every playbook edit fail once a hunt ran."""
    if "playbook_step_id" in {c["name"] for c in inspect(bind).get_columns("session_steps")}:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE session_steps DROP COLUMN playbook_step_id"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    drop_legacy_columns()
    db = SessionLocal()
    try:
        seed_playbooks(db)
        bootstrap_admin(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="GolekThreat API",
    description="Threat hunting playbook engine API.",
    version="0.1.0",
    lifespan=lifespan,
)
# Every route except /health and /auth/login needs a signed-in user or the shared API token.
# Reading needs the viewer role, hunting the analyst role, playbook deletion and users admin.
router = APIRouter(dependencies=[Depends(require_role(Role.viewer))])
analyst = Depends(require_role(Role.analyst))
admin = Depends(require_role(Role.admin))

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/login", response_model=LoginResponse)
def api_login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    locked = locked_until(payload.username)
    if locked:
        retry_after = max(1, int((locked - datetime.now(UTC)).total_seconds()))
        raise HTTPException(
            status_code=429,
            detail="Too many failed logins, try again later",
            headers={"Retry-After": str(retry_after)},
        )
    user = authenticate(db, payload.username, payload.password)
    if user is None:
        record_login_failure(payload.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    clear_login_failures(payload.username)
    return LoginResponse(token=issue_token(db, user), username=user.username, role=user.role)


@router.post("/auth/logout", status_code=204)
def api_logout(
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db)
) -> Response:
    if principal.token_hash:
        revoke_token(db, principal.token_hash)
    return Response(status_code=204)


@router.get("/auth/me", response_model=MeRead)
def api_me(principal: Principal = Depends(current_principal)) -> MeRead:
    return MeRead(username=principal.username, role=principal.role)


@router.get("/users", response_model=list[UserRead], dependencies=[admin])
def api_list_users(db: Session = Depends(get_db)) -> list:
    return db.query(User).order_by(User.username).all()


@router.post("/users", response_model=UserRead, status_code=201, dependencies=[admin])
def api_create_user(payload: UserCreate, db: Session = Depends(get_db)):
    return create_user(db, payload.username, payload.password, payload.role)


@router.delete("/users/{user_id}", status_code=204, dependencies=[admin])
def api_delete_user(
    user_id: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)
) -> Response:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == principal.user_id:
        raise HTTPException(status_code=409, detail="Cannot delete your own account")
    db.delete(user)
    db.commit()
    return Response(status_code=204)


@router.get("/playbooks", response_model=list[PlaybookRead])
def api_list_playbooks(db: Session = Depends(get_db)) -> list:
    return list_playbooks(db)


@router.post("/playbooks", response_model=PlaybookRead, status_code=201, dependencies=[analyst])
def api_create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    return create_playbook(db, payload)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookRead, dependencies=[analyst])
def api_update_playbook(playbook_id: int, payload: PlaybookUpdate, db: Session = Depends(get_db)):
    return update_playbook(db, playbook_id, payload)


@router.delete("/playbooks/{playbook_id}", status_code=204, dependencies=[admin])
def api_delete_playbook(playbook_id: int, db: Session = Depends(get_db)) -> Response:
    delete_playbook(db, playbook_id)
    return Response(status_code=204)


@router.get("/playbooks/{playbook_id}", response_model=PlaybookRead)
def api_get_playbook(playbook_id: int, db: Session = Depends(get_db)):
    return get_playbook(db, playbook_id)


@router.post("/sessions", response_model=HuntSessionRead, status_code=201, dependencies=[analyst])
def api_start_session(payload: HuntSessionCreate, db: Session = Depends(get_db)):
    return start_session(db, payload)


@router.get("/sessions", response_model=list[HuntSessionRead])
def api_list_sessions(db: Session = Depends(get_db)) -> list:
    return list_sessions(db)


@router.get("/sessions/{session_id}", response_model=HuntSessionRead)
def api_get_session(session_id: int, db: Session = Depends(get_db)):
    return get_session(db, session_id)


@router.patch("/sessions/{session_id}", response_model=HuntSessionRead, dependencies=[analyst])
def api_update_session(session_id: int, payload: HuntSessionUpdate, db: Session = Depends(get_db)):
    return update_session(db, session_id, payload)


@router.delete("/sessions/{session_id}", status_code=204, dependencies=[analyst])
def api_delete_session(session_id: int, db: Session = Depends(get_db)) -> Response:
    delete_session(db, session_id)
    return Response(status_code=204)


@router.patch("/session-steps/{step_id}", response_model=SessionStepRead, dependencies=[analyst])
def api_update_session_step(
    step_id: int, payload: SessionStepUpdate, db: Session = Depends(get_db)
):
    return update_session_step(db, step_id, payload)


@router.post(
    "/sessions/{session_id}/evidence",
    response_model=EvidenceRead,
    status_code=201,
    dependencies=[analyst],
)
def api_add_evidence(session_id: int, payload: EvidenceCreate, db: Session = Depends(get_db)):
    return add_evidence(db, session_id, payload)


@router.patch("/evidence/{evidence_id}", response_model=EvidenceRead, dependencies=[analyst])
def api_update_evidence(evidence_id: int, payload: EvidenceUpdate, db: Session = Depends(get_db)):
    return update_evidence(db, evidence_id, payload)


@router.delete("/evidence/{evidence_id}", status_code=204, dependencies=[analyst])
def api_delete_evidence(evidence_id: int, db: Session = Depends(get_db)) -> Response:
    delete_evidence(db, evidence_id)
    return Response(status_code=204)


@router.get("/coverage", response_model=list[CoverageItem])
def api_coverage(db: Session = Depends(get_db)) -> list[dict[str, str | int]]:
    return coverage(db)


@router.get("/sessions/{session_id}/report.md")
def api_report(session_id: int, db: Session = Depends(get_db)) -> Response:
    session = get_session(db, session_id)
    return Response(render_markdown_report(session), media_type="text/markdown")


app.include_router(router)
