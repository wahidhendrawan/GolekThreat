from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .models import Role, SessionStatus, Severity, StepStatus


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: Role


class MeRead(BaseModel):
    username: str
    role: Role


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Role = Role.viewer


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    created_at: datetime


class PlaybookStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    position: int
    title: str
    instruction: str


class PlaybookQueryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    platform: str
    query: str


class PlaybookStepCreate(BaseModel):
    title: str
    instruction: str


class PlaybookQueryCreate(BaseModel):
    platform: str
    query: str


class PlaybookCreate(BaseModel):
    slug: str
    title: str
    hypothesis: str
    severity: Severity = Severity.medium
    tactic: str
    technique: str
    technique_id: str
    data_sources: str
    expected_evidence: str
    false_positives: str
    response: str
    steps: list[PlaybookStepCreate]
    queries: list[PlaybookQueryCreate] = []


class PlaybookUpdate(PlaybookCreate):
    pass


class PlaybookRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    slug: str
    title: str
    hypothesis: str
    severity: Severity
    tactic: str
    technique: str
    technique_id: str
    data_sources: str
    expected_evidence: str
    false_positives: str
    response: str
    created_at: datetime
    steps: list[PlaybookStepRead]
    queries: list[PlaybookQueryRead]


class HuntSessionCreate(BaseModel):
    playbook_id: int
    analyst: str = "Unassigned"
    scope: str = "Not defined"


class HuntSessionUpdate(BaseModel):
    title: str
    analyst: str
    scope: str
    status: SessionStatus


class SessionStepUpdate(BaseModel):
    status: StepStatus
    notes: str = ""


class SessionStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    position: int
    title: str
    instruction: str
    status: StepStatus
    notes: str


class EvidenceCreate(BaseModel):
    title: str
    note: str
    artifact_ref: str = ""


class EvidenceUpdate(EvidenceCreate):
    pass


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    note: str
    artifact_ref: str
    created_at: datetime


class HuntSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    analyst: str
    scope: str
    status: SessionStatus
    started_at: datetime
    playbook: PlaybookRead
    steps: list[SessionStepRead]
    evidence: list[EvidenceRead]


class CoverageItem(BaseModel):
    tactic: str
    technique_id: str
    technique: str
    playbook_count: int
