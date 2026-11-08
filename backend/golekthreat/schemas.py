from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .models import Role, SessionStatus, Severity, StepStatus

TEXT = 20_000  # notes, instructions and similar free text
QUERY = 50_000


class LoginRequest(BaseModel):
    username: str = Field(max_length=80)
    password: str = Field(max_length=256)


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
    title: str = Field(min_length=1, max_length=200)
    instruction: str = Field(min_length=1, max_length=TEXT)


class PlaybookQueryCreate(BaseModel):
    platform: str = Field(min_length=1, max_length=60)
    query: str = Field(min_length=1, max_length=QUERY)


class PlaybookCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(min_length=1, max_length=TEXT)
    severity: Severity = Severity.medium
    tactic: str = Field(min_length=1, max_length=120)
    technique: str = Field(min_length=1, max_length=160)
    technique_id: str = Field(min_length=1, max_length=40)
    data_sources: str = Field(min_length=1, max_length=TEXT)
    expected_evidence: str = Field(min_length=1, max_length=TEXT)
    false_positives: str = Field(min_length=1, max_length=TEXT)
    response: str = Field(min_length=1, max_length=TEXT)
    steps: list[PlaybookStepCreate] = Field(max_length=200)
    queries: list[PlaybookQueryCreate] = Field(default=[], max_length=200)


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
    analyst: str = Field(default="Unassigned", max_length=120)
    scope: str = Field(default="Not defined", max_length=TEXT)


class HuntSessionUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=220)
    analyst: str = Field(max_length=120)
    scope: str = Field(max_length=TEXT)
    status: SessionStatus


class SessionStepUpdate(BaseModel):
    status: StepStatus
    notes: str = Field(default="", max_length=TEXT)


class SessionStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    position: int
    title: str
    instruction: str
    status: StepStatus
    notes: str


class EvidenceCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    note: str = Field(min_length=1, max_length=TEXT)
    artifact_ref: str = Field(default="", max_length=500)


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
