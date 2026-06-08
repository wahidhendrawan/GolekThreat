from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class StepStatus(str, Enum):
    pending = "pending"
    running = "running"
    evidence_found = "evidence_found"
    false_positive = "false_positive"
    no_finding = "no_finding"


class SessionStatus(str, Enum):
    running = "running"
    completed = "completed"
    archived = "archived"


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    hypothesis: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SqlEnum(Severity), default=Severity.medium)
    tactic: Mapped[str] = mapped_column(String(120))
    technique: Mapped[str] = mapped_column(String(160))
    technique_id: Mapped[str] = mapped_column(String(40))
    data_sources: Mapped[str] = mapped_column(Text)
    expected_evidence: Mapped[str] = mapped_column(Text)
    false_positives: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    steps: Mapped[list["PlaybookStep"]] = relationship(
        back_populates="playbook", cascade="all, delete-orphan", order_by="PlaybookStep.position"
    )
    queries: Mapped[list["PlaybookQuery"]] = relationship(
        back_populates="playbook", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["HuntSession"]] = relationship(back_populates="playbook")


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    instruction: Mapped[str] = mapped_column(Text)

    playbook: Mapped[Playbook] = relationship(back_populates="steps")


class PlaybookQuery(Base):
    __tablename__ = "playbook_queries"

    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"))
    platform: Mapped[str] = mapped_column(String(60))
    query: Mapped[str] = mapped_column(Text)

    playbook: Mapped[Playbook] = relationship(back_populates="queries")


class HuntSession(Base):
    __tablename__ = "hunt_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id"))
    title: Mapped[str] = mapped_column(String(220))
    analyst: Mapped[str] = mapped_column(String(120), default="Unassigned")
    scope: Mapped[str] = mapped_column(Text, default="Not defined")
    status: Mapped[SessionStatus] = mapped_column(SqlEnum(SessionStatus), default=SessionStatus.running)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    playbook: Mapped[Playbook] = relationship(back_populates="sessions")
    steps: Mapped[list["SessionStep"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="SessionStep.position"
    )
    evidence: Mapped[list["EvidenceItem"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class SessionStep(Base):
    __tablename__ = "session_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("hunt_sessions.id", ondelete="CASCADE"))
    playbook_step_id: Mapped[int] = mapped_column(ForeignKey("playbook_steps.id"))
    position: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    instruction: Mapped[str] = mapped_column(Text)
    status: Mapped[StepStatus] = mapped_column(SqlEnum(StepStatus), default=StepStatus.pending)
    notes: Mapped[str] = mapped_column(Text, default="")

    session: Mapped[HuntSession] = relationship(back_populates="steps")


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("hunt_sessions.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(200))
    artifact_ref: Mapped[str] = mapped_column(String(500), default="")
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[HuntSession] = relationship(back_populates="evidence")
