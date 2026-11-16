from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(160), default="Unknown")
    environment: Mapped[str] = mapped_column(String(40), default="production")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    contains_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    business_service: Mapped[str] = mapped_column(String(160), default="General")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(260))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    epss_percentile: Mapped[float] = mapped_column(Float, default=0.0)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(20), nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "vulnerability_id", name="uq_asset_vuln"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)

    # Lifecycle: open, in_progress, mitigated, remediated, risk_accepted, false_positive
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    compensating_control: Mapped[str] = mapped_column(Text, default="")
    risk_owner: Mapped[str] = mapped_column(String(160), default="")
    ticket_ref: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

    # Risk acceptance (four-eyes, time-bound)
    accepted_by: Mapped[str] = mapped_column(String(160), default="")
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acceptance_justification: Mapped[str] = mapped_column(Text, default="")

    # Scoring output
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW", index=True)
    sla_hours: Mapped[int] = mapped_column(Integer, default=720)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision: Mapped[str] = mapped_column(String(100), default="MONITOR")
    explanation: Mapped[str] = mapped_column(Text, default="")

    asset: Mapped[Asset] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")

    @property
    def due_date(self) -> str | None:  # backward-compatible v1 field
        due = _aware(self.sla_due_at)
        return due.isoformat() if due else None

    @property
    def overdue(self) -> bool:
        due = _aware(self.sla_due_at)
        return bool(due and self.status in {"open", "in_progress", "mitigated"} and datetime.now(timezone.utc) > due)


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(80), default="")
    open_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    overdue_findings: Mapped[int] = mapped_column(Integer, default=0)
    total_exposure: Mapped[float] = mapped_column(Float, default=0.0)
    sla_compliance: Mapped[float] = mapped_column(Float, default=100.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str] = mapped_column(String(160), default="system")
    entity_type: Mapped[str] = mapped_column(String(80), default="")
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="", index=True)
