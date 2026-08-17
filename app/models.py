from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(260))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[str | None] = mapped_column(String(40), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "vulnerability_id", name="uq_asset_vuln"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)

    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    due_date: Mapped[str | None] = mapped_column(String(40), nullable=True)
    compensating_control: Mapped[str] = mapped_column(Text, default="")
    risk_owner: Mapped[str] = mapped_column(String(160), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW", index=True)
    sla_hours: Mapped[int] = mapped_column(Integer, default=720)
    decision: Mapped[str] = mapped_column(String(100), default="MONITOR")
    explanation: Mapped[str] = mapped_column(Text, default="")

    asset: Mapped[Asset] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
