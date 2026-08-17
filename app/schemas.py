from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    owner: str = "Unknown"
    environment: str = "production"
    criticality: int = Field(default=3, ge=1, le=5)
    internet_exposed: bool = False
    contains_sensitive_data: bool = False
    business_service: str = "General"


class AssetRead(AssetCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(min_length=8, max_length=32)
    title: str = Field(min_length=2, max_length=260)
    description: str = ""
    cvss: float = Field(default=0.0, ge=0, le=10)
    epss: float = Field(default=0.0, ge=0, le=1)
    kev: bool = False
    patch_available: bool = False
    published_at: str | None = None

    @field_validator("cve_id")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        return value.strip().upper()


class VulnerabilityRead(VulnerabilityCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)


class FindingCreate(BaseModel):
    asset_id: int
    vulnerability_id: int
    risk_owner: str = ""
    notes: str = ""


class FindingUpdate(BaseModel):
    status: str | None = None
    risk_owner: str | None = None
    compensating_control: str | None = None
    notes: str | None = None


class FindingRead(BaseModel):
    id: int
    status: str
    detected_at: datetime
    due_date: str | None
    compensating_control: str
    risk_owner: str
    notes: str
    risk_score: float
    risk_level: str
    sla_hours: int
    decision: str
    explanation: str
    asset: AssetRead
    vulnerability: VulnerabilityRead

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total_findings: int
    open_findings: int
    critical_findings: int
    high_findings: int
    kev_findings: int
    internet_exposed_findings: int
    average_risk_score: float
    assets_affected: int


class RiskPreviewRequest(BaseModel):
    cvss: float = Field(ge=0, le=10)
    epss: float = Field(ge=0, le=1)
    kev: bool = False
    patch_available: bool = False
    asset_criticality: int = Field(ge=1, le=5)
    internet_exposed: bool = False
    contains_sensitive_data: bool = False
    environment: str = "production"
    compensating_control: bool = False


class RiskPreviewResponse(BaseModel):
    score: float
    level: str
    sla_hours: int
    decision: str
    explanation: str
    factors: dict[str, float]
