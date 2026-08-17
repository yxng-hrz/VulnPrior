from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    sla_hours: int
    decision: str
    explanation: str
    factors: dict[str, float]


def _clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(value, upper))


def _level(score: float) -> str:
    if score >= settings.risk_critical_threshold:
        return "CRITICAL"
    if score >= settings.risk_high_threshold:
        return "HIGH"
    if score >= settings.risk_medium_threshold:
        return "MEDIUM"
    return "LOW"


def _sla(level: str, kev: bool, internet_exposed: bool) -> int:
    if kev and internet_exposed:
        return 24
    return {
        "CRITICAL": 48,
        "HIGH": 168,
        "MEDIUM": 720,
        "LOW": 2160,
    }[level]


def _decision(level: str, patch_available: bool) -> str:
    if level == "CRITICAL" and patch_available:
        return "PATCH IMMEDIATELY"
    if level == "CRITICAL":
        return "MITIGATE / ISOLATE"
    if level == "HIGH" and patch_available:
        return "PATCH WITHIN SLA"
    if level == "HIGH":
        return "MITIGATE AND MONITOR"
    if level == "MEDIUM":
        return "PLAN REMEDIATION"
    return "MONITOR"


def calculate_risk(
    *,
    cvss: float,
    epss: float,
    kev: bool,
    patch_available: bool,
    asset_criticality: int,
    internet_exposed: bool,
    contains_sensitive_data: bool,
    environment: str = "production",
    compensating_control: bool = False,
) -> RiskResult:
    """
    Business-oriented vulnerability prioritization.

    Formula philosophy:
    - technical severity matters, but is not sufficient;
    - exploitation probability and known exploitation receive large weights;
    - business context can move a vulnerability up or down;
    - compensating controls reduce urgency without making the risk disappear.

    This is an educational model, not a replacement for an enterprise risk method.
    """
    cvss_factor = (cvss / 10.0) * 24.0
    epss_factor = epss * 24.0
    kev_factor = 18.0 if kev else 0.0
    criticality_factor = ((asset_criticality - 1) / 4.0) * 16.0
    exposure_factor = 8.0 if internet_exposed else 0.0
    data_factor = 5.0 if contains_sensitive_data else 0.0
    environment_factor = 3.0 if environment.lower() == "production" else 0.0
    patch_factor = 2.0 if patch_available else 0.0
    control_reduction = -12.0 if compensating_control else 0.0

    factors = {
        "cvss": round(cvss_factor, 2),
        "epss": round(epss_factor, 2),
        "known_exploited": round(kev_factor, 2),
        "asset_criticality": round(criticality_factor, 2),
        "internet_exposure": round(exposure_factor, 2),
        "sensitive_data": round(data_factor, 2),
        "production": round(environment_factor, 2),
        "patch_available": round(patch_factor, 2),
        "compensating_control": round(control_reduction, 2),
    }

    raw_score = sum(factors.values())
    score = round(_clamp(raw_score), 1)
    level = _level(score)
    sla_hours = _sla(level, kev, internet_exposed)
    decision = _decision(level, patch_available)

    reasons: list[str] = []
    if kev:
        reasons.append("listed as known exploited")
    if epss >= 0.5:
        reasons.append("high exploitation probability")
    if internet_exposed:
        reasons.append("internet-exposed asset")
    if asset_criticality >= 4:
        reasons.append("business-critical asset")
    if contains_sensitive_data:
        reasons.append("sensitive data exposure")
    if cvss >= 9:
        reasons.append("critical technical severity")
    if compensating_control:
        reasons.append("compensating control reduces urgency")

    if not reasons:
        reasons.append("limited exploitation and business context")

    explanation = (
        f"{level} risk ({score}/100). Recommended action: {decision}. "
        + "Key factors: "
        + ", ".join(reasons)
        + f". Target remediation SLA: {sla_hours} hours."
    )

    return RiskResult(
        score=score,
        level=level,
        sla_hours=sla_hours,
        decision=decision,
        explanation=explanation,
        factors=factors,
    )
