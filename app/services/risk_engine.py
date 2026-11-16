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
        return settings.sla_kev_exposed_hours
    return {
        "CRITICAL": settings.sla_critical_hours,
        "HIGH": settings.sla_high_hours,
        "MEDIUM": settings.sla_medium_hours,
        "LOW": settings.sla_low_hours,
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


def methodology() -> dict:
    """Public description of the model: what a CISO would show an auditor or a COMEX."""
    return {
        "weights": {
            "cvss": settings.weight_cvss, "epss": settings.weight_epss, "known_exploited": settings.weight_kev,
            "ransomware_use": settings.weight_ransomware, "asset_criticality": settings.weight_criticality,
            "internet_exposure": settings.weight_exposure, "sensitive_data": settings.weight_data,
            "production": settings.weight_production, "patch_available": settings.weight_patch,
            "compensating_control": settings.weight_control,
        },
        "bands": {"CRITICAL": settings.risk_critical_threshold, "HIGH": settings.risk_high_threshold,
                  "MEDIUM": settings.risk_medium_threshold, "LOW": 0},
        "sla_hours": {"KEV_AND_INTERNET_EXPOSED": settings.sla_kev_exposed_hours, "CRITICAL": settings.sla_critical_hours,
                      "HIGH": settings.sla_high_hours, "MEDIUM": settings.sla_medium_hours, "LOW": settings.sla_low_hours},
        "principles": [
            "Technical severity matters but is not sufficient.",
            "Exploitation likelihood (EPSS) and observed exploitation (KEV, ransomware) carry large weights.",
            "Business context (criticality, exposure, data, environment) moves a vulnerability up or down.",
            "Compensating controls reduce urgency without making the risk disappear.",
            "SLA deadlines are anchored on the detection date, not on the last rescoring.",
        ],
        "disclaimer": "Educational, explainable model — not an industry standard.",
    }


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
    ransomware_use: bool = False,
) -> RiskResult:
    """Business-oriented vulnerability prioritization (explainable weighted model)."""
    factors = {
        "cvss": round((cvss / 10.0) * settings.weight_cvss, 2),
        "epss": round(epss * settings.weight_epss, 2),
        "known_exploited": settings.weight_kev if kev else 0.0,
        "ransomware_use": settings.weight_ransomware if ransomware_use else 0.0,
        "asset_criticality": round(((asset_criticality - 1) / 4.0) * settings.weight_criticality, 2),
        "internet_exposure": settings.weight_exposure if internet_exposed else 0.0,
        "sensitive_data": settings.weight_data if contains_sensitive_data else 0.0,
        "production": settings.weight_production if environment.lower() == "production" else 0.0,
        "patch_available": settings.weight_patch if patch_available else 0.0,
        "compensating_control": settings.weight_control if compensating_control else 0.0,
    }

    score = round(_clamp(sum(factors.values())), 1)
    level = _level(score)
    sla_hours = _sla(level, kev, internet_exposed)
    decision = _decision(level, patch_available)

    reasons: list[str] = []
    if kev:
        reasons.append("listed as known exploited")
    if ransomware_use:
        reasons.append("used in ransomware campaigns")
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
        f"{level} risk ({score}/100). Recommended action: {decision}. Key factors: "
        + ", ".join(reasons)
        + f". Target remediation SLA: {sla_hours} hours."
    )
    return RiskResult(score=score, level=level, sla_hours=sla_hours, decision=decision,
                      explanation=explanation, factors=factors)
