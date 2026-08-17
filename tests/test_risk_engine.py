from app.services.risk_engine import calculate_risk


def test_critical_context_produces_high_priority():
    result = calculate_risk(
        cvss=9.8,
        epss=0.9,
        kev=True,
        patch_available=True,
        asset_criticality=5,
        internet_exposed=True,
        contains_sensitive_data=True,
        environment="production",
        compensating_control=False,
    )

    assert result.score >= 80
    assert result.level == "CRITICAL"
    assert result.sla_hours == 24
    assert result.decision == "PATCH IMMEDIATELY"
    assert "known exploited" in result.explanation


def test_low_context_remains_low_or_medium():
    result = calculate_risk(
        cvss=4.0,
        epss=0.01,
        kev=False,
        patch_available=False,
        asset_criticality=1,
        internet_exposed=False,
        contains_sensitive_data=False,
        environment="development",
        compensating_control=False,
    )

    assert result.score < 35
    assert result.level == "LOW"


def test_compensating_control_reduces_score():
    base = calculate_risk(
        cvss=8.0,
        epss=0.5,
        kev=False,
        patch_available=True,
        asset_criticality=4,
        internet_exposed=True,
        contains_sensitive_data=False,
        environment="production",
        compensating_control=False,
    )
    controlled = calculate_risk(
        cvss=8.0,
        epss=0.5,
        kev=False,
        patch_available=True,
        asset_criticality=4,
        internet_exposed=True,
        contains_sensitive_data=False,
        environment="production",
        compensating_control=True,
    )

    assert controlled.score < base.score
