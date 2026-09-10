"""
Tests for SecureMailScope recommendation and risk logic.
"""


from recommendation.engine import generate_recommendations
from recommendation.risk_guard import calculate_final_risk
from recommendation.service import build_risk_summary


def test_auth_before_tls_generates_critical_recommendation():
    findings = [
        {
            "finding_id": "finding-001",
            "session_id": "smtp-002",
            "finding_type": "AUTH_BEFORE_TLS",
            "severity": "CRITICAL",
        }
    ]

    recommendations = generate_recommendations(findings)

    assert len(recommendations) == 1
    assert recommendations[0]["priority"] == "CRITICAL"
    assert recommendations[0]["recommendation_id"] == "REC-AUTH-TLS-001"


def test_duplicate_findings_are_deduplicated():
    findings = [
        {
            "finding_id": "finding-001",
            "session_id": "smtp-001",
            "finding_type": "PLAINTEXT",
            "severity": "CRITICAL",
        },
        {
            "finding_id": "finding-002",
            "session_id": "imap-001",
            "finding_type": "PLAINTEXT",
            "severity": "CRITICAL",
        },
    ]

    recommendations = generate_recommendations(findings)

    assert len(recommendations) == 1
    assert recommendations[0]["finding_count"] == 2
    assert len(recommendations[0]["affected_sessions"]) == 2


def test_recommendations_are_sorted_by_priority():
    findings = [
        {
            "finding_type": "NO_PFS",
            "session_id": "smtp-001",
            "severity": "MEDIUM",
        },
        {
            "finding_type": "FAILED_STARTTLS",
            "session_id": "smtp-002",
            "severity": "HIGH",
        },
        {
            "finding_type": "AUTH_BEFORE_TLS",
            "session_id": "smtp-003",
            "severity": "CRITICAL",
        },
    ]

    recommendations = generate_recommendations(findings)

    assert recommendations[0]["priority"] == "CRITICAL"
    assert recommendations[1]["priority"] == "HIGH"
    assert recommendations[2]["priority"] == "MEDIUM"


def test_critical_finding_overrides_low_ml_risk():
    findings = [
        {
            "finding_type": "AUTH_BEFORE_TLS",
            "severity": "CRITICAL",
        }
    ]

    result = calculate_final_risk(
        "LOW",
        findings,
    )

    assert result["ml_risk_level"] == "LOW"
    assert result["final_risk_level"] == "CRITICAL"
    assert result["risk_adjusted"] is True


def test_ml_risk_is_preserved_when_higher():
    findings = [
        {
            "finding_type": "NO_PFS",
            "severity": "MEDIUM",
        }
    ]

    result = calculate_final_risk(
        "HIGH",
        findings,
    )

    assert result["ml_risk_level"] == "HIGH"
    assert result["final_risk_level"] == "HIGH"
    assert result["risk_adjusted"] is False


def test_no_findings_does_not_raise_risk():
    result = calculate_final_risk(
        "LOW",
        [],
    )

    assert result["final_risk_level"] == "LOW"
    assert result["risk_adjusted"] is False


def test_risk_summary_counts_findings():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
        {"severity": "INFO"},
    ]

    summary = build_risk_summary(findings)

    assert summary["critical"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["info"] == 1