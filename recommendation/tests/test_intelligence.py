"""
End-to-end tests for SecureMailScope intelligence.
"""


from unittest import result

from recommendation.intelligence import (
    analyze_security_intelligence,
)

from recommendation.tests.sample_analysis import (
    DJANGO_ANALYSIS,
    ML_RESULT,
)


def test_full_security_intelligence_pipeline():

    result = analyze_security_intelligence(
        DJANGO_ANALYSIS,
        ML_RESULT,
    )

    assert result["security_intelligence_version"] == "1.0.0"

    assert result["model"]["name"] == (
        "securemailscope_random_forest"
    )

    assert result["model"]["version"] == "rf-v1"

    assert result["risk"]["ml_risk_level"] == "HIGH"

    assert result["risk"]["final_risk_level"] == "CRITICAL"
    assert result["risk"]["risk_adjusted"] is True
    assert (
        result["risk"]["adjustment_reason"]
        == "A deterministic security finding has higher severity than the ML prediction."
    )
    assert result["risk"]["confidence"] == 0.91

    assert result["risk"]["confidence_status"] == "HIGH"

    assert result["risk_summary"]["critical"] == 2
    assert result["risk_summary"]["high"] == 1
    assert result["risk_summary"]["medium"] == 0
    assert result["risk_summary"]["low"] == 0
    assert result["risk_summary"]["info"] == 2

    recommendations = result["recommendations"]

    assert len(recommendations) == 3

    assert recommendations[0]["priority"] == "CRITICAL"
    assert recommendations[1]["priority"] == "CRITICAL"
    assert recommendations[2]["priority"] == "HIGH"