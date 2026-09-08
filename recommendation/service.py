"""
SecureMailScope Intelligence Service

Combines:
    - Django analysis findings
    - ML risk result
    - Risk guardrails
    - Recommendation engine

This module produces the final security intelligence
object consumed by the Node.js API layer.
"""


from .engine import generate_recommendations
from .priority import sort_recommendations
from .risk_guard import calculate_final_risk
from .models import RiskSummary


def validate_django_analysis(django_analysis):
    """Validate the Django analysis payload."""
    if not isinstance(django_analysis, dict):
        raise ValueError("INVALID_INPUT: django_analysis must be a dictionary")

    findings = django_analysis.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("INVALID_INPUT: findings must be a list")

    summary = django_analysis.get("summary", {})
    if not isinstance(summary, dict):
        raise ValueError("INVALID_INPUT: summary must be a dictionary")


def validate_ml_result(ml_result):
    """Validate the ML risk result payload."""
    if not isinstance(ml_result, dict):
        raise ValueError("INVALID_INPUT: ml_result must be a dictionary")

    ml_risk_level = ml_result.get("ml_risk_level")
    if not ml_risk_level:
        raise ValueError("INVALID_INPUT: ml_risk_level is required")

    model = ml_result.get("model", {})
    if model is not None and not isinstance(model, dict):
        raise ValueError("INVALID_INPUT: model must be a dictionary")


def build_risk_summary(findings):
    """
    Build a count of findings grouped by severity.

    Args:
        findings (list): Findings from the Django analysis response.

    Returns:
        dict: Finding counts by severity.
    """

    summary = RiskSummary()

    for finding in findings or []:
        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        if severity == "CRITICAL":
            summary.critical += 1

        elif severity == "HIGH":
            summary.high += 1

        elif severity == "MEDIUM":
            summary.medium += 1

        elif severity == "LOW":
            summary.low += 1

        elif severity == "INFO":
            summary.info += 1

    return summary.to_dict()


def build_security_intelligence(
    django_analysis,
    ml_result,
):
    """
    Build the final security intelligence result.

    Args:
        django_analysis (dict):
            Analysis response received from Django.

        ml_result (dict):
            Risk result received from the ML pipeline.

    Returns:
        dict: Final intelligence object for Node.js.
    """

    if not isinstance(django_analysis, dict):
        raise ValueError("INVALID_INPUT: django_analysis must be a dictionary")

    if not isinstance(ml_result, dict):
        raise ValueError("INVALID_INPUT: ml_result must be a dictionary")

    validate_django_analysis(django_analysis)
    validate_ml_result(ml_result)

    findings = django_analysis.get("findings", [])

    if not isinstance(findings, list):
        raise ValueError("INVALID_INPUT: findings must be a list")

    ml_risk_level = ml_result.get("ml_risk_level")

    if not ml_risk_level:
        raise ValueError("INVALID_INPUT: ml_risk_level is required")

    # ---------------------------------------------------------
    # 1. Apply deterministic risk guardrails
    # ---------------------------------------------------------

    risk_result = calculate_final_risk(
        ml_risk_level,
        findings,
    )

    # ---------------------------------------------------------
    # 2. Generate recommendations from deterministic findings
    # ---------------------------------------------------------

    recommendations = generate_recommendations(findings)

    # Ensure recommendations remain correctly prioritized.
    recommendations = sort_recommendations(
        recommendations
    )

    # ---------------------------------------------------------
    # 3. Build finding severity summary
    # ---------------------------------------------------------

    risk_summary = build_risk_summary(findings)

    # ---------------------------------------------------------
    # 4. Extract ML metadata
    # ---------------------------------------------------------

    model = ml_result.get(
        "model",
        {
            "name": "unknown",
            "version": "unknown",
        },
    )

    confidence = ml_result.get("confidence")

    # ---------------------------------------------------------
    # 5. Determine confidence status
    # ---------------------------------------------------------

    if confidence is None:
        confidence_status = "UNKNOWN"

    elif confidence >= 0.80:
        confidence_status = "HIGH"

    elif confidence >= 0.60:
        confidence_status = "MEDIUM"

    else:
        confidence_status = "LOW"

    # ---------------------------------------------------------
    # 6. Build final intelligence response
    # ---------------------------------------------------------

    return {
        "security_intelligence_version": "1.0.0",

        "model": {
            "name": model.get(
                "name",
                "unknown",
            ),
            "version": model.get(
                "version",
                "unknown",
            ),
        },

        "risk": {
            "ml_risk_level": risk_result["ml_risk_level"],
            "final_risk_level": risk_result["final_risk_level"],
            "risk_adjusted": risk_result["risk_adjusted"],
            "adjustment_reason": risk_result["adjustment_reason"],
            "confidence": confidence,
            "confidence_status": confidence_status,
        },

        "summary": django_analysis.get(
            "summary",
            {},
        ),

        "risk_summary": risk_summary,

        "recommendations": recommendations,
    }