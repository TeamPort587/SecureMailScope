"""
SecureMailScope Risk Guard

Combines the ML risk prediction with deterministic security findings.

Core security rule:
A deterministic finding must never be downgraded by the ML model.

Example:
    ML risk       = LOW
    Finding       = CRITICAL
    Final risk    = CRITICAL
"""


# Higher number = more severe.
RISK_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def get_risk_value(risk_level):
    """
    Convert a risk level into a numeric severity value.

    Args:
        risk_level (str): LOW, MEDIUM, HIGH, or CRITICAL.

    Returns:
        int: Numeric severity.
    """
    if not risk_level:
        return 0

    return RISK_ORDER.get(str(risk_level).upper(), 0)


def normalize_risk_level(risk_level):
    """
    Normalize a risk level to uppercase.

    Unknown or missing values default to LOW.

    Args:
        risk_level (str): Risk level.

    Returns:
        str: Normalized risk level.
    """
    if not risk_level:
        return "LOW"

    normalized = str(risk_level).upper()

    if normalized not in RISK_ORDER:
        return "LOW"

    return normalized


def get_highest_finding_severity(findings):
    """
    Find the highest severity among deterministic findings.

    Args:
        findings (list): Findings from the Django analysis response.

    Returns:
        str: Highest observed severity.
    """
    if not findings:
        return "LOW"

    highest = "LOW"

    for finding in findings:
        severity = normalize_risk_level(
            finding.get("severity")
        )

        if get_risk_value(severity) > get_risk_value(highest):
            highest = severity

    return highest


def calculate_final_risk(ml_risk_level, findings):
    """
    Combine ML risk with deterministic finding severity.

    A higher-severity deterministic finding always wins over
    a lower ML prediction.

    Args:
        ml_risk_level (str): Risk predicted by the ML model.
        findings (list): Findings from Django.

    Returns:
        dict: Final risk decision.
    """

    ml_risk = normalize_risk_level(ml_risk_level)

    finding_risk = get_highest_finding_severity(findings)

    ml_value = get_risk_value(ml_risk)
    finding_value = get_risk_value(finding_risk)

    # Deterministic finding overrides ML when it is more severe.
    if finding_value > ml_value:
        return {
            "ml_risk_level": ml_risk,
            "final_risk_level": finding_risk,
            "risk_adjusted": True,
            "adjustment_reason": (
                "A deterministic security finding has higher "
                "severity than the ML prediction."
            ),
        }

    # Otherwise preserve the ML prediction.
    return {
        "ml_risk_level": ml_risk,
        "final_risk_level": ml_risk,
        "risk_adjusted": False,
        "adjustment_reason": None,
    }