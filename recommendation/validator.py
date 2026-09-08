REQUIRED_DJANGO_KEYS = {
    "analysis_version",
    "file",
    "summary",
    "sessions",
    "findings",
}

REQUIRED_ML_KEYS = {
    "ml_risk_level",
    "confidence",
    "model",
}


class ContractValidationError(ValueError):
    """Raised when an input contract is invalid."""


def validate_django_analysis(data):
    if not isinstance(data, dict):
        raise ContractValidationError(
            "INVALID_INPUT: Django analysis must be a dictionary."
        )

    missing = REQUIRED_DJANGO_KEYS - data.keys()

    if missing:
        raise ContractValidationError(
            f"INVALID_INPUT: Missing Django fields: {sorted(missing)}"
        )

    if not isinstance(data["sessions"], list):
        raise ContractValidationError(
            "INVALID_INPUT: sessions must be a list."
        )

    if not isinstance(data["findings"], list):
        raise ContractValidationError(
            "INVALID_INPUT: findings must be a list."
        )

    return True


def validate_ml_result(data):
    if not isinstance(data, dict):
        raise ContractValidationError(
            "INVALID_INPUT: ML result must be a dictionary."
        )

    missing = REQUIRED_ML_KEYS - data.keys()

    if missing:
        raise ContractValidationError(
            f"INVALID_INPUT: Missing ML fields: {sorted(missing)}"
        )

    if not isinstance(data["confidence"], (int, float)):
        raise ContractValidationError(
            "INVALID_INPUT: ML confidence must be numeric."
        )

    if not 0 <= data["confidence"] <= 1:
        raise ContractValidationError(
            "INVALID_INPUT: ML confidence must be between 0 and 1."
        )

    if not isinstance(data["model"], dict):
        raise ContractValidationError(
            "INVALID_INPUT: ML model must be a dictionary."
        )

    return True