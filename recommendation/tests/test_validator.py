import pytest  # type: ignore[import-not-found]

from recommendation.validator import (
    ContractValidationError,
    validate_django_analysis,
    validate_ml_result,
)

from recommendation.tests.sample_analysis import (
    DJANGO_ANALYSIS,
    ML_RESULT,
)


def test_valid_django_analysis_passes():
    assert validate_django_analysis(DJANGO_ANALYSIS) is True


def test_valid_ml_result_passes():
    assert validate_ml_result(ML_RESULT) is True


def test_missing_django_field_fails():
    invalid = DJANGO_ANALYSIS.copy()
    del invalid["findings"]

    with pytest.raises(ContractValidationError):
        validate_django_analysis(invalid)


def test_missing_ml_field_fails():
    invalid = ML_RESULT.copy()
    del invalid["ml_risk_level"]

    with pytest.raises(ContractValidationError):
        validate_ml_result(invalid)


def test_invalid_ml_confidence_fails():
    invalid = ML_RESULT.copy()
    invalid["confidence"] = 1.5

    with pytest.raises(ContractValidationError):
        validate_ml_result(invalid)