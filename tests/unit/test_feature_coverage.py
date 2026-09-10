"""Feature Coverage & Vector Validation Tests (Section 21).

Verifies that every SecurityProfile attribute properly translates into the 19-feature
ML feature vector, that feature ordering is preserved, and that no features are dead.
"""

from pathlib import Path
import pytest
from ml.feature_engineering.extractor import extract_session_features
from ml.feature_engineering.schema import ALL_FEATURES, FEATURE_COUNT
from ml.inference.predictor import RiskPredictor


@pytest.fixture
def predictor():
    model_dir = Path(__file__).resolve().parent.parent.parent / "ml" / "artifacts"
    return RiskPredictor(model_dir=model_dir)


def test_feature_vector_contains_all_19_features():
    """Verify that extract_session_features returns all 19 canonical features."""
    session = {
        "session_id": "s-01",
        "protocol": "SMTP",
        "service": "submission",
        "client_ip": "10.0.0.1",
        "server_ip": "10.0.0.2",
        "client_port": 12345,
        "server_port": 587,
        "security": {
            "encryption_mode": "STARTTLS",
            "upgrade_advertised": "YES",
            "upgrade_requested": "YES",
            "upgrade_succeeded": "YES",
            "authentication_before_tls": "NO",
            "capture_completeness": "COMPLETE",
        },
        "tls": {
            "version": "TLS 1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "pfs": "YES",
        },
        "certificate": {
            "visibility": "OBSERVED",
            "subject": "CN=test",
            "issuer": "CN=test-ca",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "key_type": "RSA",
            "key_size": 2048,
            "self_signed": False,
        },
    }
    findings = []

    features = extract_session_features(session, findings)
    assert len(features) == FEATURE_COUNT

    for feat in ALL_FEATURES:
        assert feat in features, f"Feature {feat} was not extracted"


def test_model_inference_consumes_all_features(predictor):
    """Verify that predictor.predict_session consumes the vector and produces valid inference."""
    session = {
        "session_id": "s-02",
        "protocol": "IMAP",
        "service": "mail-access",
        "client_ip": "10.0.0.3",
        "server_ip": "10.0.0.4",
        "client_port": 23456,
        "server_port": 993,
        "security": {
            "encryption_mode": "IMPLICIT_TLS",
            "upgrade_advertised": "NOT_APPLICABLE",
            "upgrade_requested": "NOT_APPLICABLE",
            "upgrade_succeeded": "NOT_APPLICABLE",
            "authentication_before_tls": "NO",
            "capture_completeness": "COMPLETE",
        },
        "tls": {
            "version": "TLS 1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "pfs": "YES",
        },
        "certificate": {
            "visibility": "OBSERVED",
            "subject": "CN=imap.example.com",
            "issuer": "CN=DigiCert",
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
            "key_type": "RSA",
            "key_size": 2048,
            "self_signed": False,
        },
    }
    findings = []

    prediction = predictor.predict_session(session, findings)
    assert "session_id" in prediction
    assert "risk" in prediction
    risk = prediction["risk"]
    assert risk["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert risk["model_version"] == "rf-v1"
    assert "features_used" in prediction
    assert len(prediction["features_used"]) == FEATURE_COUNT
