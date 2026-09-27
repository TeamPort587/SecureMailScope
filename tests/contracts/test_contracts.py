"""Contract Tests for SecureMailScope Interfaces.

Validates schemas and contracts defined in docs/contracts/ across:
- Node -> Django request
- Django -> Node response
- ML feature vector
- ML risk result
- Node -> React response
"""

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, validate

CONTRACTS_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "contracts"


@pytest.fixture
def contract_node_django_request():
    with open(CONTRACTS_DIR / "node-django-request.json", "r") as f:
        return json.load(f)


@pytest.fixture
def contract_django_analysis_response():
    with open(CONTRACTS_DIR / "django-analysis-response.json", "r") as f:
        return json.load(f)


@pytest.fixture
def contract_ml_feature_vector():
    with open(CONTRACTS_DIR / "ml-feature-vector.json", "r") as f:
        return json.load(f)


@pytest.fixture
def contract_ml_risk_result():
    with open(CONTRACTS_DIR / "ml-session-risk-result.json", "r") as f:
        return json.load(f)


@pytest.fixture
def contract_node_react_response():
    with open(CONTRACTS_DIR / "node-react-analysis-response.json", "r") as f:
        return json.load(f)


def test_node_django_request_schema(contract_node_django_request):
    """Verify node-django request contains required payload fields."""
    req = contract_node_django_request
    assert "analysis_id" in req
    assert "filename" in req
    assert "sha256" in req
    assert "size_bytes" in req
    assert "analysis_version" in req
    assert isinstance(req["size_bytes"], int)
    assert len(req["sha256"]) == 64


def test_django_analysis_response_schema(contract_django_analysis_response):
    """Verify django-analysis-response conforms to contract structure."""
    resp = contract_django_analysis_response
    assert resp["analysis_version"] == "1.0.0"
    assert "file" in resp
    assert "summary" in resp
    assert "sessions" in resp
    assert "findings" in resp
    assert "risk" in resp
    assert "recommendations" in resp

    # Validate sessions structure
    for session in resp["sessions"]:
        assert "session_id" in session
        assert "protocol" in session
        assert session["protocol"] in ["SMTP", "IMAP", "POP3"]
        assert "security" in session
        sec = session["security"]
        assert "encryption_mode" in sec
        assert sec["encryption_mode"] in ["PLAINTEXT", "STARTTLS", "IMPLICIT_TLS", "UNKNOWN"]
        assert "capture_completeness" in sec

    # Validate findings structure
    for finding in resp["findings"]:
        assert "finding_id" in finding
        assert "finding_type" in finding
        assert "severity" in finding
        assert finding["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert "evidence" in finding
        assert isinstance(finding["evidence"], dict)

    # Validate risk structure
    risk = resp["risk"]
    assert "score" in risk
    assert "level" in risk
    assert risk["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert 0 <= risk["score"] <= 100
    assert "model_version" in risk

    # Validate recommendations structure
    for rec in resp["recommendations"]:
        assert "priority" in rec
        assert "title" in rec
        assert "description" in rec


def test_ml_feature_vector_schema(contract_ml_feature_vector):
    """Verify ML feature vector matches the 19 model features."""
    assert contract_ml_feature_vector["feature_count"] == 19
    features = contract_ml_feature_vector["example"]["features"]
    expected_fields = [
        "encryption_plaintext",
        "encryption_starttls",
        "encryption_implicit",
        "deprecated_tls",
        "weak_cipher",
        "expired_cert",
        "not_yet_valid_cert",
        "weak_key",
        "auth_before_tls",
        "tls_upgrade_failed",
        "pfs_missing",
        "self_signed",
        "protocol_smtp",
        "protocol_imap",
        "protocol_pop3",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
    ]
    for field in expected_fields:
        assert field in features, f"Missing expected ML feature: {field}"
    assert len(features) == 19


def test_ml_risk_result_schema(contract_ml_risk_result):
    """Verify ML risk result contract."""
    res = contract_ml_risk_result["example"]
    assert "session_id" in res
    assert "risk" in res
    risk = res["risk"]
    assert "level" in risk
    assert risk["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert 0.0 <= risk["confidence"] <= 1.0
    assert risk["model_version"] == "rf-v1"
    assert "features_used" in res
    assert len(res["features_used"]) == 19
