"""
Tests for ml.feature_engineering.validator — analysis JSON validation.

Covers:
    - Valid analysis structures.
    - Invalid protocol values.
    - Invalid tri-state values.
    - Null tls / certificate (allowed).
    - Empty findings (allowed).
    - Missing required fields.
    - Non-dict inputs.
"""

from __future__ import annotations

import copy
import pytest

from ml.feature_engineering.validator import (
    ValidationError,
    validate_analysis,
    validate_analysis_strict,
)


# ── Fixtures ───────────────────────────────────────────────────────

VALID_ANALYSIS: dict = {
    "analysis_version": "1.0.0",
    "sessions": [
        {
            "session_id": "smtp-001",
            "protocol": "SMTP",
            "security": {
                "encryption_mode": "STARTTLS",
                "upgrade_advertised": "YES",
                "upgrade_requested": "YES",
                "upgrade_succeeded": "YES",
                "authentication_before_tls": "NO",
            },
            "tls": {
                "version": "TLS 1.2",
                "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "pfs": "YES",
            },
            "certificate": {
                "subject": "CN=mail.example.com",
                "issuer": "Example CA",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "key_type": "RSA",
                "key_size": 2048,
                "self_signed": False,
            },
        }
    ],
    "findings": [
        {
            "finding_id": "finding-001",
            "session_id": "smtp-001",
            "finding_type": "PFS",
            "severity": "INFO",
        }
    ],
}


@pytest.fixture
def valid_analysis() -> dict:
    return copy.deepcopy(VALID_ANALYSIS)


# ── Valid analysis ─────────────────────────────────────────────────

class TestValidAnalysis:
    def test_no_errors(self, valid_analysis: dict) -> None:
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_strict_no_raise(self, valid_analysis: dict) -> None:
        validate_analysis_strict(valid_analysis)  # Should not raise

    def test_all_protocols_valid(self, valid_analysis: dict) -> None:
        for proto in ("SMTP", "IMAP", "POP3", "UNKNOWN"):
            valid_analysis["sessions"][0]["protocol"] = proto
            errors = validate_analysis(valid_analysis)
            assert errors == [], f"Protocol {proto} should be valid"

    def test_all_encryption_modes_valid(self, valid_analysis: dict) -> None:
        for mode in ("PLAINTEXT", "STARTTLS", "STLS", "IMPLICIT_TLS", "UNKNOWN"):
            valid_analysis["sessions"][0]["security"]["encryption_mode"] = mode
            errors = validate_analysis(valid_analysis)
            assert errors == [], f"Encryption mode {mode} should be valid"


# ── tls and certificate null (allowed) ─────────────────────────────

class TestNullableSections:
    def test_tls_null_allowed(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["tls"] = None
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_certificate_null_allowed(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["certificate"] = None
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_both_null_allowed(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["tls"] = None
        valid_analysis["sessions"][0]["certificate"] = None
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_certificate_not_observable(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["certificate"] = {"visibility": "NOT_OBSERVABLE"}
        errors = validate_analysis(valid_analysis)
        assert errors == []


# ── Empty findings ─────────────────────────────────────────────────

class TestFindings:
    def test_empty_findings_allowed(self, valid_analysis: dict) -> None:
        valid_analysis["findings"] = []
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_missing_findings_allowed(self, valid_analysis: dict) -> None:
        del valid_analysis["findings"]
        errors = validate_analysis(valid_analysis)
        assert errors == []

    def test_info_severity_allowed(self, valid_analysis: dict) -> None:
        valid_analysis["findings"][0]["severity"] = "INFO"
        errors = validate_analysis(valid_analysis)
        assert errors == []


# ── Invalid protocol ───────────────────────────────────────────────

class TestInvalidProtocol:
    def test_invalid_protocol_detected(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["protocol"] = "FTP"
        errors = validate_analysis(valid_analysis)
        assert len(errors) == 1
        assert "protocol" in errors[0].lower()

    def test_missing_protocol(self, valid_analysis: dict) -> None:
        del valid_analysis["sessions"][0]["protocol"]
        errors = validate_analysis(valid_analysis)
        assert len(errors) == 1
        assert "protocol" in errors[0].lower()


# ── Invalid tri-state values ──────────────────────────────────────

class TestInvalidTriState:
    def test_invalid_upgrade_advertised(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["security"]["upgrade_advertised"] = "MAYBE"
        errors = validate_analysis(valid_analysis)
        assert len(errors) == 1
        assert "tri-state" in errors[0].lower()

    def test_invalid_authentication_before_tls(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["security"]["authentication_before_tls"] = "TRUE"
        errors = validate_analysis(valid_analysis)
        assert len(errors) == 1
        assert "tri-state" in errors[0].lower()


# ── Invalid encryption mode ───────────────────────────────────────

class TestInvalidEncryptionMode:
    def test_invalid_encryption_mode(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["security"]["encryption_mode"] = "WPA2"
        errors = validate_analysis(valid_analysis)
        assert len(errors) == 1
        assert "encryption_mode" in errors[0]


# ── Structural errors ─────────────────────────────────────────────

class TestStructuralErrors:
    def test_not_a_dict_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_analysis("not a dict")

    def test_missing_sessions(self) -> None:
        errors = validate_analysis({"analysis_version": "1.0.0"})
        assert any("sessions" in e.lower() for e in errors)

    def test_sessions_not_list(self) -> None:
        data = {"sessions": "not a list"}
        errors = validate_analysis(data)
        assert any("list" in e.lower() for e in errors)

    def test_empty_sessions_list(self) -> None:
        data = {"sessions": []}
        errors = validate_analysis(data)
        assert any("empty" in e.lower() for e in errors)

    def test_session_not_dict(self) -> None:
        data = {"sessions": ["not a dict"]}
        errors = validate_analysis(data)
        assert len(errors) >= 1

    def test_missing_session_id(self, valid_analysis: dict) -> None:
        del valid_analysis["sessions"][0]["session_id"]
        errors = validate_analysis(valid_analysis)
        assert any("session_id" in e for e in errors)

    def test_invalid_finding_severity(self, valid_analysis: dict) -> None:
        valid_analysis["findings"][0]["severity"] = "SUPER_CRITICAL"
        errors = validate_analysis(valid_analysis)
        assert any("severity" in e for e in errors)

    def test_strict_raises_on_errors(self, valid_analysis: dict) -> None:
        valid_analysis["sessions"][0]["protocol"] = "FTP"
        with pytest.raises(ValidationError) as exc_info:
            validate_analysis_strict(valid_analysis)
        assert len(exc_info.value.errors) >= 1
