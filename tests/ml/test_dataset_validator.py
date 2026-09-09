"""
Unit Tests for ml.training.dataset_validator
============================================

Tests that dataset_validator correctly accepts logically sound feature
vectors and rejects invalid, contradictory, or impossible security combinations.
"""

from __future__ import annotations

import numpy as np
import pytest

from ml.feature_engineering.schema import ALL_FEATURES
from ml.training.dataset_validator import validate_feature_row, validate_dataset


def make_valid_row(
    protocol: str = "SMTP",
    encryption: str = "STARTTLS",
    risk_label: str = "LOW",
    **kwargs,
) -> dict:
    """Helper to create a valid base row."""
    row = {f: np.nan for f in ALL_FEATURES}

    # Protocol
    row["protocol_smtp"] = 1.0 if protocol == "SMTP" else 0.0
    row["protocol_imap"] = 1.0 if protocol == "IMAP" else 0.0
    row["protocol_pop3"] = 1.0 if protocol == "POP3" else 0.0

    # Encryption
    row["encryption_plaintext"] = 1.0 if encryption == "PLAINTEXT" else 0.0
    row["encryption_starttls"] = 1.0 if encryption == "STARTTLS" else 0.0
    row["encryption_implicit"] = 1.0 if encryption == "IMPLICIT_TLS" else 0.0

    # Default clean TLS / cert for STARTTLS
    if encryption in ("STARTTLS", "IMPLICIT_TLS"):
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["tls_upgrade_failed"] = 0.0

    # Counts
    row["critical_count"] = 0
    row["high_count"] = 0
    row["medium_count"] = 0
    row["low_count"] = 0

    row["risk_label"] = risk_label
    row.update(kwargs)
    return row


class TestDatasetValidatorPasses:
    """Tests for logically valid rows."""

    def test_valid_low_row(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW")
        is_valid, errors = validate_feature_row(row)
        assert is_valid, f"Expected valid, got errors: {errors}"

    def test_valid_medium_row(self):
        row = make_valid_row(
            "IMAP", "STARTTLS", "MEDIUM",
            self_signed=1.0, medium_count=1
        )
        is_valid, errors = validate_feature_row(row)
        assert is_valid, f"Expected valid, got errors: {errors}"

    def test_valid_high_row(self):
        row = make_valid_row(
            "POP3", "IMPLICIT_TLS", "HIGH",
            weak_cipher=1.0, high_count=1
        )
        is_valid, errors = validate_feature_row(row)
        assert is_valid, f"Expected valid, got errors: {errors}"

    def test_valid_critical_row(self):
        row = make_valid_row(
            "SMTP", "PLAINTEXT", "CRITICAL",
            auth_before_tls=1.0, critical_count=2
        )
        is_valid, errors = validate_feature_row(row)
        assert is_valid, f"Expected valid, got errors: {errors}"


class TestDatasetValidatorRejections:
    """Tests for invalid/contradictory rows."""

    def test_plaintext_with_deprecated_tls_must_fail(self):
        row = make_valid_row("SMTP", "PLAINTEXT", "CRITICAL", deprecated_tls=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("deprecated_tls" in e for e in errors)

    def test_plaintext_with_weak_cipher_must_fail(self):
        row = make_valid_row("SMTP", "PLAINTEXT", "CRITICAL", weak_cipher=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("weak_cipher" in e for e in errors)

    def test_plaintext_with_expired_cert_must_fail(self):
        row = make_valid_row("SMTP", "PLAINTEXT", "CRITICAL", expired_cert=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("expired_cert" in e for e in errors)

    def test_implicit_tls_with_tls_upgrade_failed_must_fail(self):
        row = make_valid_row("IMAP", "IMPLICIT_TLS", "HIGH", tls_upgrade_failed=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("tls_upgrade_failed" in e for e in errors)

    def test_implicit_tls_with_auth_before_tls_must_fail(self):
        row = make_valid_row("IMAP", "IMPLICIT_TLS", "CRITICAL", auth_before_tls=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("auth_before_tls" in e for e in errors)

    def test_expired_and_not_yet_valid_cert_simultaneously_must_fail(self):
        row = make_valid_row(
            "SMTP", "STARTTLS", "HIGH",
            expired_cert=1.0, not_yet_valid_cert=1.0, high_count=2
        )
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("both expired_cert = 1 and not_yet_valid_cert = 1" in e for e in errors)

    def test_multiple_protocols_must_fail(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW", protocol_imap=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("Protocol one-hot violation" in e for e in errors)

    def test_multiple_encryption_modes_must_fail(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW", encryption_plaintext=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("Encryption one-hot violation" in e for e in errors)

    def test_negative_counts_must_fail(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW", critical_count=-1)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("critical_count must be >= 0" in e for e in errors)

    def test_low_with_critical_count_must_fail(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW", critical_count=1)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("LOW label cannot have critical_count > 0" in e for e in errors)

    def test_low_with_weak_cipher_must_fail(self):
        row = make_valid_row("SMTP", "STARTTLS", "LOW", weak_cipher=1.0)
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("LOW label cannot have weak_cipher = 1" in e for e in errors)

    def test_medium_with_plaintext_must_fail(self):
        row = make_valid_row("SMTP", "PLAINTEXT", "MEDIUM")
        is_valid, errors = validate_feature_row(row)
        assert not is_valid
        assert any("MEDIUM label cannot be PLAINTEXT" in e for e in errors)
