"""
Tests for ml.feature_engineering.schema — canonical 19-feature schema.

Guarantees:
    - Exactly 19 features.
    - No duplicate feature names.
    - Stable, deterministic ordering.
    - Correct group membership.
    - Schema version is defined.
"""

from __future__ import annotations

import pytest

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    BINARY_FEATURES,
    CERT_FEATURES,
    COUNT_FEATURES,
    ENCRYPTION_FEATURES,
    FEATURE_COUNT,
    FINDING_TYPE_TO_FEATURE,
    PROTOCOL_FEATURES,
    RISK_LABELS,
    SCHEMA_VERSION,
    SESSION_SECURITY_FEATURES,
    SEVERITY_COUNT_FEATURES,
    TLS_QUALITY_FEATURES,
    VALID_PROTOCOLS,
    VALID_ENCRYPTION_MODES,
    VALID_TRI_STATE,
    VALID_SEVERITIES,
)


class TestFeatureCount:
    """Exactly 19 canonical MVP features must exist."""

    def test_feature_count_constant(self) -> None:
        assert FEATURE_COUNT == 19

    def test_all_features_length(self) -> None:
        assert len(ALL_FEATURES) == 19

    def test_all_features_matches_constant(self) -> None:
        assert len(ALL_FEATURES) == FEATURE_COUNT


class TestNoDuplicates:
    """Feature names must be unique."""

    def test_no_duplicate_feature_names(self) -> None:
        assert len(ALL_FEATURES) == len(set(ALL_FEATURES))


class TestStableOrder:
    """Feature order must be deterministic across imports."""

    EXPECTED_ORDER = [
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

    def test_exact_order(self) -> None:
        assert ALL_FEATURES == self.EXPECTED_ORDER

    def test_order_is_list(self) -> None:
        """Lists preserve insertion order; sets/frozensets do not."""
        assert isinstance(ALL_FEATURES, list)


class TestFeatureGroups:
    """Feature group slices must be consistent with ALL_FEATURES."""

    def test_binary_features_count(self) -> None:
        assert len(BINARY_FEATURES) == 15

    def test_count_features_count(self) -> None:
        assert len(COUNT_FEATURES) == 4

    def test_binary_plus_count_equals_all(self) -> None:
        assert BINARY_FEATURES + COUNT_FEATURES == ALL_FEATURES

    def test_encryption_features(self) -> None:
        assert ENCRYPTION_FEATURES == [
            "encryption_plaintext",
            "encryption_starttls",
            "encryption_implicit",
        ]

    def test_tls_quality_features(self) -> None:
        assert TLS_QUALITY_FEATURES == ["deprecated_tls", "weak_cipher"]

    def test_cert_features(self) -> None:
        assert CERT_FEATURES == [
            "expired_cert",
            "not_yet_valid_cert",
            "weak_key",
        ]

    def test_session_security_features(self) -> None:
        assert SESSION_SECURITY_FEATURES == [
            "auth_before_tls",
            "tls_upgrade_failed",
            "pfs_missing",
            "self_signed",
        ]

    def test_protocol_features(self) -> None:
        assert PROTOCOL_FEATURES == [
            "protocol_smtp",
            "protocol_imap",
            "protocol_pop3",
        ]

    def test_severity_count_features(self) -> None:
        assert SEVERITY_COUNT_FEATURES == [
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ]


class TestSchemaVersion:
    """Schema version must be defined."""

    def test_version_is_string(self) -> None:
        assert isinstance(SCHEMA_VERSION, str)

    def test_version_is_not_empty(self) -> None:
        assert len(SCHEMA_VERSION) > 0


class TestRiskLabels:
    """Risk labels must be correctly defined."""

    def test_risk_labels(self) -> None:
        assert RISK_LABELS == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestVocabularies:
    """Valid vocabulary sets are non-empty and contain expected values."""

    def test_valid_protocols(self) -> None:
        for p in ("SMTP", "IMAP", "POP3", "UNKNOWN"):
            assert p in VALID_PROTOCOLS

    def test_valid_encryption_modes(self) -> None:
        for m in ("PLAINTEXT", "STARTTLS", "STLS", "IMPLICIT_TLS", "UNKNOWN"):
            assert m in VALID_ENCRYPTION_MODES

    def test_valid_tri_state(self) -> None:
        assert VALID_TRI_STATE == frozenset({"YES", "NO", "UNKNOWN"})

    def test_valid_severities(self) -> None:
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert s in VALID_SEVERITIES


class TestFindingTypeMapping:
    """Finding-type → feature mapping must cover key finding types."""

    def test_mapping_not_empty(self) -> None:
        assert len(FINDING_TYPE_TO_FEATURE) > 0

    def test_all_mapped_features_are_canonical(self) -> None:
        feature_set = set(ALL_FEATURES)
        for feature_name in FINDING_TYPE_TO_FEATURE.values():
            assert feature_name in feature_set, (
                f"Mapped feature '{feature_name}' is not in ALL_FEATURES"
            )

    def test_known_aliases(self) -> None:
        assert FINDING_TYPE_TO_FEATURE["FAILED_STARTTLS"] == "tls_upgrade_failed"
        assert FINDING_TYPE_TO_FEATURE["FAILED_STLS"] == "tls_upgrade_failed"
        assert FINDING_TYPE_TO_FEATURE["AUTH_BEFORE_TLS"] == "auth_before_tls"
        assert FINDING_TYPE_TO_FEATURE["SELF_SIGNED_CERT"] == "self_signed"
