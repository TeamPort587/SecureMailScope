"""
Tests for ml.feature_engineering.extractor — session feature extraction.

This is the most important test file: it covers every extraction rule,
edge case, and the UNKNOWN → NaN policy.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pytest

from ml.feature_engineering.extractor import (
    extract_all_sessions,
    extract_session_features,
    feature_vector_to_ordered_list,
)
from ml.feature_engineering.schema import ALL_FEATURES, FEATURE_COUNT


# ── Helpers ────────────────────────────────────────────────────────

def _is_nan(v: float) -> bool:
    return isinstance(v, float) and math.isnan(v)


# Freeze "now" for deterministic tests: 2026-06-15T12:00:00Z
NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_session(overrides: dict | None = None) -> dict:
    """Minimal valid SMTP STARTTLS session."""
    s = {
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
    if overrides:
        for key, val in overrides.items():
            if isinstance(val, dict) and isinstance(s.get(key), dict):
                s[key].update(val)
            else:
                s[key] = val
    return s


# ── Test vector size ───────────────────────────────────────────────

class TestVectorSize:
    def test_exactly_19_features(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert len(vec) == FEATURE_COUNT

    def test_feature_names_match_schema(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert set(vec.keys()) == set(ALL_FEATURES)


# ── Encryption features ───────────────────────────────────────────

class TestEncryptionFeatures:
    def test_starttls_session(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["encryption_plaintext"] == 0
        assert vec["encryption_starttls"] == 1
        assert vec["encryption_implicit"] == 0

    def test_plaintext_session(self) -> None:
        session = _make_session({"security": {"encryption_mode": "PLAINTEXT"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["encryption_plaintext"] == 1
        assert vec["encryption_starttls"] == 0
        assert vec["encryption_implicit"] == 0

    def test_implicit_tls_session(self) -> None:
        session = _make_session({"security": {"encryption_mode": "IMPLICIT_TLS"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["encryption_plaintext"] == 0
        assert vec["encryption_starttls"] == 0
        assert vec["encryption_implicit"] == 1

    def test_unknown_encryption(self) -> None:
        session = _make_session({"security": {"encryption_mode": "UNKNOWN"}})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["encryption_plaintext"])
        assert _is_nan(vec["encryption_starttls"])
        assert _is_nan(vec["encryption_implicit"])

    def test_stls_maps_to_starttls(self) -> None:
        session = _make_session({"security": {"encryption_mode": "STLS"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["encryption_starttls"] == 1


# ── TLS features ──────────────────────────────────────────────────

class TestDeprecatedTLS:
    def test_tls_10_deprecated(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.0", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["deprecated_tls"] == 1

    def test_tls_11_deprecated(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.1", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["deprecated_tls"] == 1

    def test_sslv3_deprecated(self) -> None:
        session = _make_session({"tls": {"version": "SSLv3", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["deprecated_tls"] == 1

    def test_tls_12_modern(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["deprecated_tls"] == 0

    def test_tls_13_modern(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["deprecated_tls"] == 0

    def test_tls_null_nan(self) -> None:
        session = _make_session({"tls": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["deprecated_tls"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "DEPRECATED_TLS", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["deprecated_tls"] == 1


# ── Weak cipher ────────────────────────────────────────────────────

class TestWeakCipher:
    def test_strong_cipher(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["weak_cipher"] == 0

    def test_rc4_weak(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["weak_cipher"] == 1

    def test_3des_weak(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["weak_cipher"] == 1

    def test_null_cipher_weak(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_NULL_SHA", "pfs": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["weak_cipher"] == 1

    def test_tls_null_nan(self) -> None:
        session = _make_session({"tls": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["weak_cipher"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "WEAK_CIPHER", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["weak_cipher"] == 1


# ── Certificate features ──────────────────────────────────────────

class TestExpiredCert:
    def test_not_expired(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["expired_cert"] == 0

    def test_expired(self) -> None:
        session = _make_session({"certificate": {
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": "2021-01-01T00:00:00Z",
            "key_type": "RSA", "key_size": 2048, "self_signed": False,
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["expired_cert"] == 1

    def test_cert_null_nan(self) -> None:
        session = _make_session({"certificate": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["expired_cert"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "EXPIRED_CERT", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["expired_cert"] == 1


class TestNotYetValidCert:
    def test_valid_now(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["not_yet_valid_cert"] == 0

    def test_future_valid_from(self) -> None:
        session = _make_session({"certificate": {
            "valid_from": "2030-01-01T00:00:00Z",
            "valid_until": "2031-01-01T00:00:00Z",
            "key_type": "RSA", "key_size": 2048, "self_signed": False,
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["not_yet_valid_cert"] == 1

    def test_cert_null_nan(self) -> None:
        session = _make_session({"certificate": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["not_yet_valid_cert"])


class TestWeakKey:
    def test_rsa_2048_strong(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["weak_key"] == 0

    def test_rsa_1024_weak(self) -> None:
        session = _make_session({"certificate": {
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "key_type": "RSA", "key_size": 1024, "self_signed": False,
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["weak_key"] == 1

    def test_cert_null_nan(self) -> None:
        session = _make_session({"certificate": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["weak_key"])

    def test_non_rsa_nan(self) -> None:
        session = _make_session({"certificate": {
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "key_type": "ECDSA", "key_size": 256, "self_signed": False,
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["weak_key"])


# ── Session security features ────────────────────────────────────

class TestAuthBeforeTLS:
    def test_no_auth_before_tls(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["auth_before_tls"] == 0

    def test_auth_before_tls_yes(self) -> None:
        session = _make_session({"security": {"authentication_before_tls": "YES"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["auth_before_tls"] == 1

    def test_auth_before_tls_unknown(self) -> None:
        session = _make_session({"security": {"authentication_before_tls": "UNKNOWN"}})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["auth_before_tls"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "AUTH_BEFORE_TLS", "severity": "CRITICAL"}]
        session = _make_session()
        vec = extract_session_features(session, findings, now=NOW)
        assert vec["auth_before_tls"] == 1


class TestTLSUpgradeFailed:
    def test_successful_upgrade(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["tls_upgrade_failed"] == 0

    def test_failed_upgrade(self) -> None:
        session = _make_session({"security": {
            "upgrade_advertised": "YES",
            "upgrade_requested": "NO",
            "upgrade_succeeded": "NO",
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["tls_upgrade_failed"] == 1

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "FAILED_STARTTLS", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["tls_upgrade_failed"] == 1

    def test_failed_stls_finding(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "FAILED_STLS", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["tls_upgrade_failed"] == 1


class TestPFSMissing:
    def test_pfs_yes(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["pfs_missing"] == 0

    def test_pfs_no(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384", "pfs": "NO"}})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["pfs_missing"] == 1

    def test_pfs_unknown(self) -> None:
        session = _make_session({"tls": {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384", "pfs": "UNKNOWN"}})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["pfs_missing"])

    def test_tls_null_nan(self) -> None:
        session = _make_session({"tls": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["pfs_missing"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "PFS_MISSING", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["pfs_missing"] == 1


class TestSelfSigned:
    def test_not_self_signed(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["self_signed"] == 0

    def test_self_signed(self) -> None:
        session = _make_session({"certificate": {
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "key_type": "RSA", "key_size": 2048, "self_signed": True,
        }})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["self_signed"] == 1

    def test_cert_null_nan(self) -> None:
        session = _make_session({"certificate": None})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["self_signed"])

    def test_not_observable_nan(self) -> None:
        session = _make_session({"certificate": {"visibility": "NOT_OBSERVABLE"}})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["self_signed"])

    def test_finding_overrides(self) -> None:
        findings = [{"finding_id": "f1", "session_id": "smtp-001", "finding_type": "SELF_SIGNED_CERT", "severity": "HIGH"}]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["self_signed"] == 1


# ── Protocol features ─────────────────────────────────────────────

class TestProtocolFeatures:
    def test_smtp(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["protocol_smtp"] == 1
        assert vec["protocol_imap"] == 0
        assert vec["protocol_pop3"] == 0

    def test_imap(self) -> None:
        session = _make_session({"protocol": "IMAP"})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["protocol_smtp"] == 0
        assert vec["protocol_imap"] == 1
        assert vec["protocol_pop3"] == 0

    def test_pop3(self) -> None:
        session = _make_session({"protocol": "POP3"})
        vec = extract_session_features(session, [], now=NOW)
        assert vec["protocol_smtp"] == 0
        assert vec["protocol_imap"] == 0
        assert vec["protocol_pop3"] == 1

    def test_unknown_protocol(self) -> None:
        session = _make_session({"protocol": "UNKNOWN"})
        vec = extract_session_features(session, [], now=NOW)
        assert _is_nan(vec["protocol_smtp"])
        assert _is_nan(vec["protocol_imap"])
        assert _is_nan(vec["protocol_pop3"])


# ── Severity counts ───────────────────────────────────────────────

class TestSeverityCounts:
    def test_zero_counts_no_findings(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        assert vec["critical_count"] == 0
        assert vec["high_count"] == 0
        assert vec["medium_count"] == 0
        assert vec["low_count"] == 0

    def test_mixed_severities(self) -> None:
        findings = [
            {"finding_id": "f1", "session_id": "smtp-001", "finding_type": "X", "severity": "CRITICAL"},
            {"finding_id": "f2", "session_id": "smtp-001", "finding_type": "Y", "severity": "HIGH"},
            {"finding_id": "f3", "session_id": "smtp-001", "finding_type": "Z", "severity": "HIGH"},
            {"finding_id": "f4", "session_id": "smtp-001", "finding_type": "W", "severity": "LOW"},
        ]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["critical_count"] == 1
        assert vec["high_count"] == 2
        assert vec["medium_count"] == 0
        assert vec["low_count"] == 1

    def test_info_not_counted(self) -> None:
        findings = [
            {"finding_id": "f1", "session_id": "smtp-001", "finding_type": "PFS", "severity": "INFO"},
        ]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["critical_count"] == 0
        assert vec["high_count"] == 0
        assert vec["medium_count"] == 0
        assert vec["low_count"] == 0

    def test_other_session_findings_excluded(self) -> None:
        """Findings belonging to other sessions must NOT be counted."""
        findings = [
            {"finding_id": "f1", "session_id": "smtp-001", "finding_type": "X", "severity": "CRITICAL"},
            {"finding_id": "f2", "session_id": "imap-001", "finding_type": "Y", "severity": "CRITICAL"},
            {"finding_id": "f3", "session_id": "pop3-001", "finding_type": "Z", "severity": "HIGH"},
        ]
        vec = extract_session_features(_make_session(), findings, now=NOW)
        assert vec["critical_count"] == 1
        assert vec["high_count"] == 0


# ── Multi-session extraction ──────────────────────────────────────

class TestExtractAllSessions:
    def test_multiple_sessions(self) -> None:
        analysis = {
            "sessions": [
                _make_session(),
                _make_session({"session_id": "imap-001", "protocol": "IMAP"}),
            ],
            "findings": [],
        }
        results = extract_all_sessions(analysis, now=NOW)
        assert len(results) == 2
        assert results[0]["session_id"] == "smtp-001"
        assert results[1]["session_id"] == "imap-001"

    def test_each_result_has_19_features(self) -> None:
        analysis = {
            "sessions": [_make_session()],
            "findings": [],
        }
        results = extract_all_sessions(analysis, now=NOW)
        # session_id + 19 features
        assert len(results[0]) == 20


# ── Feature order utility ─────────────────────────────────────────

class TestFeatureVectorToOrderedList:
    def test_ordered_list_length(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        ordered = feature_vector_to_ordered_list(vec)
        assert len(ordered) == FEATURE_COUNT

    def test_order_matches_schema(self) -> None:
        vec = extract_session_features(_make_session(), [], now=NOW)
        ordered = feature_vector_to_ordered_list(vec)
        for i, name in enumerate(ALL_FEATURES):
            if _is_nan(vec[name]):
                assert _is_nan(ordered[i])
            else:
                assert ordered[i] == vec[name]
