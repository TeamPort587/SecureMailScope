"""
Unit Tests for Audit, Challenge Dataset, Risk Aggregator, and Cross-Validation
==============================================================================

Verifies that canonical risk aggregation strictly enforces domain semantics,
the challenge dataset is isolated from training, cross-validation executes properly,
and audit tools function accurately.
"""

from __future__ import annotations

from pathlib import Path
import pandas as pd
import pytest

from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.challenge_generator import generate_challenge_dataset
from ml.training.cross_validation import run_cross_validation
from ml.training.leakage_audit import audit_feature_label_relationships


class TestCanonicalRiskAggregator:
    """Test canonical risk aggregator semantics."""

    def test_critical_count_always_produces_critical(self):
        # Even with no other weaknesses
        features = {
            "critical_count": 1,
            "encryption_starttls": 1.0,
            "encryption_plaintext": 0.0,
            "encryption_implicit": 0.0,
        }
        label, reasons = calculate_session_risk(features)
        assert label == "CRITICAL"
        assert any("Active critical finding count" in r for r in reasons)

    def test_critical_can_exist_with_zero_critical_count(self):
        # Plaintext with zero critical findings
        features = {
            "critical_count": 0,
            "encryption_plaintext": 1.0,
            "encryption_starttls": 0.0,
            "encryption_implicit": 0.0,
        }
        label, reasons = calculate_session_risk(features)
        assert label == "CRITICAL"
        assert any("Unencrypted plaintext" in r for r in reasons)

    def test_auth_before_tls_produces_critical(self):
        features = {
            "critical_count": 0,
            "auth_before_tls": 1.0,
            "encryption_starttls": 1.0,
            "encryption_plaintext": 0.0,
            "encryption_implicit": 0.0,
        }
        label, _ = calculate_session_risk(features)
        assert label == "CRITICAL"

    def test_compounding_major_weaknesses_produce_critical_with_zero_crit_count(self):
        # Deprecated TLS + weak cipher + failed STARTTLS
        features = {
            "critical_count": 0,
            "high_count": 3,
            "encryption_starttls": 1.0,
            "encryption_plaintext": 0.0,
            "encryption_implicit": 0.0,
            "tls_upgrade_failed": 1.0,
            "deprecated_tls": 1.0,
            "weak_cipher": 1.0,
        }
        label, reasons = calculate_session_risk(features)
        assert label == "CRITICAL"
        assert any("Compounding high-severity failure" in r for r in reasons)

    def test_compounding_medium_weaknesses_produce_high(self):
        # self-signed + missing PFS
        features = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 2,
            "encryption_starttls": 1.0,
            "encryption_plaintext": 0.0,
            "encryption_implicit": 0.0,
            "self_signed": 1.0,
            "pfs_missing": 1.0,
        }
        label, reasons = calculate_session_risk(features)
        assert label == "HIGH"
        assert any("Compounding moderate weaknesses" in r for r in reasons)

    def test_clean_session_produces_low_with_optional_low_findings(self):
        features = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 2,
            "encryption_starttls": 1.0,
            "encryption_plaintext": 0.0,
            "encryption_implicit": 0.0,
            "deprecated_tls": 0.0,
            "weak_cipher": 0.0,
            "expired_cert": 0.0,
            "not_yet_valid_cert": 0.0,
            "weak_key": 0.0,
            "self_signed": 0.0,
            "auth_before_tls": 0.0,
            "tls_upgrade_failed": 0.0,
            "pfs_missing": 0.0,
        }
        label, reasons = calculate_session_risk(features)
        assert label == "LOW"


class TestChallengeDatasetIsolation:
    """Test challenge dataset generation and isolation from training."""

    def test_challenge_dataset_generation(self):
        df = generate_challenge_dataset(n_samples=50, random_state=99)
        assert len(df) > 0
        assert "data_source" in df.columns
        assert (df["data_source"] == "CHALLENGE_SYNTHETIC").all()

    def test_challenge_data_not_in_train(self):
        train_path = Path("data/processed/train.csv")
        challenge_path = Path("data/processed/challenge.csv")

        if train_path.is_file() and challenge_path.is_file():
            train_df = pd.read_csv(train_path)
            ch_df = pd.read_csv(challenge_path)

            train_sess_ids = set(train_df["session_id"])
            ch_sess_ids = set(ch_df["session_id"])

            assert len(train_sess_ids & ch_sess_ids) == 0, "Challenge sessions found in training set!"
            assert "CHALLENGE_SYNTHETIC" not in train_df["data_source"].values


class TestCrossValidation:
    """Test Stratified 5-Fold cross-validation helper."""

    def test_cross_validation_execution(self):
        train_path = Path("data/processed/train.csv")
        if train_path.is_file():
            report = run_cross_validation(train_path, n_splits=3, random_state=42)
            assert "models" in report
            assert "RandomForestClassifier" in report["models"]
            rf_stats = report["models"]["RandomForestClassifier"]
            assert "accuracy_mean" in rf_stats
            assert "macro_f1_mean" in rf_stats
            assert 0.0 <= rf_stats["accuracy_mean"] <= 1.0


class TestLeakageAuditFunctionality:
    """Test leakage audit functions."""

    def test_leakage_audit_detects_distribution(self):
        train_path = Path("data/processed/train.csv")
        if train_path.is_file():
            df = pd.read_csv(train_path)
            audit = audit_feature_label_relationships(df, leakage_threshold=0.90)
            assert "features" in audit
            assert "flagged_leakage_count" in audit
            assert len(audit["features"]) == 19
