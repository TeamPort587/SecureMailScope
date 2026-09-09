"""
Unit Tests for ml.training.synthetic_generator
==============================================

Tests that synthetic_generator generates valid, logically sound, balanced,
and reproducible datasets conforming to all domain rules and constraints.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.training.dataset_validator import validate_feature_row
from ml.training.synthetic_generator import generate_synthetic_dataset


@pytest.fixture(scope="module")
def synthetic_df():
    """Module-level fixture to avoid regenerating across multiple tests."""
    return generate_synthetic_dataset(n_samples=1600, random_state=42)


class TestSyntheticDatasetBasics:
    """Test general properties: sample size, classes, columns, reproducibility."""

    def test_sample_count(self, synthetic_df):
        assert len(synthetic_df) >= 1000
        assert len(synthetic_df) == 1600

    def test_all_columns_present(self, synthetic_df):
        expected_meta = [
            "analysis_id", "session_id", "scenario_id",
            "scenario_family", "data_source"
        ]
        for col in expected_meta:
            assert col in synthetic_df.columns, f"Missing metadata column: {col}"

        for feat in ALL_FEATURES:
            assert feat in synthetic_df.columns, f"Missing feature column: {feat}"

        assert "risk_label" in synthetic_df.columns

    def test_class_distribution_balanced(self, synthetic_df):
        counts = synthetic_df["risk_label"].value_counts()
        for label in RISK_LABELS:
            assert label in counts, f"Missing class {label}"
            # Expect approximately 400 (between 380 and 420)
            assert 380 <= counts[label] <= 420, f"Class {label} count {counts[label]} not balanced"

    def test_reproducibility(self):
        df1 = generate_synthetic_dataset(n_samples=100, random_state=42)
        df2 = generate_synthetic_dataset(n_samples=100, random_state=42)
        pd.testing.assert_frame_equal(df1, df2)

    def test_different_seed_produces_variation(self):
        df1 = generate_synthetic_dataset(n_samples=100, random_state=42)
        df2 = generate_synthetic_dataset(n_samples=100, random_state=99)
        # Should not be identical
        assert not df1.equals(df2)

    def test_scenario_family_diversity(self, synthetic_df):
        families = synthetic_df["scenario_family"].unique()
        assert len(families) >= 15, f"Expected at least 15 scenario families, got {len(families)}"


class TestSyntheticDatasetProtocolsAndEncryption:
    """Test protocol and encryption mode distributions."""

    def test_all_protocols_exist(self, synthetic_df):
        assert (synthetic_df["protocol_smtp"] == 1.0).sum() > 0
        assert (synthetic_df["protocol_imap"] == 1.0).sum() > 0
        assert (synthetic_df["protocol_pop3"] == 1.0).sum() > 0

    def test_protocol_one_hot_mutually_exclusive(self, synthetic_df):
        proto_sums = (
            synthetic_df["protocol_smtp"].fillna(0)
            + synthetic_df["protocol_imap"].fillna(0)
            + synthetic_df["protocol_pop3"].fillna(0)
        )
        assert (proto_sums == 1.0).all(), "Every row must have exactly one protocol active"

    def test_all_encryption_modes_exist(self, synthetic_df):
        assert (synthetic_df["encryption_plaintext"] == 1.0).sum() > 0
        assert (synthetic_df["encryption_starttls"] == 1.0).sum() > 0
        assert (synthetic_df["encryption_implicit"] == 1.0).sum() > 0

    def test_encryption_mode_mutually_exclusive(self, synthetic_df):
        enc_sums = (
            synthetic_df["encryption_plaintext"].fillna(0)
            + synthetic_df["encryption_starttls"].fillna(0)
            + synthetic_df["encryption_implicit"].fillna(0)
        )
        assert (enc_sums == 1.0).all(), "Every row must have exactly one encryption mode active"


class TestSyntheticDatasetConstraints:
    """Validate that every generated row conforms to the dataset validator."""

    def test_every_row_passes_validator(self, synthetic_df):
        invalid_rows = []
        for idx, row in synthetic_df.iterrows():
            is_valid, errors = validate_feature_row(row)
            if not is_valid:
                invalid_rows.append((idx, errors))

        assert len(invalid_rows) == 0, f"Found {len(invalid_rows)} invalid rows: {invalid_rows[:3]}"

    def test_no_negative_finding_counts(self, synthetic_df):
        for col in ["critical_count", "high_count", "medium_count", "low_count"]:
            assert (synthetic_df[col] >= 0).all()

    def test_feature_signature_diversity(self, synthetic_df):
        signatures = synthetic_df[ALL_FEATURES].apply(
            lambda r: tuple(r.fillna(-999.0)), axis=1
        )
        unique_sigs = signatures.nunique()
        # Ensure that rows are not just the same 4 rows duplicated
        assert unique_sigs >= 40, f"Expected at least 40 unique feature signatures, got {unique_sigs}"
