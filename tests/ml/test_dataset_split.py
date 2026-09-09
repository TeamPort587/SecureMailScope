"""
Unit Tests for ml.training.dataset_builder (Splitting & Leakage Prevention)
==========================================================================

Tests that dataset splitting preserves class balance, prevents ID overlap,
tracks scenario families and leakage, and isolates metadata from model features.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.training.dataset_builder import (
    METADATA_COLUMNS,
    combine_datasets,
    generate_quality_report,
    split_dataset,
)
from ml.training.synthetic_generator import generate_synthetic_dataset


@pytest.fixture(scope="module")
def combined_sample_df():
    synth = generate_synthetic_dataset(n_samples=400, random_state=42)
    # Small real/demo mockup taking 4 valid rows (one per class)
    real_rows = []
    for label in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        row_match = synth[synth["risk_label"] == label].iloc[0].to_dict()
        row_match["analysis_id"] = f"real-pcap-{label.lower()}"
        row_match["session_id"] = f"real-sess-{label.lower()}"
        row_match["data_source"] = "DEMO"
        row_match["scenario_family"] = "DEMO_CAPTURE"
        real_rows.append(row_match)
    real_df = pd.DataFrame(real_rows)
    return combine_datasets(real_df, synth)


class TestDatasetSplitting:
    """Test train/validation/test split logic and properties."""

    def test_split_proportions(self, combined_sample_df):
        train_df, val_df, test_df, leakage = split_dataset(
            combined_sample_df,
            train_ratio=0.70,
            val_ratio=0.15,
            test_ratio=0.15,
            random_state=42,
        )
        total = len(combined_sample_df)
        assert len(train_df) + len(val_df) + len(test_df) == total

        # Approx 70/15/15
        assert abs(len(train_df) / total - 0.70) < 0.05
        assert abs(len(val_df) / total - 0.15) < 0.05
        assert abs(len(test_df) / total - 0.15) < 0.05

    def test_stratified_labels_in_all_splits(self, combined_sample_df):
        train_df, val_df, test_df, _ = split_dataset(combined_sample_df)

        for label in RISK_LABELS:
            assert label in train_df["risk_label"].values, f"Missing {label} in train"
            assert label in val_df["risk_label"].values, f"Missing {label} in validation"
            assert label in test_df["risk_label"].values, f"Missing {label} in test"

    def test_no_overlapping_sessions_between_splits(self, combined_sample_df):
        train_df, val_df, test_df, _ = split_dataset(combined_sample_df)

        train_ids = set(train_df["session_id"])
        val_ids = set(val_df["session_id"])
        test_ids = set(test_df["session_id"])

        assert len(train_ids & val_ids) == 0, "Overlap found between train and validation"
        assert len(train_ids & test_ids) == 0, "Overlap found between train and test"
        assert len(val_ids & test_ids) == 0, "Overlap found between validation and test"

    def test_metadata_separate_from_features(self, combined_sample_df):
        for meta in METADATA_COLUMNS:
            assert meta not in ALL_FEATURES, f"Metadata column {meta} found in ALL_FEATURES!"

        train_df, _, _, _ = split_dataset(combined_sample_df)
        # Ensure 19 features can be selected cleanly without metadata
        X_features = train_df[ALL_FEATURES]
        assert X_features.shape[1] == 19
        assert "risk_label" not in X_features.columns

    def test_scenario_leakage_report_generated(self, combined_sample_df):
        _, _, _, leakage = split_dataset(combined_sample_df)
        assert "strategy" in leakage
        assert "train_validation_overlap_families" in leakage
        assert "train_test_overlap_families" in leakage
        assert "data_source_distribution_per_split" in leakage
        assert "real_holdout_status" in leakage


class TestQualityReportGeneration:
    """Test full quality report construction."""

    def test_quality_report_structure(self, combined_sample_df):
        train_df, val_df, test_df, leakage = split_dataset(combined_sample_df)
        report = generate_quality_report(combined_sample_df, leakage_report=leakage)

        assert report["total_rows"] == len(combined_sample_df)
        assert "class_distribution" in report
        assert "class_distribution_note" in report
        assert "protocol_distribution" in report
        assert "encryption_distribution" in report
        assert "missing_value_rates" in report
        assert "unique_feature_signatures" in report
        assert "duplicate_feature_signature_rate" in report
        assert "validation" in report
        assert "finding_count_vs_risk_label_analysis" in report
        assert report["validation"]["invalid_rows"] == 0
