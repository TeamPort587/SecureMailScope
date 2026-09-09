"""
Unit Tests for Realism, Robustness, Confidence, and Interaction Analysis
========================================================================

Tests:
1. interaction_analysis: Pairwise purity analysis, legitimate domain rules vs shortcuts.
2. robustness_evaluation: Perturbation testing under missing certs, partial captures, and boundary cases.
3. confidence_evaluation: Probability calibration, multiclass Brier scores, and calibration bins.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.training.synthetic_generator import generate_synthetic_dataset
from ml.training.challenge_generator import generate_challenge_dataset
from ml.training.interaction_analysis import analyze_feature_interactions
from ml.training.robustness_evaluation import (
    evaluate_missing_evidence_robustness,
    evaluate_partial_capture_robustness,
    evaluate_boundary_robustness,
    evaluate_rare_combination_robustness,
)
from ml.training.confidence_evaluation import (
    analyze_split_confidence,
    compute_multiclass_brier_score,
)


@pytest.fixture(scope="module")
def small_datasets_and_model():
    """Create small synthetic and challenge datasets and a fitted model pipeline."""
    df_train = generate_synthetic_dataset(n_samples=160, random_state=42)
    df_test = generate_synthetic_dataset(n_samples=80, random_state=123)
    df_chal = generate_challenge_dataset(n_samples=40, random_state=999)

    pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("classifier", RandomForestClassifier(n_estimators=30, random_state=42)),
    ])
    pipe.fit(df_train[ALL_FEATURES].values, df_train["risk_label"].values)

    return df_train, df_test, df_chal, pipe


class TestInteractionAnalysis:
    """Test pairwise feature interaction analysis."""

    def test_interaction_analysis_structure(self, small_datasets_and_model):
        df_train, _, _, _ = small_datasets_and_model
        report = analyze_feature_interactions(df_train, purity_threshold=0.90, min_samples=5)

        assert "dataset_total_rows" in report
        assert "purity_threshold" in report
        assert "total_flagged_interactions" in report
        assert "legitimate_domain_rules_count" in report
        assert "suspicious_shortcuts_count" in report
        assert isinstance(report["flagged_interactions"], list)

    def test_distinguishes_domain_rules(self, small_datasets_and_model):
        df_train, _, _, _ = small_datasets_and_model
        report = analyze_feature_interactions(df_train, purity_threshold=0.95, min_samples=5)

        for item in report["flagged_interactions"]:
            assert item["classification"] in ("LEGITIMATE_DOMAIN_RULE", "SUSPICIOUS_SYNTHETIC_SHORTCUT")
            assert "rationale" in item
            assert 0.0 <= item["purity"] <= 1.0


class TestRobustnessEvaluation:
    """Test robustness under controlled domain perturbations."""

    def test_missing_evidence_evaluation(self, small_datasets_and_model):
        _, df_test, _, pipe = small_datasets_and_model
        result = evaluate_missing_evidence_robustness(pipe, df_test)

        assert "samples_evaluated" in result
        assert "prediction_stability" in result
        assert "accuracy_against_derived_ground_truth" in result
        assert 0.0 <= result["prediction_stability"] <= 1.0

    def test_partial_capture_evaluation(self, small_datasets_and_model):
        _, df_test, _, pipe = small_datasets_and_model
        result = evaluate_partial_capture_robustness(pipe, df_test)

        assert "samples_evaluated" in result
        assert "accuracy_against_derived_ground_truth" in result
        assert 0.0 <= result["accuracy_against_derived_ground_truth"] <= 1.0

    def test_boundary_and_rare_robustness(self, small_datasets_and_model):
        _, df_test, df_chal, pipe = small_datasets_and_model
        boundary_res = evaluate_boundary_robustness(pipe, df_test, df_chal)
        rare_res = evaluate_rare_combination_robustness(pipe, df_chal)

        assert "boundary_accuracy" in boundary_res
        assert "rare_combination_accuracy" in rare_res


class TestConfidenceAndCalibration:
    """Test confidence distribution and calibration evaluation."""

    def test_brier_score_calculation(self):
        y_true = np.array(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        # Perfect probabilities
        classes = sorted(list(set(y_true)))
        y_proba_perfect = np.array([
            [0, 0, 1, 0], # LOW
            [0, 0, 0, 1], # MEDIUM
            [0, 1, 0, 0], # HIGH
            [1, 0, 0, 0], # CRITICAL
        ])
        brier = compute_multiclass_brier_score(y_true, y_proba_perfect, classes)
        assert brier == 0.0

    def test_split_confidence_metrics(self, small_datasets_and_model):
        _, df_test, _, pipe = small_datasets_and_model
        classes = sorted(list(pipe.classes_))
        conf_res = analyze_split_confidence(pipe, df_test, classes, name="test")

        assert "mean_max_probability" in conf_res
        assert "median_max_probability" in conf_res
        assert "brier_score" in conf_res
        assert "calibration_bins" in conf_res
        assert 0.0 <= conf_res["mean_max_probability"] <= 1.0
        assert 0.0 <= conf_res["brier_score"] <= 2.0
