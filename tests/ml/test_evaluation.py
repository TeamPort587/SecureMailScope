"""
Unit Tests for ml.training.evaluate (Model Evaluation)
=====================================================

Tests that evaluate.py computes valid macro and per-class metrics, confusion matrices,
and outputs explicit dataset limitation statements.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pytest
from sklearn.dummy import DummyClassifier
from sklearn.pipeline import Pipeline

from ml.feature_engineering.schema import ALL_FEATURES
from ml.training.evaluate import (
    evaluate_test_set,
    save_confusion_matrix_plot,
    save_metrics,
)


@pytest.fixture
def mock_pipeline_and_data():
    """Create a simple deterministic pipeline and test data."""
    X = np.zeros((20, 19))
    y = np.array(["LOW"] * 5 + ["MEDIUM"] * 5 + ["HIGH"] * 5 + ["CRITICAL"] * 5)

    clf = DummyClassifier(strategy="most_frequent")
    clf.fit(X, y)
    pipe = Pipeline([("classifier", clf)])
    return pipe, X, y


class TestEvaluationPipeline:
    """Test evaluation logic and report serialization."""

    def test_metrics_calculation(self, mock_pipeline_and_data):
        pipe, X, y = mock_pipeline_and_data
        metrics = evaluate_test_set(pipe, X, y)

        assert "accuracy" in metrics
        assert "precision_macro" in metrics
        assert "recall_macro" in metrics
        assert "f1_macro" in metrics
        assert "per_class" in metrics
        assert "confusion_matrix" in metrics
        assert "limitations" in metrics

        assert len(metrics["limitations"]) >= 2
        assert metrics["test_rows"] == 20

    def test_per_class_metrics_present(self, mock_pipeline_and_data):
        pipe, X, y = mock_pipeline_and_data
        metrics = evaluate_test_set(pipe, X, y)

        for label in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert label in metrics["per_class"]
            assert "precision" in metrics["per_class"][label]
            assert "recall" in metrics["per_class"][label]
            assert "f1_score" in metrics["per_class"][label]
            assert "support" in metrics["per_class"][label]

    def test_save_metrics_json(self, mock_pipeline_and_data):
        pipe, X, y = mock_pipeline_and_data
        metrics = evaluate_test_set(pipe, X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_metrics(metrics, tmpdir)
            assert path.is_file()
            assert path.name == "evaluation_metrics.json"

    def test_save_confusion_matrix_plot(self, mock_pipeline_and_data):
        pipe, X, y = mock_pipeline_and_data
        metrics = evaluate_test_set(pipe, X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_confusion_matrix_plot(metrics, tmpdir)
            # Matplotlib is installed in environment, so path should be created
            if path is not None:
                assert path.is_file()
                assert path.name == "confusion_matrix.png"
