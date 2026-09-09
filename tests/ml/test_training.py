"""
Unit Tests for ml.training.train (Training & Baseline Comparison)
================================================================

Tests that train.py trains models on 19 canonical features, compares baselines,
excludes metadata, saves valid artifacts and metadata, and that saved artifacts reload.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import pytest

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.training.synthetic_generator import generate_synthetic_dataset
from ml.training.train import (
    compare_models,
    load_dataset_split,
    save_artifacts,
)


@pytest.fixture(scope="module")
def sample_splits():
    """Create small train and validation splits for fast testing."""
    df = generate_synthetic_dataset(n_samples=200, random_state=42)
    train_df = df.iloc[:160]
    val_df = df.iloc[160:]

    with tempfile.TemporaryDirectory() as tmpdir:
        t_path = Path(tmpdir) / "train.csv"
        v_path = Path(tmpdir) / "val.csv"
        train_df.to_csv(t_path, index=False)
        val_df.to_csv(v_path, index=False)
        yield t_path, v_path


class TestTrainingPipeline:
    """Test model training, feature isolation, and baseline comparisons."""

    def test_load_dataset_split_excludes_metadata(self, sample_splits):
        t_path, _ = sample_splits
        X, y = load_dataset_split(t_path)

        assert X.shape[1] == 19
        assert list(X.columns) == ALL_FEATURES
        assert "risk_label" not in X.columns
        for meta in ["analysis_id", "session_id", "scenario_id", "data_source"]:
            assert meta not in X.columns

    def test_compare_models_evaluates_all_candidates(self, sample_splits):
        t_path, v_path = sample_splits
        X_train, y_train = load_dataset_split(t_path)
        X_val, y_val = load_dataset_split(v_path)

        best_name, report, fitted_pipes = compare_models(
            X_train, y_train, X_val, y_val, random_state=42, n_estimators=50
        )

        assert "DummyClassifier" in report["validation_comparison"]
        assert "LogisticRegression" in report["validation_comparison"]
        assert "RandomForestClassifier" in report["validation_comparison"]

        assert best_name in fitted_pipes
        pipe = fitted_pipes[best_name]
        assert hasattr(pipe, "predict")

    def test_save_and_reload_artifacts(self, sample_splits):
        t_path, v_path = sample_splits
        X_train, y_train = load_dataset_split(t_path)
        X_val, y_val = load_dataset_split(v_path)

        best_name, report, fitted_pipes = compare_models(
            X_train, y_train, X_val, y_val, random_state=42, n_estimators=30
        )
        pipe = fitted_pipes[best_name]

        metadata = {
            "model_version": "test-v1",
            "schema_version": "1.0",
            "feature_count": 19,
            "feature_names": ALL_FEATURES,
            "label_classes": RISK_LABELS,
        }

        with tempfile.TemporaryDirectory() as out_dir:
            model_path = save_artifacts(pipe, metadata, report, out_dir)
            assert model_path.is_file()

            # Reload
            reloaded = joblib.load(model_path)
            preds = reloaded.predict(X_val.values[:5])
            assert len(preds) == 5

            meta_file = Path(out_dir) / "model_metadata.json"
            assert meta_file.is_file()
            with open(meta_file) as f:
                loaded_meta = json.load(f)
            assert loaded_meta["schema_version"] == "1.0"
