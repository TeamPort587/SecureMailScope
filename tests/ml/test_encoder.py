"""
Tests for ml.feature_engineering.encoder — preprocessing pipeline.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ml.feature_engineering.encoder import (
    build_pipeline,
    features_to_dataframe,
    prepare_feature_matrix,
)
from ml.feature_engineering.schema import ALL_FEATURES, FEATURE_COUNT


# ── Helpers ────────────────────────────────────────────────────────

def _make_feature_vec(**overrides: float) -> dict:
    """Create a canonical feature vector (all zeros by default)."""
    vec = {f: 0.0 for f in ALL_FEATURES}
    vec.update(overrides)
    return vec


# ── Pipeline construction ─────────────────────────────────────────

class TestBuildPipeline:
    def test_pipeline_has_two_steps(self) -> None:
        pipe = build_pipeline()
        assert len(pipe.steps) == 2

    def test_pipeline_step_names(self) -> None:
        pipe = build_pipeline()
        names = [name for name, _ in pipe.steps]
        assert names == ["imputer", "classifier"]

    def test_custom_params(self) -> None:
        pipe = build_pipeline(n_estimators=50, random_state=123)
        clf = pipe.named_steps["classifier"]
        assert clf.n_estimators == 50
        assert clf.random_state == 123


# ── DataFrame conversion ─────────────────────────────────────────

class TestFeaturesToDataframe:
    def test_column_count(self) -> None:
        df = features_to_dataframe([_make_feature_vec()])
        assert df.shape[1] == FEATURE_COUNT

    def test_column_order(self) -> None:
        df = features_to_dataframe([_make_feature_vec()])
        assert list(df.columns) == ALL_FEATURES

    def test_nan_preserved(self) -> None:
        vec = _make_feature_vec(deprecated_tls=float("nan"))
        df = features_to_dataframe([vec])
        assert math.isnan(df["deprecated_tls"].iloc[0])


# ── Matrix conversion ────────────────────────────────────────────

class TestPrepareFeatureMatrix:
    def test_shape(self) -> None:
        mat = prepare_feature_matrix([_make_feature_vec(), _make_feature_vec()])
        assert mat.shape == (2, FEATURE_COUNT)

    def test_nan_preserved(self) -> None:
        vec = _make_feature_vec(weak_cipher=float("nan"))
        mat = prepare_feature_matrix([vec])
        assert np.isnan(mat[0, ALL_FEATURES.index("weak_cipher")])


# ── Training/inference consistency ────────────────────────────────

class TestTrainingInferenceConsistency:
    """Verify that the pipeline produces identical preprocessing
    when fit on training data and then applied to inference data."""

    def test_fit_transform_consistency(self) -> None:
        # Training data: one row with NaN, one without
        train_vecs = [
            _make_feature_vec(deprecated_tls=float("nan"), encryption_starttls=1),
            _make_feature_vec(deprecated_tls=0, encryption_plaintext=1),
            _make_feature_vec(deprecated_tls=1, encryption_implicit=1),
        ]
        labels = ["LOW", "MEDIUM", "HIGH"]

        mat = prepare_feature_matrix(train_vecs)
        pipe = build_pipeline(n_estimators=10, random_state=42)
        pipe.fit(mat, labels)

        # Inference: single row with NaN
        inf_vec = _make_feature_vec(deprecated_tls=float("nan"))
        inf_mat = prepare_feature_matrix([inf_vec])

        # Pipeline must be able to predict without error
        predictions = pipe.predict(inf_mat)
        assert len(predictions) == 1
        assert predictions[0] in labels

    def test_exact_19_input_features(self) -> None:
        """Pipeline must accept exactly 19 input features."""
        vec = _make_feature_vec()
        mat = prepare_feature_matrix([vec])
        assert mat.shape[1] == 19
