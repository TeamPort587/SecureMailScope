"""
Tests for guardrails — robustness against invalid/incomplete input.

Covers:
    - Missing model artifact.
    - Schema version mismatch.
    - Feature count / name mismatch.
    - All NaN features.
    - Too many unknown features (low evidence).
    - Invalid feature count.
    - Low evidence warnings.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import joblib
import numpy as np
import pytest

from ml.feature_engineering.encoder import build_pipeline, prepare_feature_matrix
from ml.feature_engineering.schema import (
    ALL_FEATURES,
    FEATURE_COUNT,
    QUALITY_LOW,
    QUALITY_SUFFICIENT,
    SCHEMA_VERSION,
)
from ml.inference.predictor import (
    FeatureCountMismatch,
    ModelLoadError,
    RiskPredictor,
    SchemaVersionMismatch,
    assess_prediction_quality,
)


# ── Helpers ────────────────────────────────────────────────────────

def _make_feature_vec(**overrides: float) -> dict:
    vec = {f: 0.0 for f in ALL_FEATURES}
    vec.update(overrides)
    return vec


def _save_model_with_metadata(
    output_dir: Path,
    metadata_overrides: dict | None = None,
) -> None:
    """Train and save a tiny model with optional metadata overrides."""
    rows = [
        _make_feature_vec(encryption_starttls=1, protocol_smtp=1),
        _make_feature_vec(encryption_plaintext=1, protocol_imap=1, critical_count=2),
        _make_feature_vec(encryption_implicit=1, protocol_pop3=1, high_count=1),
    ]
    labels = ["LOW", "CRITICAL", "HIGH"]

    mat = prepare_feature_matrix(rows)
    pipe = build_pipeline(n_estimators=10, random_state=42)
    pipe.fit(mat, labels)

    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, output_dir / "risk_model.joblib")

    metadata = {
        "model_version": "rf-v1",
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": ALL_FEATURES,
        "training_timestamp": "2026-01-01T00:00:00Z",
        "label_classes": ["CRITICAL", "HIGH", "LOW"],
        "training_rows": 3,
        "test_rows": 0,
        "random_state": 42,
    }
    if metadata_overrides:
        metadata.update(metadata_overrides)

    with open(output_dir / "model_metadata.json", "w") as f:
        json.dump(metadata, f)


# ── Missing model ─────────────────────────────────────────────────

class TestMissingModel:
    def test_missing_model_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ModelLoadError, match="not found"):
            RiskPredictor(tmp_path / "nonexistent")

    def test_missing_metadata_raises(self, tmp_path: Path) -> None:
        d = tmp_path / "no_meta"
        d.mkdir()
        # Create a dummy model file but no metadata
        joblib.dump("not_a_pipeline", d / "risk_model.joblib")
        with pytest.raises(ModelLoadError, match="metadata"):
            RiskPredictor(d)


# ── Schema mismatch ───────────────────────────────────────────────

class TestSchemaMismatch:
    def test_wrong_schema_version(self, tmp_path: Path) -> None:
        d = tmp_path / "bad_schema"
        _save_model_with_metadata(d, {"schema_version": "99.99"})
        with pytest.raises(SchemaVersionMismatch):
            RiskPredictor(d)

    def test_wrong_feature_count(self, tmp_path: Path) -> None:
        d = tmp_path / "bad_count"
        _save_model_with_metadata(d, {"feature_count": 42})
        with pytest.raises(FeatureCountMismatch):
            RiskPredictor(d)

    def test_wrong_feature_names(self, tmp_path: Path) -> None:
        d = tmp_path / "bad_names"
        _save_model_with_metadata(d, {"feature_names": ["wrong_feature"] * 19})
        with pytest.raises(FeatureCountMismatch):
            RiskPredictor(d)


# ── Evidence quality ──────────────────────────────────────────────

class TestEvidenceQuality:
    def test_all_nan_features_low_evidence(self) -> None:
        """If ALL binary features are NaN, prediction_quality = LOW_EVIDENCE."""
        vec = {f: float("nan") for f in ALL_FEATURES}
        quality, warnings = assess_prediction_quality(vec)
        assert quality == QUALITY_LOW

    def test_all_present_sufficient(self) -> None:
        vec = _make_feature_vec()
        quality, warnings = assess_prediction_quality(vec)
        assert quality == QUALITY_SUFFICIENT

    def test_tls_unavailable_warning(self) -> None:
        vec = _make_feature_vec(
            deprecated_tls=float("nan"),
            weak_cipher=float("nan"),
            pfs_missing=float("nan"),
        )
        _, warnings = assess_prediction_quality(vec)
        assert "TLS details unavailable" in warnings

    def test_cert_unavailable_warning(self) -> None:
        vec = _make_feature_vec(
            expired_cert=float("nan"),
            not_yet_valid_cert=float("nan"),
            weak_key=float("nan"),
            self_signed=float("nan"),
        )
        _, warnings = assess_prediction_quality(vec)
        assert "Certificate details unavailable" in warnings

    def test_encryption_unknown_warning(self) -> None:
        vec = _make_feature_vec(
            encryption_plaintext=float("nan"),
            encryption_starttls=float("nan"),
            encryption_implicit=float("nan"),
        )
        _, warnings = assess_prediction_quality(vec)
        assert "Encryption mode unknown" in warnings

    def test_protocol_unknown_warning(self) -> None:
        vec = _make_feature_vec(
            protocol_smtp=float("nan"),
            protocol_imap=float("nan"),
            protocol_pop3=float("nan"),
        )
        _, warnings = assess_prediction_quality(vec)
        assert "Protocol unknown" in warnings

    def test_low_evidence_threshold(self) -> None:
        """If >50% of 15 binary features are NaN, quality is LOW."""
        # Set 8 out of 15 binary features to NaN (53%)
        from ml.feature_engineering.schema import BINARY_FEATURES
        vec = _make_feature_vec()
        for i, feat in enumerate(BINARY_FEATURES):
            if i < 8:
                vec[feat] = float("nan")
        quality, _ = assess_prediction_quality(vec)
        assert quality == QUALITY_LOW

    def test_just_under_threshold_sufficient(self) -> None:
        """If exactly 7 of 15 binary features are NaN (46.7%), still sufficient."""
        from ml.feature_engineering.schema import BINARY_FEATURES
        vec = _make_feature_vec()
        for i, feat in enumerate(BINARY_FEATURES):
            if i < 7:
                vec[feat] = float("nan")
        quality, _ = assess_prediction_quality(vec)
        assert quality == QUALITY_SUFFICIENT


# ── Prediction with low evidence ──────────────────────────────────

class TestPredictionWithLowEvidence:
    """Even with low evidence, the model should still return a prediction
    (but clearly marked as low evidence)."""

    def test_low_evidence_prediction_still_works(self, tmp_path: Path) -> None:
        d = tmp_path / "model"
        _save_model_with_metadata(d)
        predictor = RiskPredictor(d)

        # Session with almost nothing — tls=null, cert=null, protocol=UNKNOWN
        session = {
            "session_id": "unknown-001",
            "protocol": "UNKNOWN",
            "security": {
                "encryption_mode": "UNKNOWN",
                "upgrade_advertised": "UNKNOWN",
                "upgrade_requested": "UNKNOWN",
                "upgrade_succeeded": "UNKNOWN",
                "authentication_before_tls": "UNKNOWN",
            },
            "tls": None,
            "certificate": None,
        }

        result = predictor.predict_session(session, [])
        assert result["risk"]["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert result["risk"]["prediction_quality"] == QUALITY_LOW
        assert len(result["warnings"]) > 0

    def test_low_evidence_json_serializable(self, tmp_path: Path) -> None:
        d = tmp_path / "model"
        _save_model_with_metadata(d)
        predictor = RiskPredictor(d)

        session = {
            "session_id": "unknown-001",
            "protocol": "UNKNOWN",
            "security": {"encryption_mode": "UNKNOWN"},
            "tls": None,
            "certificate": None,
        }

        result = predictor.predict_session(session, [])
        # Must not raise (NaN must be converted to None)
        json.dumps(result)
