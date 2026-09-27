"""
Isolation Forest — Model Loader & Inference
=============================================

Loads pre-trained artifacts and runs session-level anomaly inference.
Provides a cached singleton pattern consistent with the existing
RiskPredictor in ml/inference/predictor.py.
"""

from __future__ import annotations

import json
import logging
import math
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    ANOMALY_CLASSIFICATION_ANOMALOUS,
    ANOMALY_CLASSIFICATION_BASELINE,
    ANOMALY_STATUS_COMPLETE,
    ANOMALY_STATUS_ERROR,
    ANOMALY_STATUS_INSUFFICIENT,
    ANOMALY_STATUS_UNAVAILABLE,
    IF_FEATURE_COUNT,
    IF_METADATA_FILENAME,
    IF_MODEL_FILENAME,
    IF_MODEL_VERSION,
    IF_SCHEMA_VERSION,
)
from analysis.anomaly_detection.preprocessing import AnomalyPreprocessor

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"


class AnomalyModelLoadError(Exception):
    """Raised when the IF model cannot be loaded."""


class AnomalyPredictor:
    """Loads a pre-trained Isolation Forest and runs anomaly inference."""

    def __init__(self, artifact_dir: Optional[Path] = None) -> None:
        self.artifact_dir = Path(artifact_dir) if artifact_dir else DEFAULT_ARTIFACT_DIR
        self.model: Any = None
        self.preprocessor: Optional[AnomalyPreprocessor] = None
        self.metadata: Dict[str, Any] = {}
        self.baseline_stats: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load model, preprocessor, and metadata."""
        model_path = self.artifact_dir / IF_MODEL_FILENAME
        meta_path = self.artifact_dir / IF_METADATA_FILENAME

        if not model_path.is_file():
            raise AnomalyModelLoadError(f"IF model not found: {model_path}")
        if not meta_path.is_file():
            raise AnomalyModelLoadError(f"IF metadata not found: {meta_path}")

        # Load metadata for validation
        with open(meta_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        # Schema version check
        schema_ver = self.metadata.get("schema_version", "")
        if schema_ver != IF_SCHEMA_VERSION:
            raise AnomalyModelLoadError(
                f"IF schema version '{schema_ver}' != current '{IF_SCHEMA_VERSION}'"
            )

        # Feature count check
        feat_count = self.metadata.get("feature_count", 0)
        if feat_count != IF_FEATURE_COUNT:
            raise AnomalyModelLoadError(
                f"IF expects {feat_count} features, schema defines {IF_FEATURE_COUNT}"
            )

        # Feature names check
        feat_names = self.metadata.get("feature_names", [])
        if feat_names != ALL_IF_FEATURES:
            raise AnomalyModelLoadError(
                "IF feature names do not match current schema."
            )

        # Load model
        with warnings.catch_warnings():
            try:
                from sklearn.exceptions import InconsistentVersionWarning
                warnings.simplefilter("ignore", InconsistentVersionWarning)
            except ImportError:
                pass
            self.model = joblib.load(model_path)

        # Load preprocessor
        self.preprocessor = AnomalyPreprocessor.load(self.artifact_dir)

        # Load baseline stats for explanations
        from analysis.anomaly_detection.feature_schema import IF_BASELINE_STATS_FILENAME
        stats_path = self.artifact_dir / IF_BASELINE_STATS_FILENAME
        if stats_path.is_file():
            with open(stats_path, "r", encoding="utf-8") as f:
                self.baseline_stats = json.load(f)

        logger.info("AnomalyPredictor loaded from %s", self.artifact_dir)

    def predict(self, feature_vector: Dict[str, float]) -> Dict[str, Any]:
        """Run anomaly inference on a single session's feature vector.

        Parameters
        ----------
        feature_vector : Dict[str, float]
            The 30-feature IF vector for one session.

        Returns
        -------
        Dict with anomaly status, classification, scores, and metadata.
        """
        # Validate feature count
        if len(feature_vector) != IF_FEATURE_COUNT:
            return self._error_result(
                f"Feature count {len(feature_vector)} != expected {IF_FEATURE_COUNT}"
            )

        # Check for sufficient evidence
        nan_count = sum(1 for v in feature_vector.values() if isinstance(v, float) and math.isnan(v))
        if nan_count > IF_FEATURE_COUNT * 0.7:
            return {
                "status": ANOMALY_STATUS_INSUFFICIENT,
                "classification": None,
                "is_anomalous": None,
                "raw_score": None,
                "decision_score": None,
                "threshold": float(self.model.offset_),
                "model_version": self.metadata.get("model_version", IF_MODEL_VERSION),
                "feature_schema_version": IF_SCHEMA_VERSION,
                "warnings": ["Insufficient feature evidence for reliable anomaly detection."],
            }

        # Convert to ordered array
        ordered = [feature_vector[name] for name in ALL_IF_FEATURES]
        X = np.array([ordered])

        # Preprocess
        X_scaled = self.preprocessor.transform(X)

        # Predict
        pred = self.model.predict(X_scaled)[0]
        decision_score = float(self.model.decision_function(X_scaled)[0])
        raw_score = float(self.model.score_samples(X_scaled)[0])

        is_anomalous = bool(pred == -1)
        classification = (
            ANOMALY_CLASSIFICATION_ANOMALOUS if is_anomalous
            else ANOMALY_CLASSIFICATION_BASELINE
        )

        return {
            "status": ANOMALY_STATUS_COMPLETE,
            "classification": classification,
            "is_anomalous": is_anomalous,
            "raw_score": round(raw_score, 6),
            "decision_score": round(decision_score, 6),
            "threshold": round(float(self.model.offset_), 6),
            "model_version": self.metadata.get("model_version", IF_MODEL_VERSION),
            "feature_schema_version": IF_SCHEMA_VERSION,
            "warnings": [],
        }

    def _error_result(self, message: str) -> Dict[str, Any]:
        """Return a structured error result."""
        return {
            "status": ANOMALY_STATUS_ERROR,
            "classification": None,
            "is_anomalous": None,
            "raw_score": None,
            "decision_score": None,
            "threshold": None,
            "model_version": self.metadata.get("model_version", IF_MODEL_VERSION),
            "feature_schema_version": IF_SCHEMA_VERSION,
            "warnings": [message],
        }
