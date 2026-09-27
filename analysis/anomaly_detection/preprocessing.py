"""
Isolation Forest — Preprocessing Pipeline
==========================================

Handles missing-value imputation and feature scaling.
Fitted ONLY on training data, then saved and reloaded for inference.

Key design decisions:
- NaN values are imputed using median (numerical) strategy fitted on training data.
- Features are scaled using RobustScaler (resistant to outliers in the normal baseline).
- The fitted pipeline is serialized alongside the model.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    IF_FEATURE_COUNT,
    IF_PREPROCESSOR_FILENAME,
    IF_SCHEMA_VERSION,
)

logger = logging.getLogger(__name__)


class AnomalyPreprocessor:
    """Fit-once preprocessor for Isolation Forest features.

    Uses median imputation + RobustScaler to handle NaN values
    and normalize feature ranges while being resistant to outliers.
    """

    def __init__(self) -> None:
        self._fitted = False
        self._medians: Optional[np.ndarray] = None
        self._centers: Optional[np.ndarray] = None
        self._scales: Optional[np.ndarray] = None
        self._feature_names: List[str] = list(ALL_IF_FEATURES)
        self._schema_version: str = IF_SCHEMA_VERSION

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def fit(self, X: np.ndarray) -> "AnomalyPreprocessor":
        """Fit the preprocessor on training data only.

        Parameters
        ----------
        X : np.ndarray
            Training feature matrix of shape (n_samples, IF_FEATURE_COUNT).
            May contain NaN values.
        """
        assert X.shape[1] == IF_FEATURE_COUNT, (
            f"Expected {IF_FEATURE_COUNT} features, got {X.shape[1]}"
        )

        # Compute per-feature medians (ignoring NaN)
        self._medians = np.nanmedian(X, axis=0)

        # Replace NaN with medians for scale fitting
        X_imputed = X.copy()
        for col in range(X.shape[1]):
            mask = np.isnan(X_imputed[:, col])
            X_imputed[mask, col] = self._medians[col]

        # RobustScaler: center = median, scale = IQR
        q25 = np.percentile(X_imputed, 25, axis=0)
        q75 = np.percentile(X_imputed, 75, axis=0)
        self._centers = np.median(X_imputed, axis=0)
        self._scales = q75 - q25
        # Avoid division by zero for constant features
        self._scales[self._scales == 0] = 1.0

        self._fitted = True
        logger.info("AnomalyPreprocessor fitted on %d samples", X.shape[0])
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform features using the fitted preprocessor.

        Parameters
        ----------
        X : np.ndarray
            Feature matrix, shape (n_samples, IF_FEATURE_COUNT).

        Returns
        -------
        np.ndarray
            Imputed and scaled feature matrix. Guaranteed finite.
        """
        if not self._fitted:
            raise RuntimeError("Preprocessor has not been fitted.")

        assert X.shape[1] == IF_FEATURE_COUNT, (
            f"Expected {IF_FEATURE_COUNT} features, got {X.shape[1]}"
        )

        X_out = X.copy()

        # Impute NaN with fitted medians
        for col in range(X_out.shape[1]):
            mask = np.isnan(X_out[:, col])
            X_out[mask, col] = self._medians[col]

        # Scale
        X_out = (X_out - self._centers) / self._scales

        # Final safety: replace any remaining non-finite values
        X_out = np.nan_to_num(X_out, nan=0.0, posinf=0.0, neginf=0.0)

        return X_out

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit on X and then transform X."""
        return self.fit(X).transform(X)

    def save(self, directory: Path) -> None:
        """Save fitted preprocessor to directory."""
        if not self._fitted:
            raise RuntimeError("Cannot save unfitted preprocessor.")
        directory.mkdir(parents=True, exist_ok=True)
        state = {
            "medians": self._medians,
            "centers": self._centers,
            "scales": self._scales,
            "feature_names": self._feature_names,
            "schema_version": self._schema_version,
        }
        path = directory / IF_PREPROCESSOR_FILENAME
        joblib.dump(state, path)
        logger.info("Preprocessor saved to %s", path)

    @classmethod
    def load(cls, directory: Path) -> "AnomalyPreprocessor":
        """Load a fitted preprocessor from directory."""
        path = directory / IF_PREPROCESSOR_FILENAME
        if not path.is_file():
            raise FileNotFoundError(f"Preprocessor not found: {path}")
        state = joblib.load(path)
        instance = cls()
        instance._medians = state["medians"]
        instance._centers = state["centers"]
        instance._scales = state["scales"]
        instance._feature_names = state.get("feature_names", list(ALL_IF_FEATURES))
        instance._schema_version = state.get("schema_version", IF_SCHEMA_VERSION)
        instance._fitted = True

        # Validate schema version
        if instance._schema_version != IF_SCHEMA_VERSION:
            raise ValueError(
                f"Preprocessor schema version '{instance._schema_version}' "
                f"does not match current '{IF_SCHEMA_VERSION}'"
            )

        logger.info("Preprocessor loaded from %s", path)
        return instance

    def get_baseline_stats(self) -> Dict[str, Any]:
        """Return baseline statistics for explanation purposes."""
        if not self._fitted:
            return {}
        stats = {}
        for i, name in enumerate(self._feature_names):
            stats[name] = {
                "median": float(self._medians[i]) if not math.isnan(self._medians[i]) else None,
                "center": float(self._centers[i]),
                "iqr_scale": float(self._scales[i]),
                "q25": float(self._centers[i] - self._scales[i] * 0.5),
                "q75": float(self._centers[i] + self._scales[i] * 0.5),
            }
        return stats
