"""
Feature Encoder / Preprocessing Pipeline
=========================================

Wraps sklearn's imputation and the RandomForest classifier into a
single ``Pipeline`` that is persisted as one artifact — guaranteeing
identical preprocessing during training and inference.

Design decision (documented):
    For the MVP, a single ``SimpleImputer(strategy='most_frequent',
    add_indicator=True)`` is used for *all* 19 features.  This
    simplifies the pipeline while correctly handling NaN values.
    Binary features (mode → 0 or 1) and count features (mode → most
    common count, typically 0) both behave sensibly under
    ``most_frequent``.  A ``ColumnTransformer`` with separate
    strategies per group can be added post-MVP if needed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from ml.feature_engineering.schema import ALL_FEATURES, FEATURE_COUNT


def build_pipeline(
    *,
    n_estimators: int = 200,
    random_state: int = 42,
    class_weight: str = "balanced",
) -> Pipeline:
    """Build the canonical preprocessing + classification pipeline.

    The pipeline has two named steps:

    1. ``imputer`` — ``SimpleImputer`` with ``add_indicator=True``.
    2. ``classifier`` — ``RandomForestClassifier``.

    Parameters
    ----------
    n_estimators:
        Number of trees in the forest.
    random_state:
        Random seed for reproducibility.
    class_weight:
        Class weight strategy (default ``'balanced'``).

    Returns
    -------
    Pipeline
        An **unfitted** sklearn Pipeline.
    """
    return Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="most_frequent", add_indicator=True),
        ),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=random_state,
                class_weight=class_weight,
            ),
        ),
    ])


def features_to_dataframe(
    feature_rows: List[Dict[str, float]],
) -> pd.DataFrame:
    """Convert a list of feature-vector dicts to a DataFrame.

    Guarantees canonical column order defined in ``ALL_FEATURES``.
    """
    df = pd.DataFrame(feature_rows, columns=ALL_FEATURES)
    assert df.shape[1] == FEATURE_COUNT, (
        f"Expected {FEATURE_COUNT} columns, got {df.shape[1]}"
    )
    return df


def prepare_feature_matrix(
    feature_rows: List[Dict[str, float]],
) -> np.ndarray:
    """Convert feature-vector dicts to a numpy matrix in canonical order.

    Returns shape ``(n_sessions, 19)`` with ``np.nan`` preserved.
    """
    df = features_to_dataframe(feature_rows)
    return df.values
