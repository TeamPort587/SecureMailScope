"""
Model Training Pipeline
=======================

Trains a RandomForestClassifier on the processed dataset, persists
the full preprocessing + model pipeline, and saves model metadata.

CLI Usage::

    python -m ml.training.train \\
        --data data/processed/training_dataset.csv \\
        --output ml/artifacts
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.feature_engineering.encoder import build_pipeline
from ml.feature_engineering.schema import (
    ALL_FEATURES,
    FEATURE_COUNT,
    RISK_LABELS,
    SCHEMA_VERSION,
)


# ── Constants ──────────────────────────────────────────────────────

DEFAULT_MODEL_VERSION: str = "rf-v1"
DEFAULT_TEST_SIZE: float = 0.2
DEFAULT_RANDOM_STATE: int = 42
DEFAULT_N_ESTIMATORS: int = 200

MODEL_FILENAME: str = "risk_model.joblib"
METADATA_FILENAME: str = "model_metadata.json"


def load_training_data(
    data_path: str | Path,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load processed training CSV and split into features / labels.

    Parameters
    ----------
    data_path:
        Path to the training CSV (produced by ``dataset_builder.py``).

    Returns
    -------
    Tuple[pd.DataFrame, pd.Series]
        ``(X, y)`` where ``X`` has the 19 canonical feature columns
        and ``y`` is the risk label series.
    """
    df = pd.read_csv(data_path)

    if "risk_label" not in df.columns:
        raise ValueError(
            "Training data must contain a 'risk_label' column. "
            "Run dataset_builder.py with --labels first."
        )

    missing_features = set(ALL_FEATURES) - set(df.columns)
    if missing_features:
        raise ValueError(
            f"Training data missing features: {missing_features}"
        )

    X = df[ALL_FEATURES]
    y = df["risk_label"]

    return X, y


def train_model(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    random_state: int = DEFAULT_RANDOM_STATE,
    test_size: float = DEFAULT_TEST_SIZE,
) -> Tuple[Any, pd.DataFrame, pd.Series, pd.DataFrame, pd.Series]:
    """Train the pipeline and return the fitted model + split data.

    Uses stratified split when possible; falls back to non-stratified
    for tiny / imbalanced datasets.

    Returns
    -------
    Tuple[Pipeline, X_train, y_train, X_test, y_test]
    """
    # Attempt stratified split; fall back if not possible
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
            stratify=y,
        )
    except ValueError:
        # Too few samples for stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
        )

    pipeline = build_pipeline(
        n_estimators=n_estimators,
        random_state=random_state,
    )

    pipeline.fit(X_train.values, y_train.values)

    return pipeline, X_train, y_train, X_test, y_test


def save_model(
    pipeline: Any,
    output_dir: str | Path,
    *,
    model_version: str = DEFAULT_MODEL_VERSION,
    training_rows: int = 0,
    test_rows: int = 0,
    random_state: int = DEFAULT_RANDOM_STATE,
    label_classes: Optional[List[str]] = None,
    feature_importances: Optional[List[float]] = None,
) -> Path:
    """Persist the trained pipeline and metadata.

    Saves:
        - ``risk_model.joblib`` — the full sklearn pipeline.
        - ``model_metadata.json`` — training metadata.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Save pipeline
    model_path = out / MODEL_FILENAME
    joblib.dump(pipeline, model_path)

    # Build metadata
    metadata: Dict[str, Any] = {
        "model_version": model_version,
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": ALL_FEATURES,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "label_classes": label_classes or RISK_LABELS,
        "training_rows": training_rows,
        "test_rows": test_rows,
        "random_state": random_state,
    }

    if feature_importances is not None:
        metadata["feature_importances"] = dict(
            zip(ALL_FEATURES, feature_importances)
        )

    meta_path = out / METADATA_FILENAME
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return model_path


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for training."""
    parser = argparse.ArgumentParser(
        description="Train the ML risk scoring model."
    )
    parser.add_argument(
        "--data", required=True,
        help="Path to training CSV (from dataset_builder).",
    )
    parser.add_argument(
        "--output", default="ml/artifacts",
        help="Directory to save model artifacts.",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS,
        help=f"Number of trees (default: {DEFAULT_N_ESTIMATORS}).",
    )
    parser.add_argument(
        "--random-state", type=int, default=DEFAULT_RANDOM_STATE,
        help=f"Random state (default: {DEFAULT_RANDOM_STATE}).",
    )
    parser.add_argument(
        "--test-size", type=float, default=DEFAULT_TEST_SIZE,
        help=f"Test split fraction (default: {DEFAULT_TEST_SIZE}).",
    )

    args = parser.parse_args(argv)

    print(f"Loading training data: {args.data}")
    X, y = load_training_data(args.data)
    print(f"  {len(X)} rows, {X.shape[1]} features, "
          f"{y.nunique()} classes: {sorted(y.unique())}")

    print("Training model...")
    pipeline, X_train, y_train, X_test, y_test = train_model(
        X, y,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        test_size=args.test_size,
    )

    # Extract feature importances
    clf = pipeline.named_steps["classifier"]
    importances = clf.feature_importances_.tolist()

    print(f"Saving model to: {args.output}")
    save_model(
        pipeline, args.output,
        training_rows=len(X_train),
        test_rows=len(X_test),
        random_state=args.random_state,
        label_classes=sorted(y.unique().tolist()),
        feature_importances=importances,
    )

    # Quick accuracy
    accuracy = pipeline.score(X_test.values, y_test.values)
    print(f"  Test accuracy: {accuracy:.4f}")
    print("Done.")


if __name__ == "__main__":
    main()
