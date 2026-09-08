"""
Model Training & Baseline Comparison Pipeline
==============================================

Trains and compares baseline classifiers against RandomForestClassifier on
the training split, evaluates them on the validation split, selects the best
performing model, and persists the full preprocessing + model pipeline and metadata.

CLI Usage::

    python -m ml.training.train \\
        --train data/processed/train.csv \\
        --validation data/processed/validation.csv \\
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
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    FEATURE_COUNT,
    RISK_LABELS,
    SCHEMA_VERSION,
)


# ── Constants ──────────────────────────────────────────────────────

DEFAULT_MODEL_VERSION: str = "rf-v1"
DEFAULT_RANDOM_STATE: int = 42
DEFAULT_N_ESTIMATORS: int = 300

MODEL_FILENAME: str = "risk_model.joblib"
METADATA_FILENAME: str = "model_metadata.json"
COMPARISON_FILENAME: str = "model_comparison.json"
FEATURE_IMPORTANCES_FILENAME: str = "feature_importances.json"


def load_dataset_split(
    file_path: str | Path,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load a dataset CSV and return (X_features, y_labels).

    Excludes all metadata columns; returns strictly the 19 canonical features.
    """
    df = pd.read_csv(file_path)

    if "risk_label" not in df.columns:
        raise ValueError(
            f"Dataset {file_path} missing 'risk_label' column."
        )

    missing = set(ALL_FEATURES) - set(df.columns)
    if missing:
        raise ValueError(f"Dataset {file_path} missing features: {missing}")

    X = df[ALL_FEATURES]
    y = df["risk_label"]

    return X, y


def build_classifier_pipeline(
    classifier: Any,
) -> Pipeline:
    """Build a Pipeline with SimpleImputer and the specified classifier."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent", add_indicator=True)),
        ("classifier", classifier),
    ])


def evaluate_split_metrics(
    pipeline: Pipeline,
    X: pd.DataFrame,
    y: pd.Series,
) -> Dict[str, Any]:
    """Compute standard classification metrics on a dataset split."""
    y_pred = pipeline.predict(X.values)
    labels = sorted(list(set(y.tolist()) | set(y_pred.tolist())))

    return {
        "accuracy": round(float(accuracy_score(y, y_pred)), 4),
        "precision_macro": round(float(precision_score(y, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y, y_pred, average="macro", zero_division=0)), 4),
        "classification_report": classification_report(y, y_pred, labels=labels, zero_division=0, output_dict=True),
    }


def compare_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    *,
    random_state: int = DEFAULT_RANDOM_STATE,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
) -> Tuple[str, Dict[str, Any], Dict[str, Pipeline]]:
    """Train and compare DummyClassifier, LogisticRegression, and RandomForestClassifier.

    Returns
    -------
    Tuple[str, Dict[str, Any], Dict[str, Pipeline]]
        ``(best_model_name, comparison_report, fitted_pipelines)``
    """
    candidates = {
        "DummyClassifier": DummyClassifier(
            strategy="stratified",
            random_state=random_state,
        ),
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=random_state,
        ),
        "RandomForestClassifier": RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced",
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=random_state,
            n_jobs=-1,
        ),
    }

    comparison_report: Dict[str, Any] = {
        "validation_comparison": {},
        "train_comparison": {},
    }
    fitted_pipelines: Dict[str, Pipeline] = {}

    best_name = "RandomForestClassifier"
    best_f1 = -1.0

    for name, clf in candidates.items():
        pipe = build_classifier_pipeline(clf)
        pipe.fit(X_train.values, y_train.values)
        fitted_pipelines[name] = pipe

        train_metrics = evaluate_split_metrics(pipe, X_train, y_train)
        val_metrics = evaluate_split_metrics(pipe, X_val, y_val)

        comparison_report["train_comparison"][name] = train_metrics
        comparison_report["validation_comparison"][name] = val_metrics

        # Prefer RandomForestClassifier if tied on validation F1
        if val_metrics["f1_macro"] > best_f1 or (name == "RandomForestClassifier" and val_metrics["f1_macro"] >= best_f1):
            best_f1 = val_metrics["f1_macro"]
            best_name = name

    comparison_report["selected_model"] = best_name
    comparison_report["selection_metric"] = "validation_f1_macro"
    comparison_report["note"] = (
        "Model selection is based on validation split performance. "
        "Test split was not used for model selection or tuning."
    )

    return best_name, comparison_report, fitted_pipelines


def save_artifacts(
    pipeline: Pipeline,
    metadata: Dict[str, Any],
    comparison_report: Dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """Save model pipeline, metadata, baseline comparison, and feature importances."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. Save model pipeline
    model_path = out / MODEL_FILENAME
    joblib.dump(pipeline, model_path)

    # 2. Save metadata
    meta_path = out / METADATA_FILENAME
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # 3. Save model comparison report
    comp_path = out / COMPARISON_FILENAME
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump(comparison_report, f, indent=2)

    # 4. Save feature importances if available
    if "feature_importances" in metadata:
        fi_path = out / FEATURE_IMPORTANCES_FILENAME
        with open(fi_path, "w", encoding="utf-8") as f:
            json.dump(metadata["feature_importances"], f, indent=2)

    return model_path


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for model training and comparison."""
    parser = argparse.ArgumentParser(
        description="Train and evaluate baseline and RandomForest models."
    )
    parser.add_argument(
        "--train", default="data/processed/train.csv",
        help="Path to training CSV (default: data/processed/train.csv).",
    )
    parser.add_argument(
        "--validation", default="data/processed/validation.csv",
        help="Path to validation CSV (default: data/processed/validation.csv).",
    )
    # Backward compat: allow --data
    parser.add_argument(
        "--data", help="Alias for --train (splits automatically if --validation not found).",
    )
    parser.add_argument(
        "--output", default="ml/artifacts",
        help="Directory to save artifacts.",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS,
        help=f"Number of trees in RandomForest (default: {DEFAULT_N_ESTIMATORS}).",
    )
    parser.add_argument(
        "--random-state", type=int, default=DEFAULT_RANDOM_STATE,
        help=f"Random state (default: {DEFAULT_RANDOM_STATE}).",
    )

    args = parser.parse_args(argv)

    train_path = Path(args.data if args.data and not Path(args.train).is_file() else args.train)
    val_path = Path(args.validation)

    if not train_path.is_file():
        print(f"Error: Training file not found: {train_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading training data: {train_path}")
    X_train, y_train = load_dataset_split(train_path)
    print(f"  Train: {len(X_train)} samples, classes: {sorted(y_train.unique().tolist())}")

    if val_path.is_file():
        print(f"Loading validation data: {val_path}")
        X_val, y_val = load_dataset_split(val_path)
        print(f"  Validation: {len(X_val)} samples, classes: {sorted(y_val.unique().tolist())}")
    else:
        print("  Validation split not found; splitting train data (80/20)...")
        from sklearn.model_selection import train_test_split
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=args.random_state, stratify=y_train
        )

    print("\nTraining and comparing models (DummyClassifier vs LogisticRegression vs RandomForest)...")
    best_name, comparison_report, fitted_pipes = compare_models(
        X_train, y_train, X_val, y_val,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
    )

    print("\n--- MODEL COMPARISON ON VALIDATION SET ---")
    for m_name, m_metrics in comparison_report["validation_comparison"].items():
        print(
            f"  {m_name:24s} | Acc: {m_metrics['accuracy']:.4f} | "
            f"F1 (macro): {m_metrics['f1_macro']:.4f} | "
            f"Precision: {m_metrics['precision_macro']:.4f} | "
            f"Recall: {m_metrics['recall_macro']:.4f}"
        )
    print(f"\nSelected Model based on validation F1: {best_name}")

    # Chosen pipeline
    best_pipeline = fitted_pipes[best_name]

    # Feature importances (if tree-based)
    clf_step = best_pipeline.named_steps["classifier"]
    feature_importances = None
    if hasattr(clf_step, "feature_importances_"):
        feature_importances = dict(zip(ALL_FEATURES, [round(float(v), 4) for v in clf_step.feature_importances_]))

    metadata: Dict[str, Any] = {
        "model_version": DEFAULT_MODEL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": ALL_FEATURES,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "selected_model_class": type(clf_step).__name__,
        "label_classes": sorted(y_train.unique().tolist()),
        "training_rows": len(X_train),
        "validation_rows": len(X_val),
        "random_state": args.random_state,
        "validation_metrics": comparison_report["validation_comparison"][best_name],
        "feature_importances": feature_importances,
    }

    save_artifacts(best_pipeline, metadata, comparison_report, args.output)
    print(f"Artifacts successfully saved to: {args.output}")


if __name__ == "__main__":
    main()
