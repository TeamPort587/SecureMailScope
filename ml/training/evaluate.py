"""
Model Evaluation Pipeline
=========================

Evaluates the trained model artifact against the final test split.
Computes macro and per-class metrics, generates confusion matrix,
and exports structured JSON metrics with explicit dataset limitations.

CLI Usage::

    python -m ml.training.evaluate \\
        --test data/processed/test.csv \\
        --model ml/artifacts/risk_model.joblib \\
        --output ml/artifacts
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS


METRICS_FILENAME: str = "evaluation_metrics.json"
CONFUSION_MATRIX_FILENAME: str = "confusion_matrix.png"

DEFAULT_LIMITATIONS: List[str] = [
    "Dataset contains curated synthetic security scenarios generated for MVP training and testing.",
    "Model performance on synthetic data does not represent independent real-world validation.",
    "High accuracy on synthetic scenarios is expected because the classifier learns domain scenario archetypes.",
    "Real-world holdout evaluation is currently insufficient (INSUFFICIENT_REAL_HOLDOUT_DATA) pending large-scale capture collection.",
]


def load_test_data(
    test_path: str | Path,
) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """Load test CSV and return (X_features, y_labels, full_df)."""
    df = pd.read_csv(test_path)

    if "risk_label" not in df.columns:
        raise ValueError(f"Test data {test_path} missing 'risk_label' column.")

    missing = set(ALL_FEATURES) - set(df.columns)
    if missing:
        raise ValueError(f"Test data {test_path} missing features: {missing}")

    X = df[ALL_FEATURES]
    y = df["risk_label"]

    return X, y, df


def evaluate_test_set(
    pipeline: Any,
    X_test: pd.DataFrame | np.ndarray,
    y_test: pd.Series | np.ndarray,
    *,
    dataset_type: str = "MVP_CURATED_SYNTHETIC_PLUS_AVAILABLE_REAL",
    limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Evaluate pipeline on test set and generate structured report."""
    if isinstance(X_test, pd.DataFrame):
        X_val = X_test.values
    else:
        X_val = X_test

    if isinstance(y_test, pd.Series):
        y_true = y_test.values
    else:
        y_true = y_test

    y_pred = pipeline.predict(X_val)
    present_labels = sorted(list(set(y_true.tolist()) | set(y_pred.tolist())))

    clf_report = classification_report(
        y_true, y_pred, labels=present_labels, zero_division=0, output_dict=True
    )

    # Per-class metrics
    per_class = {}
    for label in present_labels:
        if label in clf_report:
            per_class[label] = {
                "precision": round(float(clf_report[label]["precision"]), 4),
                "recall": round(float(clf_report[label]["recall"]), 4),
                "f1_score": round(float(clf_report[label]["f1-score"]), 4),
                "support": int(clf_report[label]["support"]),
            }

    cm = confusion_matrix(y_true, y_pred, labels=present_labels).tolist()

    return {
        "dataset_type": dataset_type,
        "test_rows": len(y_true),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "per_class": per_class,
        "confusion_matrix": cm,
        "confusion_matrix_labels": present_labels,
        "limitations": limitations or DEFAULT_LIMITATIONS,
    }


def save_metrics(
    metrics: Dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """Save metrics dict to JSON."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / METRICS_FILENAME
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    return path


def save_confusion_matrix_plot(
    metrics: Dict[str, Any],
    output_dir: str | Path,
) -> Optional[Path]:
    """Generate and save confusion matrix as a PNG image."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    cm = np.array(metrics["confusion_matrix"])
    labels = metrics.get("confusion_matrix_labels", RISK_LABELS)

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.set_title("Test Set Confusion Matrix")
    fig.colorbar(im, ax=ax)

    tick_marks = list(range(len(labels)))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(labels)

    thresh = cm.max() / 2.0 if cm.max() > 0 else 1.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")
    fig.tight_layout()

    path = out / CONFUSION_MATRIX_FILENAME
    fig.savefig(path, dpi=150)
    plt.close(fig)

    return path


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for test evaluation."""
    parser = argparse.ArgumentParser(
        description="Evaluate trained ML risk model against test dataset."
    )
    parser.add_argument(
        "--test", default="data/processed/test.csv",
        help="Path to test CSV (default: data/processed/test.csv).",
    )
    parser.add_argument(
        "--data", help="Alias for --test.",
    )
    parser.add_argument(
        "--model", default="ml/artifacts/risk_model.joblib",
        help="Path to model artifact (default: ml/artifacts/risk_model.joblib).",
    )
    parser.add_argument(
        "--output", default="ml/artifacts",
        help="Directory to save evaluation artifacts.",
    )
    parser.add_argument(
        "--dataset-type", default="MVP_CURATED_SYNTHETIC_PLUS_AVAILABLE_REAL",
        help="Dataset type description tag.",
    )

    args = parser.parse_args(argv)

    test_path = Path(args.data if args.data else args.test)
    model_path = Path(args.model)

    if not model_path.is_file():
        print(f"Error: Model not found at: {model_path}", file=sys.stderr)
        sys.exit(1)

    if not test_path.is_file():
        print(f"Error: Test data not found at: {test_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading model: {model_path}")
    pipeline = joblib.load(model_path)

    print(f"Loading test dataset: {test_path}")
    X_test, y_test, full_df = load_test_data(test_path)
    print(f"  Test samples: {len(X_test)}, classes: {sorted(y_test.unique().tolist())}")

    # Check real-world holdout subset
    if "data_source" in full_df.columns:
        real_count = int((full_df["data_source"] == "REAL").sum())
        if real_count < 50:
            print(f"  Real-world samples in test set: {real_count} (INSUFFICIENT_REAL_HOLDOUT_DATA)")

    print("Evaluating model on test split...")
    metrics = evaluate_test_set(pipeline, X_test, y_test, dataset_type=args.dataset_type)

    print(f"\n--- TEST EVALUATION METRICS ---")
    print(f"  Accuracy:         {metrics['accuracy']:.4f}")
    print(f"  Precision Macro:  {metrics['precision_macro']:.4f}")
    print(f"  Recall Macro:     {metrics['recall_macro']:.4f}")
    print(f"  F1 Macro:         {metrics['f1_macro']:.4f}")

    print("\n--- PER-CLASS METRICS ---")
    for cls, c_met in metrics["per_class"].items():
        print(f"  {cls:10s} | Precision: {c_met['precision']:.4f} | Recall: {c_met['recall']:.4f} | F1: {c_met['f1_score']:.4f} | Support: {c_met['support']}")

    metrics_path = save_metrics(metrics, args.output)
    print(f"\nSaved metrics to: {metrics_path}")

    cm_path = save_confusion_matrix_plot(metrics, args.output)
    if cm_path:
        print(f"Saved confusion matrix plot to: {cm_path}")
    else:
        print("(matplotlib not installed, skipped confusion matrix plot)")


if __name__ == "__main__":
    main()
