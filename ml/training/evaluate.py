"""
Model Evaluation
================

Computes accuracy, precision, recall, F1 (macro), confusion matrix,
and classification report.  Saves metrics to JSON and optionally
generates a confusion matrix plot.

CLI Usage::

    python -m ml.training.evaluate \\
        --data data/processed/training_dataset.csv \\
        --model ml/artifacts/risk_model.joblib
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


def evaluate_model(
    pipeline: Any,
    X_test: np.ndarray | pd.DataFrame,
    y_test: np.ndarray | pd.Series,
    *,
    label_classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Evaluate a trained pipeline on test data.

    Returns
    -------
    Dict[str, Any]
        Dictionary containing ``accuracy``, ``precision_macro``,
        ``recall_macro``, ``f1_macro``, ``confusion_matrix``, and
        ``classification_report``.
    """
    if isinstance(X_test, pd.DataFrame):
        X_test = X_test.values
    if isinstance(y_test, pd.Series):
        y_test = y_test.values

    y_pred = pipeline.predict(X_test)
    labels = label_classes or RISK_LABELS

    # Filter labels to only those present in y_test or y_pred
    present_labels = sorted(
        set(y_test.tolist()) | set(y_pred.tolist())
    )

    metrics: Dict[str, Any] = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(
            precision_score(y_test, y_pred, average="macro", zero_division=0)
        ),
        "recall_macro": float(
            recall_score(y_test, y_pred, average="macro", zero_division=0)
        ),
        "f1_macro": float(
            f1_score(y_test, y_pred, average="macro", zero_division=0)
        ),
        "confusion_matrix": confusion_matrix(
            y_test, y_pred, labels=present_labels
        ).tolist(),
        "confusion_matrix_labels": present_labels,
        "classification_report": classification_report(
            y_test, y_pred, labels=present_labels, zero_division=0, output_dict=True
        ),
    }

    return metrics


def save_metrics(
    metrics: Dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """Save evaluation metrics to JSON."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Convert classification_report for JSON serialization
    serializable = {}
    for k, v in metrics.items():
        if isinstance(v, np.ndarray):
            serializable[k] = v.tolist()
        else:
            serializable[k] = v

    path = out / METRICS_FILENAME
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    return path


def save_confusion_matrix_plot(
    metrics: Dict[str, Any],
    output_dir: str | Path,
) -> Optional[Path]:
    """Save confusion matrix as a PNG image.

    Returns ``None`` if matplotlib is unavailable.
    """
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

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.set_title("Confusion Matrix")
    fig.colorbar(im, ax=ax)

    tick_marks = list(range(len(labels)))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(labels)

    # Annotate cells
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    ax.set_ylabel("True label")
    ax.set_xlabel("Predicted label")
    fig.tight_layout()

    path = out / CONFUSION_MATRIX_FILENAME
    fig.savefig(path, dpi=150)
    plt.close(fig)

    return path


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for evaluation."""
    parser = argparse.ArgumentParser(
        description="Evaluate the trained ML risk model."
    )
    parser.add_argument(
        "--data", required=True,
        help="Path to training/test CSV.",
    )
    parser.add_argument(
        "--model", required=True,
        help="Path to risk_model.joblib.",
    )
    parser.add_argument(
        "--output", default="ml/artifacts",
        help="Directory to save evaluation artifacts.",
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Test split fraction (default: 0.2).",
    )
    parser.add_argument(
        "--random-state", type=int, default=42,
        help="Random state for split (default: 42).",
    )

    args = parser.parse_args(argv)

    print(f"Loading model: {args.model}")
    pipeline = joblib.load(args.model)

    print(f"Loading data: {args.data}")
    df = pd.read_csv(args.data)
    X = df[ALL_FEATURES]
    y = df["risk_label"]

    # Re-split with same random state
    from sklearn.model_selection import train_test_split
    try:
        _, X_test, _, y_test = train_test_split(
            X, y,
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=y,
        )
    except ValueError:
        _, X_test, _, y_test = train_test_split(
            X, y,
            test_size=args.test_size,
            random_state=args.random_state,
        )

    print("Evaluating...")
    metrics = evaluate_model(pipeline, X_test, y_test)

    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision_macro']:.4f}")
    print(f"  Recall:    {metrics['recall_macro']:.4f}")
    print(f"  F1:        {metrics['f1_macro']:.4f}")

    metrics_path = save_metrics(metrics, args.output)
    print(f"  Metrics saved: {metrics_path}")

    cm_path = save_confusion_matrix_plot(metrics, args.output)
    if cm_path:
        print(f"  Confusion matrix: {cm_path}")
    else:
        print("  (matplotlib unavailable; skipped confusion matrix plot)")


if __name__ == "__main__":
    main()
