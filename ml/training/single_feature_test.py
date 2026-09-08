"""
Single Feature Predictability Test
==================================

Trains a classifier on each of the 19 canonical features independently to measure
how much predictive power an individual feature possesses on the validation set.
Identifies shortcut features that enable trivial classification.

Output:
- ml/artifacts/single_feature_performance.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS


def test_single_feature_performance(
    train_path: str | Path,
    val_path: str | Path,
    suspicious_threshold_f1: float = 0.50,
) -> Dict[str, Any]:
    """Train single-feature models and evaluate predictive power."""
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    results: Dict[str, Any] = {}
    flagged: List[str] = []

    for feat in ALL_FEATURES:
        X_train = train_df[[feat]].values
        y_train = train_df["risk_label"].values

        X_val = val_df[[feat]].values
        y_val = val_df["risk_label"].values

        # Build pipeline with imputer
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent", add_indicator=True)),
            ("clf", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")),
        ])

        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_val)

        acc = float(accuracy_score(y_val, y_pred))
        prec = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
        rec = float(recall_score(y_val, y_pred, average="macro", zero_division=0))
        f1 = float(f1_score(y_val, y_pred, average="macro", zero_division=0))

        is_suspicious = f1 >= suspicious_threshold_f1
        risk_level = "VERY_HIGH" if f1 >= 0.70 else ("HIGH" if f1 >= 0.50 else ("MODERATE" if f1 >= 0.35 else "LOW"))

        if is_suspicious:
            flagged.append(feat)

        results[feat] = {
            "accuracy": round(acc, 4),
            "macro_precision": round(prec, 4),
            "macro_recall": round(rec, 4),
            "macro_f1": round(f1, 4),
            "leakage_risk": risk_level,
            "suspicious": is_suspicious,
        }

    return {
        "benchmark_random_baseline_f1": 0.25,
        "suspicious_threshold_f1": suspicious_threshold_f1,
        "suspicious_threshold_rationale": (
            "For a balanced 4-class problem, a random classifier achieves ~0.25 Macro F1. "
            "Any single feature achieving >= 0.50 Macro F1 alone contains disproportionate "
            "univariate predictive power that may represent label leakage or artificial determinism."
        ),
        "flagged_features": flagged,
        "features": results,
    }


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Test single-feature predictive power.")
    parser.add_argument("--train", default="data/processed/train.csv")
    parser.add_argument("--val", default="data/processed/validation.csv")
    parser.add_argument("--output", default="ml/artifacts/single_feature_performance.json")
    parser.add_argument("--threshold", type=float, default=0.50)
    args = parser.parse_args(argv)

    report = test_single_feature_performance(args.train, args.val, suspicious_threshold_f1=args.threshold)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Single feature performance saved to: {out_path}")
    print(f"Flagged {len(report['flagged_features'])} features exceeding {args.threshold:.0%} Macro F1:")
    for feat in report["flagged_features"]:
        metrics = report["features"][feat]
        print(f"  {feat:25s} -> Acc: {metrics['accuracy']:.4f} | F1: {metrics['macro_f1']:.4f} | Risk: {metrics['leakage_risk']}")


if __name__ == "__main__":
    main()
