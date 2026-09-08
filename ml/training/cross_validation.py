"""
Stratified 5-Fold Cross-Validation
==================================

Evaluates LogisticRegression and RandomForestClassifier using 5-fold
StratifiedKFold cross-validation on the training set to assess model stability,
variance, and generalization without touching the test set.

Output:
- ml/artifacts/cross_validation_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline

from ml.feature_engineering.schema import ALL_FEATURES


def run_cross_validation(
    train_path: str | Path,
    n_splits: int = 5,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Perform 5-fold stratified cross-validation on the training split."""
    df = pd.read_csv(train_path)

    X = df[ALL_FEATURES].values
    y = df["risk_label"].values

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    models = {
        "LogisticRegression": lambda: LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=random_state
        ),
        "RandomForestClassifier": lambda: RandomForestClassifier(
            n_estimators=100, class_weight="balanced", min_samples_leaf=2,
            max_features="sqrt", random_state=random_state, n_jobs=-1
        ),
    }

    report: Dict[str, Any] = {
        "n_splits": n_splits,
        "random_state": random_state,
        "train_samples": len(df),
        "models": {},
    }

    for model_name, model_factory in models.items():
        acc_scores: List[float] = []
        prec_scores: List[float] = []
        rec_scores: List[float] = []
        f1_scores: List[float] = []

        for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            X_tr, X_val = X[train_idx], X[val_idx]
            y_tr, y_val = y[train_idx], y[val_idx]

            pipe = Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent", add_indicator=True)),
                ("clf", model_factory()),
            ])

            pipe.fit(X_tr, y_tr)
            y_pred = pipe.predict(X_val)

            acc_scores.append(float(accuracy_score(y_val, y_pred)))
            prec_scores.append(float(precision_score(y_val, y_pred, average="macro", zero_division=0)))
            rec_scores.append(float(recall_score(y_val, y_pred, average="macro", zero_division=0)))
            f1_scores.append(float(f1_score(y_val, y_pred, average="macro", zero_division=0)))

        report["models"][model_name] = {
            "accuracy_mean": round(float(np.mean(acc_scores)), 4),
            "accuracy_std": round(float(np.std(acc_scores)), 4),
            "macro_f1_mean": round(float(np.mean(f1_scores)), 4),
            "macro_f1_std": round(float(np.std(f1_scores)), 4),
            "precision_macro_mean": round(float(np.mean(prec_scores)), 4),
            "precision_macro_std": round(float(np.std(prec_scores)), 4),
            "recall_macro_mean": round(float(np.mean(rec_scores)), 4),
            "recall_macro_std": round(float(np.std(rec_scores)), 4),
            "fold_f1_scores": [round(s, 4) for s in f1_scores],
        }

    return report


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run 5-Fold Stratified Cross-Validation.")
    parser.add_argument("--train", default="data/processed/train.csv", help="Path to train.csv.")
    parser.add_argument("--n-splits", type=int, default=5, help="Number of folds.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument("--output", default="ml/artifacts/cross_validation_report.json", help="Output JSON path.")
    args = parser.parse_args(argv)

    print(f"Running {args.n_splits}-fold Stratified CV on: {args.train}")
    report = run_cross_validation(args.train, n_splits=args.n_splits, random_state=args.random_state)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Cross-validation report saved to: {out_path}")
    for m_name, m_stats in report["models"].items():
        print(f"  {m_name:24s} -> Acc: {m_stats['accuracy_mean']:.4f} (+/- {m_stats['accuracy_std']:.4f}) | "
              f"Macro F1: {m_stats['macro_f1_mean']:.4f} (+/- {m_stats['macro_f1_std']:.4f})")


if __name__ == "__main__":
    main()
