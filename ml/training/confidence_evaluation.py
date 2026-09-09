"""
Probability, Confidence & Calibration Evaluation
================================================

Evaluates predict_proba() confidence distributions, multiclass Brier scores,
boundary/challenge confidence, and compares RandomForest vs CalibratedClassifierCV.

CLI Usage::

    python -m ml.training.confidence_evaluation \\
        --model ml/artifacts/risk_model.joblib \\
        --train-data data/processed/train.csv \\
        --test-data data/processed/test.csv \\
        --challenge-data data/processed/challenge.csv \\
        --output ml/artifacts/confidence_report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import label_binarize

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS


def compute_multiclass_brier_score(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    classes: List[str],
) -> float:
    """Compute multiclass Brier score: (1/N) * sum_i sum_k (p_ik - y_ik)^2."""
    Y_onehot = label_binarize(y_true, classes=classes)
    if Y_onehot.shape[1] != y_proba.shape[1]:
        # Handle edge cases with binary or missing class columns
        return float(np.mean((y_proba - Y_onehot) ** 2))
    brier = np.mean(np.sum((y_proba - Y_onehot) ** 2, axis=1))
    return float(round(float(brier), 4))


def analyze_split_confidence(
    pipeline: Any,
    df: pd.DataFrame,
    classes: List[str],
    name: str = "test",
) -> Dict[str, Any]:
    """Analyze prediction confidence and calibration on a dataset split."""
    X = df[ALL_FEATURES]
    y = df["risk_label"]

    probas = pipeline.predict_proba(X.values)
    preds = pipeline.predict(X.values)

    max_probas = np.max(probas, axis=1)

    low_conf_threshold = 0.70
    low_conf_mask = max_probas < low_conf_threshold
    low_conf_rate = float(np.mean(low_conf_mask))

    brier_score = compute_multiclass_brier_score(y.values, probas, classes)
    acc = float(accuracy_score(y, preds))
    macro_f1 = float(f1_score(y, preds, average="macro", zero_division=0))

    # Probability calibration bins (10 bins)
    bins = np.linspace(0.0, 1.0, 11)
    bin_assignments = np.digitize(max_probas, bins) - 1
    calibration_bins: List[Dict[str, Any]] = []

    for b in range(len(bins) - 1):
        in_bin = bin_assignments == b
        if np.any(in_bin):
            mean_pred_prob = float(np.mean(max_probas[in_bin]))
            bin_acc = float(np.mean(preds[in_bin] == y.values[in_bin]))
            calibration_bins.append({
                "bin_range": f"{bins[b]:.1f}-{bins[b+1]:.1f}",
                "sample_count": int(np.sum(in_bin)),
                "mean_predicted_probability": round(mean_pred_prob, 4),
                "actual_accuracy": round(bin_acc, 4),
            })

    return {
        "split_name": name,
        "sample_count": len(df),
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "mean_max_probability": round(float(np.mean(max_probas)), 4),
        "median_max_probability": round(float(np.median(max_probas)), 4),
        "min_max_probability": round(float(np.min(max_probas)), 4),
        "low_confidence_rate_under_70": round(low_conf_rate, 4),
        "brier_score": brier_score,
        "calibration_bins": calibration_bins,
    }


def evaluate_confidence_and_calibration(
    model_path: str | Path,
    train_path: str | Path,
    test_path: str | Path,
    challenge_path: str | Path,
) -> Dict[str, Any]:
    """Perform complete confidence distribution and calibration analysis."""
    pipeline = joblib.load(model_path)
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    chal_df = pd.read_csv(challenge_path)

    classes = sorted(list(pipeline.classes_))

    # 1. Test Split Confidence
    test_analysis = analyze_split_confidence(pipeline, test_df, classes, name="test")

    # 2. Challenge Set Confidence
    challenge_analysis = analyze_split_confidence(pipeline, chal_df, classes, name="challenge")

    # 3. Boundary Cases Confidence
    combined = pd.concat([test_df, chal_df], ignore_index=True)
    boundary_mask = combined["scenario_family"].str.contains("BOUNDARY", case=False, na=False)
    boundary_df = combined[boundary_mask]

    if not boundary_df.empty:
        boundary_analysis = analyze_split_confidence(pipeline, boundary_df, classes, name="boundary")
    else:
        boundary_analysis = {"sample_count": 0, "mean_max_probability": 0.0}

    # 4. Compare Raw Model vs CalibratedClassifierCV
    # Train calibrated wrapper on train set with isotonic calibration (cv=3)
    X_train = train_df[ALL_FEATURES]
    y_train = train_df["risk_label"]

    calibrated_clf = CalibratedClassifierCV(pipeline, cv=3, method="isotonic")
    calibrated_clf.fit(X_train.values, y_train.values)

    calibrated_test_analysis = analyze_split_confidence(calibrated_clf, test_df, classes, name="calibrated_test")
    calibrated_chal_analysis = analyze_split_confidence(calibrated_clf, chal_df, classes, name="calibrated_challenge")

    comparison = {
        "raw_model": {
            "test_brier_score": test_analysis["brier_score"],
            "test_accuracy": test_analysis["accuracy"],
            "test_mean_max_prob": test_analysis["mean_max_probability"],
            "challenge_brier_score": challenge_analysis["brier_score"],
        },
        "calibrated_model": {
            "test_brier_score": calibrated_test_analysis["brier_score"],
            "test_accuracy": calibrated_test_analysis["accuracy"],
            "test_mean_max_prob": calibrated_test_analysis["mean_max_probability"],
            "challenge_brier_score": calibrated_chal_analysis["brier_score"],
        },
        "recommendation": (
            "Keep raw RandomForest model if Brier score is comparable and probabilities maintain sharp discernment, "
            "or adopt CalibratedClassifierCV if probabilistic risk calibration is paramount."
        ),
    }

    report = {
        "classes": classes,
        "test_confidence": test_analysis,
        "challenge_confidence": challenge_analysis,
        "boundary_confidence": boundary_analysis,
        "calibration_comparison": comparison,
    }

    return report


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate confidence distribution and calibration.")
    parser.add_argument("--model", default="ml/artifacts/risk_model.joblib", help="Path to model pipeline.")
    parser.add_argument("--train-data", default="data/processed/train.csv", help="Path to train CSV.")
    parser.add_argument("--test-data", default="data/processed/test.csv", help="Path to test CSV.")
    parser.add_argument("--challenge-data", default="data/processed/challenge.csv", help="Path to challenge CSV.")
    parser.add_argument("--output", default="ml/artifacts/confidence_report.json", help="Path to output JSON.")
    args = parser.parse_args(argv)

    print(f"Evaluating confidence & calibration for {args.model}...")
    report = evaluate_confidence_and_calibration(
        args.model, args.train_data, args.test_data, args.challenge_data
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Also save confidence_distribution.json for explicit contract compliance
    dist_path = out_path.parent / "confidence_distribution.json"
    with open(dist_path, "w", encoding="utf-8") as f:
        json.dump(report["test_confidence"], f, indent=2)

    print(f"  Confidence report saved to: {out_path}")
    print(f"  Confidence distribution saved to: {dist_path}")
    print(f"  Test Brier Score:       {report['test_confidence']['brier_score']}")
    print(f"  Test Mean Max Prob:     {report['test_confidence']['mean_max_probability']}")
    print(f"  Challenge Mean Max Prob:{report['challenge_confidence']['mean_max_probability']}")


if __name__ == "__main__":
    main()
