"""
Model Robustness & Controlled Perturbation Evaluation
=====================================================

Evaluates trained model robustness under domain-valid perturbations:
- Missing Evidence Robustness: Simulates unobserved certificates (cert -> NaN) in TLS captures.
- Partial Capture Robustness: Simulates truncated handshakes with unobserved cipher/cert details.
- Boundary Accuracy: Evaluates performance across subtle risk class transitions.
- Rare Combination Accuracy: Evaluates rare RFC-valid cipher/protocol configurations.
- Prediction Stability: Measures classification consistency under minor informational shifts.

CLI Usage::

    python -m ml.training.robustness_evaluation \\
        --model ml/artifacts/risk_model.joblib \\
        --test-data data/processed/test.csv \\
        --challenge-data data/processed/challenge.csv \\
        --output ml/artifacts/robustness_report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

from ml.feature_engineering.schema import ALL_FEATURES
from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.dataset_validator import validate_feature_row


def evaluate_missing_evidence_robustness(
    pipeline: Any,
    test_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Simulate missing certificate evidence in TLS sessions and evaluate model stability."""
    # Select TLS sessions that currently have observable certificates
    tls_mask = (test_df["encryption_plaintext"] == 0.0) & (test_df["tls_upgrade_failed"] != 1.0)
    tls_df = test_df[tls_mask].copy()

    if tls_df.empty:
        return {"samples": 0, "stability": 1.0, "accuracy": 1.0}

    # Baseline predictions
    X_orig = tls_df[ALL_FEATURES]
    y_orig = tls_df["risk_label"]
    preds_orig = pipeline.predict(X_orig.values)

    # Perturbed: Set certificate fields to NaN
    perturbed_df = tls_df.copy()
    for cert_feat in ["expired_cert", "not_yet_valid_cert", "weak_key", "self_signed"]:
        perturbed_df[cert_feat] = np.nan

    X_pert = perturbed_df[ALL_FEATURES]
    preds_pert = pipeline.predict(X_pert.values)

    # Derived labels for the new perturbed state
    derived_labels: List[str] = []
    for _, row in perturbed_df.iterrows():
        derived_label, _ = calculate_session_risk(row.to_dict())
        derived_labels.append(derived_label)

    stability = float(np.mean(preds_orig == preds_pert))
    accuracy_vs_derived = float(accuracy_score(derived_labels, preds_pert))
    accuracy_vs_original = float(accuracy_score(y_orig, preds_pert))

    return {
        "samples_evaluated": len(tls_df),
        "prediction_stability": round(stability, 4),
        "accuracy_against_derived_ground_truth": round(accuracy_vs_derived, 4),
        "accuracy_against_original_label": round(accuracy_vs_original, 4),
    }


def evaluate_partial_capture_robustness(
    pipeline: Any,
    test_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Simulate partial capture where both TLS cipher and certificate details were missed."""
    tls_mask = (test_df["encryption_plaintext"] == 0.0) & (test_df["tls_upgrade_failed"] != 1.0)
    tls_df = test_df[tls_mask].copy()

    if tls_df.empty:
        return {"samples": 0, "accuracy": 1.0}

    partial_df = tls_df.copy()
    # Omit TLS details & cert details, preserving encryption mode
    for f in ["deprecated_tls", "weak_cipher", "pfs_missing", "expired_cert", "not_yet_valid_cert", "weak_key", "self_signed"]:
        partial_df[f] = np.nan

    X_part = partial_df[ALL_FEATURES]
    preds_part = pipeline.predict(X_part.values)

    derived_labels: List[str] = []
    for _, row in partial_df.iterrows():
        derived_label, _ = calculate_session_risk(row.to_dict())
        derived_labels.append(derived_label)

    accuracy_vs_derived = float(accuracy_score(derived_labels, preds_part))

    return {
        "samples_evaluated": len(partial_df),
        "accuracy_against_derived_ground_truth": round(accuracy_vs_derived, 4),
    }


def evaluate_boundary_robustness(
    pipeline: Any,
    test_df: pd.DataFrame,
    challenge_df: Optional[pd.DataFrame] = None,
) -> Dict[str, Any]:
    """Evaluate performance on boundary scenarios across test and challenge datasets."""
    frames = [test_df]
    if challenge_df is not None:
        frames.append(challenge_df)
    combined = pd.concat(frames, ignore_index=True)

    boundary_mask = combined["scenario_family"].str.contains("BOUNDARY", case=False, na=False)
    boundary_df = combined[boundary_mask]

    if boundary_df.empty:
        return {"samples": 0, "accuracy": 1.0, "macro_f1": 1.0}

    X = boundary_df[ALL_FEATURES]
    y = boundary_df["risk_label"]
    preds = pipeline.predict(X.values)

    acc = float(accuracy_score(y, preds))
    f1 = float(f1_score(y, preds, average="macro", zero_division=0))

    return {
        "samples_evaluated": len(boundary_df),
        "boundary_accuracy": round(acc, 4),
        "boundary_macro_f1": round(f1, 4),
    }


def evaluate_rare_combination_robustness(
    pipeline: Any,
    challenge_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Evaluate performance on rare combinations from challenge dataset."""
    rare_mask = challenge_df["scenario_family"].str.contains("RARE", case=False, na=False)
    rare_df = challenge_df[rare_mask]

    if rare_df.empty:
        return {"samples": 0, "accuracy": 1.0, "macro_f1": 1.0}

    X = rare_df[ALL_FEATURES]
    y = rare_df["risk_label"]
    preds = pipeline.predict(X.values)

    acc = float(accuracy_score(y, preds))
    f1 = float(f1_score(y, preds, average="macro", zero_division=0))

    return {
        "samples_evaluated": len(rare_df),
        "rare_combination_accuracy": round(acc, 4),
        "rare_combination_macro_f1": round(f1, 4),
    }


def compute_comprehensive_robustness(
    model_path: str | Path,
    test_path: str | Path,
    challenge_path: str | Path,
) -> Dict[str, Any]:
    """Run all robustness checks and compile comprehensive report."""
    pipeline = joblib.load(model_path)
    test_df = pd.read_csv(test_path)
    chal_df = pd.read_csv(challenge_path)

    # 1. Baseline metrics on clean test set
    X_test = test_df[ALL_FEATURES]
    y_test = test_df["risk_label"]
    test_preds = pipeline.predict(X_test.values)
    base_acc = float(accuracy_score(y_test, test_preds))
    base_f1 = float(f1_score(y_test, test_preds, average="macro", zero_division=0))

    # 2. Perturbation checks
    missing_evidence = evaluate_missing_evidence_robustness(pipeline, test_df)
    partial_capture = evaluate_partial_capture_robustness(pipeline, test_df)
    boundary = evaluate_boundary_robustness(pipeline, test_df, chal_df)
    rare = evaluate_rare_combination_robustness(pipeline, chal_df)

    # Overall robustness composite score (weighted mean of accuracies)
    robustness_score = round(
        0.30 * base_acc
        + 0.25 * missing_evidence["accuracy_against_derived_ground_truth"]
        + 0.20 * partial_capture["accuracy_against_derived_ground_truth"]
        + 0.15 * boundary["boundary_accuracy"]
        + 0.10 * rare["rare_combination_accuracy"],
        4,
    )

    report = {
        "baseline_accuracy": round(base_acc, 4),
        "baseline_macro_f1": round(base_f1, 4),
        "missing_evidence_accuracy": missing_evidence["accuracy_against_derived_ground_truth"],
        "missing_evidence_stability": missing_evidence["prediction_stability"],
        "partial_capture_accuracy": partial_capture["accuracy_against_derived_ground_truth"],
        "boundary_accuracy": boundary["boundary_accuracy"],
        "boundary_macro_f1": boundary["boundary_macro_f1"],
        "rare_combination_accuracy": rare["rare_combination_accuracy"],
        "rare_combination_macro_f1": rare["rare_combination_macro_f1"],
        "prediction_stability": missing_evidence["prediction_stability"],
        "overall_robustness_score": robustness_score,
        "details": {
            "missing_evidence": missing_evidence,
            "partial_capture": partial_capture,
            "boundary": boundary,
            "rare_combinations": rare,
        },
    }

    return report


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate model robustness under controlled domain perturbations.")
    parser.add_argument("--model", default="ml/artifacts/risk_model.joblib", help="Path to trained model pipeline.")
    parser.add_argument("--test-data", default="data/processed/test.csv", help="Path to test CSV.")
    parser.add_argument("--challenge-data", default="data/processed/challenge.csv", help="Path to challenge CSV.")
    parser.add_argument("--output", default="ml/artifacts/robustness_report.json", help="Path to output JSON.")
    args = parser.parse_args(argv)

    print(f"Evaluating robustness of {args.model}...")
    report = compute_comprehensive_robustness(args.model, args.test_data, args.challenge_data)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"  Robustness evaluation saved to: {out_path}")
    print(f"  Overall Robustness Score: {report['overall_robustness_score']}")
    print(f"  Baseline Accuracy:        {report['baseline_accuracy']}")
    print(f"  Missing Evidence Acc:     {report['missing_evidence_accuracy']}")
    print(f"  Boundary Accuracy:        {report['boundary_accuracy']}")
    print(f"  Rare Combination Acc:     {report['rare_combination_accuracy']}")


if __name__ == "__main__":
    main()
