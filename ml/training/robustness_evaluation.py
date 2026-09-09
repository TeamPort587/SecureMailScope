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

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
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


def evaluate_scenarios_on_partial_capture_dataset(
    pipeline: Any,
    partial_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Evaluate performance independently per capture scenario on partial_capture_challenge dataset."""
    scenarios = partial_df["capture_scenario"].unique() if "capture_scenario" in partial_df.columns else []
    scenario_reports: Dict[str, Any] = {}

    overall_y = partial_df["risk_label"]
    overall_X = partial_df[ALL_FEATURES]
    overall_preds = pipeline.predict(overall_X.values)
    overall_probas = pipeline.predict_proba(overall_X.values)
    overall_confs = np.max(overall_probas, axis=1)

    overall_acc = float(accuracy_score(overall_y, overall_preds))
    overall_f1 = float(f1_score(overall_y, overall_preds, average="macro", zero_division=0))

    for scen in sorted(scenarios):
        scen_mask = partial_df["capture_scenario"] == scen
        scen_df = partial_df[scen_mask]
        if scen_df.empty:
            continue

        X = scen_df[ALL_FEATURES]
        y = scen_df["risk_label"]
        preds = pipeline.predict(X.values)
        probas = pipeline.predict_proba(X.values)
        confs = np.max(probas, axis=1)

        acc = float(accuracy_score(y, preds))
        f1 = float(f1_score(y, preds, average="macro", zero_division=0))

        # Per-class F1
        per_class: Dict[str, float] = {}
        for c in RISK_LABELS:
            if (y == c).sum() > 0:
                c_f1 = float(f1_score(y == c, preds == c, zero_division=0))
                per_class[c] = round(c_f1, 4)

        # Prediction stability (margin between top 2 predicted probabilities)
        sorted_probas = np.sort(probas, axis=1)
        margins = sorted_probas[:, -1] - sorted_probas[:, -2] if sorted_probas.shape[1] > 1 else np.ones(len(probas))
        stability = float(np.mean(margins))

        # Evidence quality distribution
        from ml.inference.predictor import assess_prediction_quality
        qualities: Dict[str, int] = {}
        for _, row in scen_df.iterrows():
            q, _ = assess_prediction_quality(row.to_dict())
            qualities[q] = qualities.get(q, 0) + 1

        scenario_reports[str(scen)] = {
            "samples": len(scen_df),
            "accuracy": round(acc, 4),
            "macro_f1": round(f1, 4),
            "per_class_f1": per_class,
            "mean_confidence": round(float(np.mean(confs)), 4),
            "prediction_stability": round(stability, 4),
            "evidence_quality_distribution": qualities,
        }

    return {
        "overall_samples": len(partial_df),
        "overall_accuracy": round(overall_acc, 4),
        "overall_macro_f1": round(overall_f1, 4),
        "mean_confidence": round(float(np.mean(overall_confs)), 4),
        "scenarios": scenario_reports,
    }


def compute_comprehensive_robustness(
    model_path: str | Path,
    test_path: str | Path,
    challenge_path: str | Path,
    partial_path: str | Path | None = None,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
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

    # 3. Independent Partial Capture Challenge dataset
    partial_report = None
    if partial_path and Path(partial_path).is_file():
        partial_df = pd.read_csv(partial_path)
        partial_report = evaluate_scenarios_on_partial_capture_dataset(pipeline, partial_df)

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

    if partial_report is not None:
        report["partial_capture_challenge_metrics"] = {
            "overall_accuracy": partial_report["overall_accuracy"],
            "overall_macro_f1": partial_report["overall_macro_f1"],
            "mean_confidence": partial_report["mean_confidence"],
        }

    return report, partial_report


def save_partial_capture_reports(
    partial_report: Dict[str, Any],
    json_path: Path,
    txt_path: Path,
) -> None:
    """Save detailed partial capture reports in JSON and TXT formats."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(partial_report, f, indent=2)

    lines = [
        "==================================================================",
        "SECUREMAILSCOPE PARTIAL CAPTURE ROBUSTNESS REPORT",
        "==================================================================",
        f"Total Incomplete Samples Evaluated: {partial_report['overall_samples']}",
        f"Overall Accuracy:                  {partial_report['overall_accuracy']:.4f}",
        f"Overall Macro F1:                  {partial_report['overall_macro_f1']:.4f}",
        f"Mean Prediction Confidence:        {partial_report['mean_confidence']:.4f}",
        "",
        "--- PER-SCENARIO DETAILED BREAKDOWN ---",
    ]
    for scen, d in partial_report["scenarios"].items():
        lines.append(f"\nScenario: {scen}")
        lines.append(f"  Samples:      {d['samples']}")
        lines.append(f"  Accuracy:     {d['accuracy']:.4f}")
        lines.append(f"  Macro F1:     {d['macro_f1']:.4f}")
        lines.append(f"  Confidence:   {d['mean_confidence']:.4f}")
        lines.append(f"  Stability:    {d['prediction_stability']:.4f}")
        lines.append(f"  Per-Class F1: {d['per_class_f1']}")
        lines.append(f"  Evidence:     {d['evidence_quality_distribution']}")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate model robustness under controlled domain perturbations.")
    parser.add_argument("--model", default="ml/artifacts/risk_model.joblib", help="Path to trained model pipeline.")
    parser.add_argument("--test-data", default="data/processed/test.csv", help="Path to test CSV.")
    parser.add_argument("--challenge-data", default="data/processed/challenge.csv", help="Path to challenge CSV.")
    parser.add_argument("--partial-data", default="data/processed/partial_capture_challenge.csv", help="Path to partial capture challenge CSV.")
    parser.add_argument("--output", default="ml/artifacts/robustness_report.json", help="Path to output JSON.")
    parser.add_argument("--partial-output", default="ml/artifacts/partial_capture_report.json", help="Path to partial capture report JSON.")
    parser.add_argument("--partial-txt", default="ml/artifacts/partial_capture_report.txt", help="Path to partial capture report TXT.")
    args = parser.parse_args(argv)

    print(f"Evaluating robustness of {args.model}...")
    report, partial_report = compute_comprehensive_robustness(
        args.model, args.test_data, args.challenge_data, args.partial_data
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    if partial_report is not None:
        save_partial_capture_reports(
            partial_report,
            Path(args.partial_output),
            Path(args.partial_txt),
        )
        print(f"  Partial capture report saved to: {args.partial_output}")
        print(f"  Partial capture Overall Macro F1: {partial_report['overall_macro_f1']}")

    print(f"  Robustness evaluation saved to: {out_path}")
    print(f"  Overall Robustness Score: {report['overall_robustness_score']}")
    print(f"  Baseline Accuracy:        {report['baseline_accuracy']}")
    print(f"  Missing Evidence Acc:     {report['missing_evidence_accuracy']}")
    print(f"  Boundary Accuracy:        {report['boundary_accuracy']}")
    print(f"  Rare Combination Acc:     {report['rare_combination_accuracy']}")


if __name__ == "__main__":
    main()

