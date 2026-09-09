"""
Feature-to-Label Leakage Audit
==============================

Audits the relationship between each of the 19 canonical features and risk_label
to identify potential label leakage, extreme class-conditional associations,
and deterministic shortcuts.

Outputs:
- ml/artifacts/feature_label_audit.json
- ml/artifacts/feature_label_audit.txt
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS


def audit_feature_label_relationships(
    df: pd.DataFrame,
    leakage_threshold: float = 0.95,
) -> Dict[str, Any]:
    """Analyze the association between each feature and risk_label.

    Parameters
    ----------
    df:
        DataFrame containing the 19 canonical features and 'risk_label'.
    leakage_threshold:
        Fraction above which a feature value occurring almost exclusively
        in a single class is flagged as POTENTIAL_LABEL_LEAKAGE.

    Returns
    -------
    Dict[str, Any]
        Audit dictionary with per-feature statistics and flagged leakage.
    """
    if "risk_label" not in df.columns:
        raise ValueError("DataFrame must contain 'risk_label'")

    total_rows = len(df)
    class_counts = df["risk_label"].value_counts().to_dict()

    feature_audits: Dict[str, Any] = {}
    flagged_leakages: List[Dict[str, Any]] = []

    for feat in ALL_FEATURES:
        if feat not in df.columns:
            continue

        series = df[feat]
        # Missing value analysis
        missing_by_class = {}
        for label in RISK_LABELS:
            sub = df[df["risk_label"] == label]
            missing_by_class[label] = {
                "missing_count": int(sub[feat].isna().sum()),
                "missing_rate": round(float(sub[feat].isna().mean()), 4) if len(sub) > 0 else 0.0,
            }

        # Value distributions by class (treat NaN as 'NaN')
        str_vals = series.apply(lambda x: "NaN" if (pd.isna(x) or x is None) else (str(int(x)) if isinstance(x, (int, float)) and not math.isnan(x) and x == int(x) else str(x)))
        contingency = pd.crosstab(str_vals, df["risk_label"], dropna=False)

        contingency_dict = {}
        exclusive_values = []

        for val in contingency.index:
            row_counts = contingency.loc[val].to_dict()
            val_total = sum(row_counts.values())
            contingency_dict[str(val)] = {
                "counts": {str(k): int(v) for k, v in row_counts.items()},
                "total": int(val_total),
            }

            # Check if this non-NaN value occurs almost exclusively in one class
            if val != "NaN" and val_total >= 10:
                for label, count in row_counts.items():
                    purity = count / val_total
                    if purity >= leakage_threshold:
                        exclusive_values.append({
                            "value": str(val),
                            "class": str(label),
                            "count": int(count),
                            "total_with_value": int(val_total),
                            "purity": round(float(purity), 4),
                        })
                        flagged_leakages.append({
                            "feature": feat,
                            "value": str(val),
                            "target_class": str(label),
                            "purity": round(float(purity), 4),
                            "count": int(count),
                            "reason": f"Value {val} appears in class '{label}' with {purity:.1%} purity ({count}/{val_total})",
                        })

        # Feature summary metrics
        # For numeric features, get mean/std per class
        num_stats = {}
        if pd.api.types.is_numeric_dtype(series):
            for label in RISK_LABELS:
                sub_vals = df[df["risk_label"] == label][feat].dropna()
                if len(sub_vals) > 0:
                    num_stats[label] = {
                        "mean": round(float(sub_vals.mean()), 3),
                        "std": round(float(sub_vals.std()), 3) if len(sub_vals) > 1 else 0.0,
                        "min": round(float(sub_vals.min()), 3),
                        "max": round(float(sub_vals.max()), 3),
                    }

        feature_audits[feat] = {
            "overall_missing_rate": round(float(series.isna().mean()), 4),
            "missing_by_class": missing_by_class,
            "contingency_table": contingency_dict,
            "exclusive_values": exclusive_values,
            "numeric_stats_by_class": num_stats,
            "leakage_risk": "HIGH" if len(exclusive_values) > 0 else "LOW",
        }

    return {
        "total_samples": total_rows,
        "class_distribution": {str(k): int(v) for k, v in class_counts.items()},
        "leakage_threshold_used": leakage_threshold,
        "flagged_leakage_count": len(flagged_leakages),
        "flagged_leakages": flagged_leakages,
        "features": feature_audits,
    }


def format_text_audit(audit: Dict[str, Any]) -> str:
    """Format audit results as readable text."""
    lines = [
        "=" * 70,
        "FEATURE-TO-LABEL LEAKAGE AUDIT REPORT",
        "=" * 70,
        f"Total Samples Analyzed: {audit['total_samples']}",
        f"Leakage Purity Threshold: {audit['leakage_threshold_used']:.0%}",
        f"Flagged Potential Leakage Patterns: {audit['flagged_leakage_count']}",
        "",
        "--- FLAGGED POTENTIAL LABEL LEAKAGES ---",
    ]

    if not audit["flagged_leakages"]:
        lines.append("  None detected at the specified threshold.")
    else:
        for fl in audit["flagged_leakages"]:
            lines.append(
                f"  [POTENTIAL_LABEL_LEAKAGE] Feature '{fl['feature']}' = {fl['value']} "
                f"-> 100% indicates '{fl['target_class']}' (purity: {fl['purity']:.1%}, count: {fl['count']})"
            )
    lines.append("")

    lines.append("--- DETAILED FEATURE-BY-FEATURE SUMMARY ---")
    for feat, data in audit["features"].items():
        lines.append(f"Feature: {feat} (Risk: {data['leakage_risk']}, Missing: {data['overall_missing_rate']:.1%})")
        if data["exclusive_values"]:
            for ev in data["exclusive_values"]:
                lines.append(f"   -> Value {ev['value']} is exclusive to class {ev['class']} ({ev['purity']:.1%})")
        if data["numeric_stats_by_class"]:
            stats_str = ", ".join(f"{cls}: avg {st['mean']}" for cls, st in data["numeric_stats_by_class"].items())
            lines.append(f"   -> Numeric Means: {stats_str}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run Feature-to-Label Leakage Audit.")
    parser.add_argument("--data", default="data/processed/combined_dataset.csv", help="Path to CSV dataset.")
    parser.add_argument("--output-dir", default="ml/artifacts", help="Directory to save audit artifacts.")
    parser.add_argument("--threshold", type=float, default=0.95, help="Purity threshold for leakage flagging.")
    args = parser.parse_args(argv)

    data_path = Path(args.data)
    if not data_path.is_file():
        print(f"Error: Dataset not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(data_path)
    print(f"Auditing {len(df)} rows from: {data_path} (threshold={args.threshold:.0%})")

    audit = audit_feature_label_relationships(df, leakage_threshold=args.threshold)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "feature_label_audit.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)
    print(f"Audit JSON saved to: {json_path}")

    txt_path = out_dir / "feature_label_audit.txt"
    txt_content = format_text_audit(audit)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt_content)
    print(f"Audit TXT saved to: {txt_path}")
    print(f"\nSummary: Found {audit['flagged_leakage_count']} potential leakage patterns.")


if __name__ == "__main__":
    main()
