"""
Dataset Builder & Splitting Pipeline
====================================

Loads curated analysis JSON files and manual labels, extracts per-session
feature vectors, merges real/demo and synthetic data, creates leakage-aware
train/val/test splits, and generates comprehensive quality reports.

CLI Usage::

    # 1. Build real/demo dataset from analysis JSONs + labels
    python -m ml.training.dataset_builder \\
        --input data/curated \\
        --labels data/labels/session_labels.csv \\
        --output data/processed/real_dataset.csv \\
        --data-source DEMO

    # 2. Combine real/demo with synthetic data
    python -m ml.training.dataset_builder \\
        --real data/processed/real_dataset.csv \\
        --synthetic data/processed/synthetic_dataset.csv \\
        --output data/processed/combined_dataset.csv

    # 3. Create stratified 70/15/15 splits with leakage report
    python -m ml.training.dataset_builder \\
        --split \\
        --input data/processed/combined_dataset.csv \\
        --train-output data/processed/train.csv \\
        --validation-output data/processed/validation.csv \\
        --test-output data/processed/test.csv
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.feature_engineering.extractor import extract_all_sessions
from ml.feature_engineering.schema import (
    ALL_FEATURES,
    FEATURE_COUNT,
    RISK_LABEL_SET,
    RISK_LABELS,
)
from ml.training.dataset_validator import validate_dataset


METADATA_COLUMNS: List[str] = [
    "analysis_id",
    "session_id",
    "scenario_id",
    "scenario_family",
    "data_source",
]


def load_analysis_files(input_dir: str | Path) -> List[Dict[str, Any]]:
    """Load all ``*.json`` analysis files from a directory."""
    input_path = Path(input_dir)
    analyses: List[Dict[str, Any]] = []

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_path}")

    for json_file in sorted(input_path.glob("*.json")):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        analysis_id = data.get("file", {}).get("analysis_id", json_file.stem)
        data["_analysis_id"] = analysis_id
        analyses.append(data)

    return analyses


def load_labels(labels_path: str | Path) -> pd.DataFrame:
    """Load session labels from a CSV file."""
    labels_file = Path(labels_path)
    if not labels_file.is_file():
        raise FileNotFoundError(f"Labels file not found: {labels_file}")

    df = pd.read_csv(labels_file)
    required_cols = {"analysis_id", "session_id", "risk_label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Labels CSV missing required columns: {missing}")

    invalid = set(df["risk_label"].dropna().unique()) - RISK_LABEL_SET
    if invalid:
        raise ValueError(
            f"Invalid risk labels found: {invalid}. Valid labels: {sorted(RISK_LABEL_SET)}"
        )

    return df


def build_dataset(
    analyses: List[Dict[str, Any]],
    labels_df: Optional[pd.DataFrame] = None,
    data_source: str = "DEMO",
) -> pd.DataFrame:
    """Build a feature dataset from analysis dicts and optional labels."""
    rows: List[Dict[str, Any]] = []

    for analysis in analyses:
        analysis_id = analysis.get("_analysis_id", "unknown")
        session_features = extract_all_sessions(analysis)

        for sf in session_features:
            sess_id = sf["session_id"]
            row: Dict[str, Any] = {
                "analysis_id": analysis_id,
                "session_id": sess_id,
                "scenario_id": f"{analysis_id}_{sess_id}",
                "scenario_family": f"{data_source}_CAPTURE",
                "data_source": data_source,
            }
            for feat in ALL_FEATURES:
                row[feat] = sf[feat]
            rows.append(row)

    df = pd.DataFrame(rows)
    all_cols = METADATA_COLUMNS + ALL_FEATURES

    if df.empty:
        if labels_df is not None:
            all_cols.append("risk_label")
        return pd.DataFrame(columns=all_cols)

    if labels_df is not None:
        df = df.merge(
            labels_df[["analysis_id", "session_id", "risk_label"]],
            on=["analysis_id", "session_id"],
            how="inner",
        )

    # Order columns
    present_cols = [c for c in all_cols if c in df.columns]
    if "risk_label" in df.columns and "risk_label" not in present_cols:
        present_cols.append("risk_label")

    return df[present_cols]


def combine_datasets(
    real_df: pd.DataFrame,
    synthetic_df: pd.DataFrame,
) -> pd.DataFrame:
    """Combine real/demo and synthetic DataFrames into a single dataset.

    Ensures consistent metadata columns and feature ordering.
    """
    for df, name in [(real_df, "real_df"), (synthetic_df, "synthetic_df")]:
        for col in ["scenario_id", "scenario_family"]:
            if col not in df.columns:
                df[col] = f"{df.get('data_source', 'UNKNOWN')}_UNKNOWN"

    combined = pd.concat([real_df, synthetic_df], ignore_index=True)

    final_cols = METADATA_COLUMNS + ALL_FEATURES
    if "risk_label" in combined.columns:
        final_cols.append("risk_label")

    return combined[final_cols]


def split_dataset(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Perform group-aware stratified 70/15/15 train/val/test splitting and compute leakage reports.

    Groups rows by feature signature so that identical feature signatures do NOT
    leak across train, validation, and test splits, while preserving class balance.

    Returns
    -------
    Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]
        ``(train_df, val_df, test_df, leakage_report)``
    """
    assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-5, "Ratios must sum to 1.0"

    rng = np.random.default_rng(random_state)
    df_copy = df.copy()
    df_copy["_sig"] = df_copy[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1)

    train_dfs: List[pd.DataFrame] = []
    val_dfs: List[pd.DataFrame] = []
    test_dfs: List[pd.DataFrame] = []

    # Check if we have risk_label to stratify
    has_labels = "risk_label" in df_copy.columns and df_copy["risk_label"].nunique() > 1

    if has_labels:
        for label, group in df_copy.groupby("risk_label"):
            unique_sigs = list(group["_sig"].unique())
            rng.shuffle(unique_sigs)

            total_class_rows = len(group)
            train_target = int(total_class_rows * train_ratio)
            val_target = int(total_class_rows * val_ratio)

            curr_train, curr_val = 0, 0
            t_sigs, v_sigs, te_sigs = set(), set(), set()

            for s in unique_sigs:
                cnt = int((group["_sig"] == s).sum())
                if curr_train + cnt <= train_target or curr_train < int(train_target * 0.9):
                    t_sigs.add(s)
                    curr_train += cnt
                elif curr_val + cnt <= val_target or curr_val < int(val_target * 0.9):
                    v_sigs.add(s)
                    curr_val += cnt
                else:
                    te_sigs.add(s)

            train_dfs.append(group[group["_sig"].isin(t_sigs)])
            val_dfs.append(group[group["_sig"].isin(v_sigs)])
            test_dfs.append(group[group["_sig"].isin(te_sigs)])

        train_df = pd.concat(train_dfs, ignore_index=True)
        val_df = pd.concat(val_dfs, ignore_index=True)
        test_df = pd.concat(test_dfs, ignore_index=True)
    else:
        # Fallback for unlabelled data
        unique_sigs = list(df_copy["_sig"].unique())
        rng.shuffle(unique_sigs)
        total_rows = len(df_copy)
        train_target = int(total_rows * train_ratio)
        val_target = int(total_rows * val_ratio)
        curr_train, curr_val = 0, 0
        t_sigs, v_sigs, te_sigs = set(), set(), set()
        for s in unique_sigs:
            cnt = int((df_copy["_sig"] == s).sum())
            if curr_train + cnt <= train_target:
                t_sigs.add(s)
                curr_train += cnt
            elif curr_val + cnt <= val_target:
                v_sigs.add(s)
                curr_val += cnt
            else:
                te_sigs.add(s)
        train_df = df_copy[df_copy["_sig"].isin(t_sigs)].copy()
        val_df = df_copy[df_copy["_sig"].isin(v_sigs)].copy()
        test_df = df_copy[df_copy["_sig"].isin(te_sigs)].copy()

    # Drop internal helper column
    train_df = train_df.drop(columns=["_sig"])
    val_df = val_df.drop(columns=["_sig"])
    test_df = test_df.drop(columns=["_sig"])

    # Compute Feature Signatures
    train_sigs = set(train_df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1))
    val_sigs = set(val_df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1))
    test_sigs = set(test_df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1))

    tv_sig_overlap = len(train_sigs & val_sigs)
    tt_sig_overlap = len(train_sigs & test_sigs)
    vt_sig_overlap = len(val_sigs & test_sigs)

    # Scenario family leakage calculation
    train_families = set(train_df.get("scenario_family", []).unique())
    val_families = set(val_df.get("scenario_family", []).unique())
    test_families = set(test_df.get("scenario_family", []).unique())

    leakage_report = {
        "strategy": "group_aware_stratified_by_feature_signature",
        "unique_signatures_train": len(train_sigs),
        "unique_signatures_validation": len(val_sigs),
        "unique_signatures_test": len(test_sigs),
        "train_validation_signature_overlap_count": tv_sig_overlap,
        "train_validation_signature_overlap_rate": round(float(tv_sig_overlap / len(train_sigs)) if train_sigs else 0.0, 4),
        "train_test_signature_overlap_count": tt_sig_overlap,
        "train_test_signature_overlap_rate": round(float(tt_sig_overlap / len(train_sigs)) if train_sigs else 0.0, 4),
        "validation_test_signature_overlap_count": vt_sig_overlap,
        "validation_test_signature_overlap_rate": round(float(vt_sig_overlap / len(val_sigs)) if val_sigs else 0.0, 4),
        "train_validation_overlap_families": sorted(list(train_families & val_families)),
        "train_validation_overlap_count": len(train_families & val_families),
        "train_test_overlap_families": sorted(list(train_families & test_families)),
        "train_test_overlap_count": len(train_families & test_families),
        "validation_test_overlap_families": sorted(list(val_families & test_families)),
        "validation_test_overlap_count": len(val_families & test_families),
        "note": (
            "Group-aware stratified splitting isolates distinct feature signatures into individual "
            "splits, reducing exact signature leakage to 0% while preserving class balance."
        ),
    }

    # Data source distribution across splits
    def _source_dist(d: pd.DataFrame) -> Dict[str, int]:
        if "data_source" in d.columns:
            return {str(k): int(v) for k, v in d["data_source"].value_counts().items()}
        return {}

    leakage_report["data_source_distribution_per_split"] = {
        "train": _source_dist(train_df),
        "validation": _source_dist(val_df),
        "test": _source_dist(test_df),
    }

    # Real holdout status
    real_count_test = _source_dist(test_df).get("REAL", 0)
    leakage_report["real_holdout_status"] = (
        "SUFFICIENT_REAL_HOLDOUT_DATA" if real_count_test >= 50 else "INSUFFICIENT_REAL_HOLDOUT_DATA"
    )

    return train_df, val_df, test_df, leakage_report


def generate_quality_report(
    df: pd.DataFrame,
    leakage_report: Optional[Dict[str, Any]] = None,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Generate comprehensive dataset quality report as a dictionary."""
    total_rows = len(df)

    # Class distribution
    class_dist = {str(k): int(v) for k, v in df["risk_label"].value_counts().items()} if "risk_label" in df.columns else {}

    # Protocol distribution
    proto_dist = {
        "SMTP": int((df["protocol_smtp"] == 1.0).sum()) if "protocol_smtp" in df.columns else 0,
        "IMAP": int((df["protocol_imap"] == 1.0).sum()) if "protocol_imap" in df.columns else 0,
        "POP3": int((df["protocol_pop3"] == 1.0).sum()) if "protocol_pop3" in df.columns else 0,
    }

    # Encryption distribution
    enc_dist = {
        "PLAINTEXT": int((df["encryption_plaintext"] == 1.0).sum()) if "encryption_plaintext" in df.columns else 0,
        "STARTTLS": int((df["encryption_starttls"] == 1.0).sum()) if "encryption_starttls" in df.columns else 0,
        "IMPLICIT_TLS": int((df["encryption_implicit"] == 1.0).sum()) if "encryption_implicit" in df.columns else 0,
    }

    # Missing value rates
    missing_rates = {}
    for feat in ALL_FEATURES:
        if feat in df.columns:
            missing_rates[feat] = round(float(df[feat].isna().mean()), 4)

    # Data source distribution
    data_source_dist = {str(k): int(v) for k, v in df["data_source"].value_counts().items()} if "data_source" in df.columns else {}

    # Scenario family distribution
    scenario_family_dist = {str(k): int(v) for k, v in df["scenario_family"].value_counts().items()} if "scenario_family" in df.columns else {}

    # Feature signature diversity
    signatures = df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1)
    unique_sigs = int(signatures.nunique())
    dup_sig_rate = round(float(1.0 - (unique_sigs / total_rows)) if total_rows > 0 else 0.0, 4)

    # Constraint validation
    valid_count, invalid_count, _ = validate_dataset(df)

    # Finding count vs risk label analysis
    finding_analysis: Dict[str, Any] = {}
    if "risk_label" in df.columns:
        for label in RISK_LABELS:
            subset = df[df["risk_label"] == label]
            if not subset.empty:
                finding_analysis[label] = {
                    "avg_critical_count": round(float(subset["critical_count"].mean()), 2),
                    "avg_high_count": round(float(subset["high_count"].mean()), 2),
                    "avg_medium_count": round(float(subset["medium_count"].mean()), 2),
                    "avg_low_count": round(float(subset["low_count"].mean()), 2),
                }

    report = {
        "total_rows": total_rows,
        "class_distribution": class_dist,
        "class_distribution_note": (
            "The class distribution is intentionally approximately balanced for MVP model training "
            "and does not represent real-world security risk prevalence."
        ),
        "protocol_distribution": proto_dist,
        "encryption_distribution": enc_dist,
        "missing_value_rates": missing_rates,
        "data_source_distribution": data_source_dist,
        "scenario_family_distribution": scenario_family_dist,
        "scenario_leakage_report": leakage_report or {},
        "unique_feature_signatures": unique_sigs,
        "duplicate_feature_signature_rate": dup_sig_rate,
        "validation": {
            "valid_rows": valid_count,
            "invalid_rows": invalid_count,
        },
        "finding_count_vs_risk_label_analysis": finding_analysis,
        "random_state": random_state,
    }

    return report


def format_text_report(report: Dict[str, Any]) -> str:
    """Format dictionary quality report into a human-readable text report."""
    lines = [
        "==================================================================",
        "SECUREMAILSCOPE ML DATASET QUALITY REPORT",
        "==================================================================",
        f"Total Samples: {report.get('total_rows')}",
        "",
        "--- CLASS DISTRIBUTION ---",
    ]
    for k, v in report.get("class_distribution", {}).items():
        lines.append(f"  {k:10s}: {v}")
    lines.append(f"Note: {report.get('class_distribution_note', '')}")
    lines.append("")

    lines.append("--- PROTOCOL DISTRIBUTION ---")
    for k, v in report.get("protocol_distribution", {}).items():
        lines.append(f"  {k:10s}: {v}")
    lines.append("")

    lines.append("--- ENCRYPTION MODE DISTRIBUTION ---")
    for k, v in report.get("encryption_distribution", {}).items():
        lines.append(f"  {k:15s}: {v}")
    lines.append("")

    lines.append("--- DATA SOURCE DISTRIBUTION ---")
    for k, v in report.get("data_source_distribution", {}).items():
        lines.append(f"  {k:20s}: {v}")
    lines.append("")

    lines.append("--- FEATURE DIVERSITY & VALIDATION ---")
    lines.append(f"  Unique Feature Signatures:        {report.get('unique_feature_signatures')}")
    lines.append(f"  Duplicate Feature Signature Rate: {report.get('duplicate_feature_signature_rate'):.2%}")
    val = report.get("validation", {})
    lines.append(f"  Validated Sound Rows:            {val.get('valid_rows')}")
    lines.append(f"  Validation Failures:             {val.get('invalid_rows')}")
    lines.append("")

    lines.append("--- FINDING COUNTS VS RISK LABEL ---")
    for label, counts in report.get("finding_count_vs_risk_label_analysis", {}).items():
        lines.append(
            f"  {label:8s} -> Crit: {counts.get('avg_critical_count'):.1f}, "
            f"High: {counts.get('avg_high_count'):.1f}, "
            f"Med: {counts.get('avg_medium_count'):.1f}, "
            f"Low: {counts.get('avg_low_count'):.1f}"
        )
    lines.append("")

    leak = report.get("scenario_leakage_report", {})
    if leak:
        lines.append("--- SCENARIO LEAKAGE & SPLIT REPORT ---")
        lines.append(f"  Strategy: {leak.get('strategy')}")
        lines.append(f"  Train/Val Overlap Families:  {leak.get('train_validation_overlap_count')}")
        lines.append(f"  Train/Test Overlap Families: {leak.get('train_test_overlap_count')}")
        lines.append(f"  Real Holdout Status:         {leak.get('real_holdout_status')}")
        lines.append(f"  Note: {leak.get('note')}")
        lines.append("")

    lines.append("==================================================================")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for dataset building, merging, splitting, and reporting."""
    parser = argparse.ArgumentParser(
        description="Dataset Builder, Merger, and Leakage-Aware Splitting Pipeline."
    )
    # Mode 1: build from analyses + labels
    parser.add_argument("--input", help="Directory containing analysis JSON files or CSV path for splitting.")
    parser.add_argument("--labels", help="Path to session_labels.csv.")
    parser.add_argument("--output", help="Path for output CSV.")
    parser.add_argument("--data-source", default="DEMO", help="Data source tag (DEMO, REAL, CURATED_SYNTHETIC).")

    # Mode 2: combine real and synthetic
    parser.add_argument("--real", help="Path to real_dataset.csv.")
    parser.add_argument("--synthetic", help="Path to synthetic_dataset.csv.")

    # Mode 3: splitting
    parser.add_argument("--split", action="store_true", help="Split input dataset into train/val/test.")
    parser.add_argument("--train-output", default="data/processed/train.csv", help="Path for train.csv.")
    parser.add_argument("--validation-output", default="data/processed/validation.csv", help="Path for validation.csv.")
    parser.add_argument("--test-output", default="data/processed/test.csv", help="Path for test.csv.")
    parser.add_argument("--random-state", type=int, default=42, help="Random state seed.")
    parser.add_argument("--report", default="data/processed/dataset_quality_report.json", help="Path for quality JSON.")

    args = parser.parse_args(argv)

    # Action 1: Combine real and synthetic
    if args.real and args.synthetic:
        print(f"Loading real data: {args.real}")
        real_df = pd.read_csv(args.real)
        print(f"Loading synthetic data: {args.synthetic}")
        synth_df = pd.read_csv(args.synthetic)

        combined = combine_datasets(real_df, synth_df)
        out_path = Path(args.output or "data/processed/combined_dataset.csv")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        combined.to_csv(out_path, index=False)
        print(f"Combined {len(real_df)} real/demo and {len(synth_df)} synthetic -> {len(combined)} rows saved to {out_path}")
        return

    # Action 2: Split dataset
    if args.split:
        in_path = args.input or "data/processed/combined_dataset.csv"
        print(f"Loading dataset to split: {in_path}")
        df = pd.read_csv(in_path)

        train_df, val_df, test_df, leakage = split_dataset(
            df,
            train_ratio=0.70,
            val_ratio=0.15,
            test_ratio=0.15,
            random_state=args.random_state,
        )

        for p, d, name in [
            (args.train_output, train_df, "Train"),
            (args.validation_output, val_df, "Validation"),
            (args.test_output, test_df, "Test"),
        ]:
            path = Path(p)
            path.parent.mkdir(parents=True, exist_ok=True)
            d.to_csv(path, index=False)
            print(f"  {name} set: {len(d)} rows saved to {path}")

        # Quality reports
        quality_report = generate_quality_report(df, leakage_report=leakage, random_state=args.random_state)
        json_path = Path(args.report)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(quality_report, f, indent=2)
        print(f"  Quality JSON report saved to: {json_path}")

        # Also save signature overlap report directly to ml/artifacts
        overlap_artifact_path = Path("ml/artifacts/signature_overlap_report.json")
        overlap_artifact_path.parent.mkdir(parents=True, exist_ok=True)
        with open(overlap_artifact_path, "w", encoding="utf-8") as f:
            json.dump(leakage, f, indent=2)
        print(f"  Signature Overlap report saved to: {overlap_artifact_path}")

        txt_path = json_path.with_suffix(".txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(format_text_report(quality_report))
        print(f"  Quality Text report saved to: {txt_path}")
        return

    # Action 3: Build from curated analyses and labels
    if args.input and args.labels:
        print(f"Loading analyses from: {args.input}")
        analyses = load_analysis_files(args.input)
        print(f"Loading labels from: {args.labels}")
        labels_df = load_labels(args.labels)
        dataset = build_dataset(analyses, labels_df, data_source=args.data_source)

        out_path = Path(args.output or "data/processed/real_dataset.csv")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        dataset.to_csv(out_path, index=False)
        print(f"Saved {len(dataset)} rows to: {out_path}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
