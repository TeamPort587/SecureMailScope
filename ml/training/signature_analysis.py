"""
Duplicate and Feature Signature Analysis
========================================

Analyzes exact duplicate rows, unique feature signatures, cross-split signature
leakage, label ambiguity, and scenario family overlap across train, validation,
and test splits.

Output:
- ml/artifacts/signature_analysis.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES


def analyze_signatures(
    train_path: str | Path,
    val_path: str | Path,
    test_path: str | Path,
) -> Dict[str, Any]:
    """Perform duplicate and signature analysis across splits."""
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    splits = {
        "train": train_df,
        "validation": val_df,
        "test": test_df,
    }

    full_df = pd.concat([train_df, val_df, test_df], ignore_index=True)
    total_rows = len(full_df)

    # 1. Exact duplicate rows across all columns
    exact_duplicates = int(full_df.duplicated().sum())

    # 2. Feature signatures (canonical 19 features)
    def _get_sigs(df: pd.DataFrame) -> List[Tuple]:
        return [tuple(r.fillna(-999.0)) for _, r in df[ALL_FEATURES].iterrows()]

    full_sigs = _get_sigs(full_df)
    train_sigs = set(_get_sigs(train_df))
    val_sigs = set(_get_sigs(val_df))
    test_sigs = set(_get_sigs(test_df))

    unique_sigs_count = len(set(full_sigs))
    duplicate_signatures_count = total_rows - unique_sigs_count

    # 3. Signatures appearing in multiple splits
    train_val_overlap_sigs = len(train_sigs & val_sigs)
    train_test_overlap_sigs = len(train_sigs & test_sigs)
    val_test_overlap_sigs = len(val_sigs & test_sigs)
    all_three_overlap_sigs = len(train_sigs & val_sigs & test_sigs)

    # 4 & 5. Signatures associated with 1 vs multiple labels
    sig_to_labels: Dict[Tuple, Set[str]] = {}
    for sig, label in zip(full_sigs, full_df["risk_label"]):
        sig_to_labels.setdefault(sig, set()).add(label)

    single_label_sigs = sum(1 for labels in sig_to_labels.values() if len(labels) == 1)
    multi_label_sigs = sum(1 for labels in sig_to_labels.values() if len(labels) > 1)

    # 6 & 7. Scenario family distributions and overlap
    def _family_dist(df: pd.DataFrame) -> Dict[str, int]:
        if "scenario_family" in df.columns:
            return {str(k): int(v) for k, v in df["scenario_family"].value_counts().items()}
        return {}

    train_families = set(train_df.get("scenario_family", []).unique())
    val_families = set(val_df.get("scenario_family", []).unique())
    test_families = set(test_df.get("scenario_family", []).unique())

    return {
        "total_rows": total_rows,
        "exact_duplicate_rows": exact_duplicates,
        "unique_feature_signatures": unique_sigs_count,
        "duplicate_feature_signatures_count": duplicate_signatures_count,
        "duplicate_feature_signature_rate": round(duplicate_signatures_count / total_rows, 4) if total_rows > 0 else 0.0,
        "signatures_associated_with_single_label": single_label_sigs,
        "signatures_associated_with_multiple_labels": multi_label_sigs,
        "cross_split_signature_overlap": {
            "train_val_overlap_signatures": train_val_overlap_sigs,
            "train_val_overlap_rate_on_val": round(train_val_overlap_sigs / len(val_sigs), 4) if len(val_sigs) > 0 else 0.0,
            "train_test_overlap_signatures": train_test_overlap_sigs,
            "train_test_overlap_rate_on_test": round(train_test_overlap_sigs / len(test_sigs), 4) if len(test_sigs) > 0 else 0.0,
            "val_test_overlap_signatures": val_test_overlap_sigs,
            "all_three_splits_overlap_signatures": all_three_overlap_sigs,
        },
        "scenario_family_analysis": {
            "train_family_count": len(train_families),
            "val_family_count": len(val_families),
            "test_family_count": len(test_families),
            "train_val_family_overlap": len(train_families & val_families),
            "train_test_family_overlap": len(train_families & test_families),
            "val_test_family_overlap": len(val_families & test_families),
            "per_split_distribution": {
                "train": _family_dist(train_df),
                "validation": _family_dist(val_df),
                "test": _family_dist(test_df),
            },
        },
    }


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Analyze feature signatures across splits.")
    parser.add_argument("--train", default="data/processed/train.csv")
    parser.add_argument("--val", default="data/processed/validation.csv")
    parser.add_argument("--test", default="data/processed/test.csv")
    parser.add_argument("--output", default="ml/artifacts/signature_analysis.json")
    args = parser.parse_args(argv)

    print("Analyzing feature signatures and scenario family distribution...")
    analysis = analyze_signatures(args.train, args.val, args.test)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    print(f"Signature analysis saved to: {out_path}")
    print(f"  Unique Signatures: {analysis['unique_feature_signatures']} / {analysis['total_rows']}")
    print(f"  Train-Val Signature Overlap: {analysis['cross_split_signature_overlap']['train_val_overlap_signatures']}")
    print(f"  Train-Test Signature Overlap: {analysis['cross_split_signature_overlap']['train_test_overlap_signatures']}")
    print(f"  Signatures with Multi-Labels: {analysis['signatures_associated_with_multiple_labels']}")


if __name__ == "__main__":
    main()
