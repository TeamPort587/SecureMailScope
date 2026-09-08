"""
Dataset Builder
===============

Loads curated analysis JSON files and manual labels, extracts
per-session feature vectors, joins labels, and produces a
training-ready CSV dataset.

CLI Usage::

    python -m ml.training.dataset_builder \\
        --input data/curated \\
        --labels data/labels/session_labels.csv \\
        --output data/processed/training_dataset.csv
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from ml.feature_engineering.extractor import extract_all_sessions
from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABEL_SET


def load_analysis_files(input_dir: str | Path) -> List[Dict[str, Any]]:
    """Load all ``*.json`` analysis files from a directory.

    Parameters
    ----------
    input_dir:
        Path to a directory containing analysis JSON files.

    Returns
    -------
    List[Dict[str, Any]]
        A list of ``(analysis_id, analysis_data)`` tuples is returned
        as a list of dicts with an ``analysis_id`` key injected.
    """
    input_path = Path(input_dir)
    analyses: List[Dict[str, Any]] = []

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_path}")

    for json_file in sorted(input_path.glob("*.json")):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Use filename stem as analysis_id if not present
        analysis_id = data.get(
            "file", {}
        ).get("analysis_id", json_file.stem)

        data["_analysis_id"] = analysis_id
        analyses.append(data)

    return analyses


def load_labels(
    labels_path: str | Path,
) -> pd.DataFrame:
    """Load session labels from a CSV file.

    Expected CSV columns::

        analysis_id,session_id,risk_label

    Returns
    -------
    pd.DataFrame
        DataFrame with columns ``analysis_id``, ``session_id``,
        ``risk_label``.
    """
    labels_file = Path(labels_path)
    if not labels_file.is_file():
        raise FileNotFoundError(f"Labels file not found: {labels_file}")

    df = pd.read_csv(labels_file)

    required_cols = {"analysis_id", "session_id", "risk_label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(
            f"Labels CSV missing required columns: {missing}"
        )

    # Validate risk labels
    invalid = set(df["risk_label"].unique()) - RISK_LABEL_SET
    if invalid:
        raise ValueError(
            f"Invalid risk labels found: {invalid}. "
            f"Valid labels: {sorted(RISK_LABEL_SET)}"
        )

    return df


def build_dataset(
    analyses: List[Dict[str, Any]],
    labels_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Build a training dataset from analyses and optional labels.

    Parameters
    ----------
    analyses:
        List of analysis dicts (must have ``_analysis_id`` injected).
    labels_df:
        Optional DataFrame of labels.  If provided, only labeled
        sessions are included.

    Returns
    -------
    pd.DataFrame
        DataFrame with columns: ``analysis_id``, ``session_id``,
        the 19 canonical features, and optionally ``risk_label``.
    """
    rows: List[Dict[str, Any]] = []

    for analysis in analyses:
        analysis_id = analysis.get("_analysis_id", "unknown")
        session_features = extract_all_sessions(analysis)

        for sf in session_features:
            row: Dict[str, Any] = {
                "analysis_id": analysis_id,
                "session_id": sf["session_id"],
            }
            for feat in ALL_FEATURES:
                row[feat] = sf[feat]
            rows.append(row)

    df = pd.DataFrame(rows)

    if df.empty:
        # Return empty DataFrame with correct columns
        cols = ["analysis_id", "session_id"] + ALL_FEATURES
        if labels_df is not None:
            cols.append("risk_label")
        return pd.DataFrame(columns=cols)

    # Join labels if provided
    if labels_df is not None:
        df = df.merge(
            labels_df[["analysis_id", "session_id", "risk_label"]],
            on=["analysis_id", "session_id"],
            how="inner",
        )

    return df


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for dataset building."""
    parser = argparse.ArgumentParser(
        description="Build ML training dataset from curated analysis JSON files."
    )
    parser.add_argument(
        "--input", required=True,
        help="Directory containing curated analysis JSON files.",
    )
    parser.add_argument(
        "--labels", required=True,
        help="Path to session_labels.csv.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path for the output training CSV.",
    )

    args = parser.parse_args(argv)

    print(f"Loading analyses from: {args.input}")
    analyses = load_analysis_files(args.input)
    print(f"  Loaded {len(analyses)} analysis file(s).")

    print(f"Loading labels from: {args.labels}")
    labels_df = load_labels(args.labels)
    print(f"  Loaded {len(labels_df)} label(s).")

    print("Building dataset...")
    dataset = build_dataset(analyses, labels_df)
    print(f"  Dataset has {len(dataset)} rows.")

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    dataset.to_csv(output_path, index=False)
    print(f"  Saved to: {output_path}")


if __name__ == "__main__":
    main()
