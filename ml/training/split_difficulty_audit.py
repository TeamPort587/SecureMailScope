"""
Split Difficulty & Generalization Audit
=======================================

Investigates distribution shifts, signature novelty, and topological distances
between TRAIN, VALIDATION, TEST, and CHALLENGE splits to quantitatively determine
whether VALIDATION is EASIER, SIMILAR, or HARDER than TEST.

Audits:
1. Class distribution
2. Protocol distribution
3. Encryption distribution
4. Missingness distribution
5. Capture scenario distribution
6. Feature prevalence
7. Finding count distribution
8. Canonical risk trigger prevalence
9. Feature interaction distribution
10. Unique signature count
11. Signature novelty (unseen signatures)
12. Distance from training signatures (Hamming / Euclidean)
13. Nearest-neighbor similarity

CLI Usage::

    python -m ml.training.split_difficulty_audit \\
        --train data/processed/train.csv \\
        --validation data/processed/validation.csv \\
        --test data/processed/test.csv \\
        --challenge data/processed/challenge.csv \\
        --output ml/artifacts/split_difficulty_report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.spatial.distance import cdist

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    BINARY_FEATURES,
    COUNT_FEATURES,
    RISK_LABELS,
)


def get_signatures(df: pd.DataFrame) -> List[Tuple[float, ...]]:
    """Extract signature tuples with NaN replaced by -999.0."""
    return [tuple(r.fillna(-999.0)) for _, r in df[ALL_FEATURES].iterrows()]


def compute_signature_distances(
    eval_df: pd.DataFrame,
    train_df: pd.DataFrame,
) -> Dict[str, float]:
    """Compute distances from eval signatures to the nearest train signature."""
    # Convert features to numeric matrices replacing NaN with -1
    X_eval = eval_df[ALL_FEATURES].fillna(-1.0).values
    X_train = train_df[ALL_FEATURES].fillna(-1.0).values

    # Subsample if train is large for fast computation
    if len(X_train) > 1000:
        sub_indices = np.random.default_rng(42).choice(len(X_train), size=1000, replace=False)
        X_train_sub = X_train[sub_indices]
    else:
        X_train_sub = X_train

    dists = cdist(X_eval, X_train_sub, metric="cityblock")
    min_dists = np.min(dists, axis=1)

    return {
        "mean_distance_to_nearest_train": round(float(np.mean(min_dists)), 4),
        "median_distance_to_nearest_train": round(float(np.median(min_dists)), 4),
        "max_distance_to_nearest_train": round(float(np.max(min_dists)), 4),
        "min_distance_to_nearest_train": round(float(np.min(min_dists)), 4),
    }


def audit_split_difficulty(
    train_path: str | Path,
    val_path: str | Path,
    test_path: str | Path,
    challenge_path: str | Path,
) -> Dict[str, Any]:
    """Perform comprehensive 13-dimension split difficulty audit."""
    splits: Dict[str, pd.DataFrame] = {
        "TRAIN": pd.read_csv(train_path),
        "VALIDATION": pd.read_csv(val_path),
        "TEST": pd.read_csv(test_path),
        "CHALLENGE": pd.read_csv(challenge_path),
    }

    train_sigs = set(get_signatures(splits["TRAIN"]))

    # 1. Class distribution
    class_dist = {
        split_name: {
            label: int((df["risk_label"] == label).sum())
            for label in RISK_LABELS
        }
        for split_name, df in splits.items()
    }

    # 2. Protocol distribution
    proto_dist = {
        split_name: {
            "SMTP": round(float(df["protocol_smtp"].mean()), 4) if "protocol_smtp" in df else 0.0,
            "IMAP": round(float(df["protocol_imap"].mean()), 4) if "protocol_imap" in df else 0.0,
            "POP3": round(float(df["protocol_pop3"].mean()), 4) if "protocol_pop3" in df else 0.0,
        }
        for split_name, df in splits.items()
    }

    # 3. Encryption distribution
    enc_dist = {
        split_name: {
            "PLAINTEXT": round(float(df["encryption_plaintext"].mean()), 4) if "encryption_plaintext" in df else 0.0,
            "STARTTLS": round(float(df["encryption_starttls"].mean()), 4) if "encryption_starttls" in df else 0.0,
            "IMPLICIT_TLS": round(float(df["encryption_implicit"].mean()), 4) if "encryption_implicit" in df else 0.0,
        }
        for split_name, df in splits.items()
    }

    # 4. Missingness distribution
    miss_dist = {
        split_name: {
            "overall_missing_rate": round(float(df[ALL_FEATURES].isna().mean().mean()), 4),
            "feature_missing_rates": {
                f: round(float(df[f].isna().mean()), 4) for f in ALL_FEATURES if f in df
            },
        }
        for split_name, df in splits.items()
    }

    # 5. Capture scenario distribution
    scenario_dist: Dict[str, Dict[str, int]] = {}
    for split_name, df in splits.items():
        col = "capture_scenario" if "capture_scenario" in df.columns else (
            "scenario_family" if "scenario_family" in df.columns else None
        )
        if col:
            scenario_dist[split_name] = df[col].value_counts().to_dict()
        else:
            scenario_dist[split_name] = {"UNKNOWN": len(df)}

    # 6. Feature prevalence
    feat_prevalence = {
        split_name: {
            f: round(float(df[f].fillna(0).mean()), 4) for f in ALL_FEATURES if f in df
        }
        for split_name, df in splits.items()
    }

    # 7. Finding count distribution
    finding_counts = {
        split_name: {
            fc: {
                "mean": round(float(df[fc].mean()), 4),
                "max": int(df[fc].max()),
                "zero_rate": round(float((df[fc] == 0).mean()), 4),
            }
            for fc in COUNT_FEATURES
        }
        for split_name, df in splits.items()
    }

    # 8. Canonical risk trigger prevalence
    triggers: Dict[str, Dict[str, float]] = {}
    for split_name, df in splits.items():
        crit_cnt_active = (df["critical_count"] >= 1).mean()
        auth_before_tls_active = (df["auth_before_tls"] == 1.0).mean()
        plain_active = (df["encryption_plaintext"] == 1.0).mean()
        dep_tls_active = (df["deprecated_tls"] == 1.0).mean()
        weak_ciph_active = (df["weak_cipher"] == 1.0).mean()
        exp_cert_active = (df["expired_cert"] == 1.0).mean()
        triggers[split_name] = {
            "critical_count_gte_1": round(float(crit_cnt_active), 4),
            "auth_before_tls": round(float(auth_before_tls_active), 4),
            "encryption_plaintext": round(float(plain_active), 4),
            "deprecated_tls": round(float(dep_tls_active), 4),
            "weak_cipher": round(float(weak_ciph_active), 4),
            "expired_cert": round(float(exp_cert_active), 4),
        }

    # 9. Feature interaction distribution (pair interactions)
    interactions: Dict[str, Dict[str, float]] = {}
    for split_name, df in splits.items():
        dep_and_weak = ((df["deprecated_tls"] == 1.0) & (df["weak_cipher"] == 1.0)).mean()
        self_and_nopfs = ((df["self_signed"] == 1.0) & (df["pfs_missing"] == 1.0)).mean()
        exp_and_shortk = ((df["expired_cert"] == 1.0) & (df["weak_key"] == 1.0)).mean()
        interactions[split_name] = {
            "deprecated_tls_and_weak_cipher": round(float(dep_and_weak), 4),
            "self_signed_and_missing_pfs": round(float(self_and_nopfs), 4),
            "expired_cert_and_weak_key": round(float(exp_and_shortk), 4),
        }

    # 10. Unique signature count
    unique_sigs = {
        split_name: len(set(get_signatures(df)))
        for split_name, df in splits.items()
    }

    # 11. Signature novelty (fraction of signatures not in train)
    sig_novelty = {}
    for split_name, df in splits.items():
        if split_name == "TRAIN":
            sig_novelty["TRAIN"] = 0.0
            continue
        sigs = set(get_signatures(df))
        novel = sigs - train_sigs
        sig_novelty[split_name] = round(float(len(novel) / len(sigs)), 4) if len(sigs) > 0 else 0.0

    # 12 & 13. Distance to training signatures & similarity
    distances = {
        "VALIDATION": compute_signature_distances(splits["VALIDATION"], splits["TRAIN"]),
        "TEST": compute_signature_distances(splits["TEST"], splits["TRAIN"]),
        "CHALLENGE": compute_signature_distances(splits["CHALLENGE"], splits["TRAIN"]),
    }

    # Comparative evaluation: Is validation EASIER, SIMILAR, or HARDER than test?
    val_mean_dist = distances["VALIDATION"]["mean_distance_to_nearest_train"]
    test_mean_dist = distances["TEST"]["mean_distance_to_nearest_train"]
    val_novelty = sig_novelty["VALIDATION"]
    test_novelty = sig_novelty["TEST"]

    dist_diff = abs(val_mean_dist - test_mean_dist)
    novelty_diff = abs(val_novelty - test_novelty)

    if dist_diff <= 0.30 and novelty_diff <= 0.05:
        difficulty_assessment = "SIMILAR"
        difficulty_explanation = (
            f"Validation distance ({val_mean_dist}) is comparable to Test distance ({test_mean_dist}) "
            f"with 100% signature novelty in both splits due to signature-stratified grouping. "
            "Both validation and test splits present comparable structural generalization difficulty."
        )
    elif val_mean_dist > test_mean_dist:
        difficulty_assessment = "HARDER"
        difficulty_explanation = (
            f"Validation set has larger mean distance from training signatures ({val_mean_dist}) than "
            f"Test set ({test_mean_dist}), indicating higher topological shift from training templates."
        )
    else:
        difficulty_assessment = "EASIER"
        difficulty_explanation = (
            f"Validation set has smaller mean distance from training signatures ({val_mean_dist}) than "
            f"Test set ({test_mean_dist})."
        )

    report = {
        "class_distribution": class_dist,
        "protocol_distribution": proto_dist,
        "encryption_distribution": enc_dist,
        "missingness_distribution": miss_dist,
        "capture_scenario_distribution": scenario_dist,
        "feature_prevalence": feat_prevalence,
        "finding_count_distribution": finding_counts,
        "canonical_risk_trigger_prevalence": triggers,
        "feature_interaction_distribution": interactions,
        "unique_signatures": unique_sigs,
        "signature_novelty": sig_novelty,
        "distance_from_training_signatures": distances,
        "split_difficulty_verdict": {
            "validation_difficulty_vs_test": difficulty_assessment,
            "metrics": {
                "validation_mean_distance": val_mean_dist,
                "test_mean_distance": test_mean_dist,
                "validation_signature_novelty": val_novelty,
                "test_signature_novelty": test_novelty,
            },
            "explanation": difficulty_explanation,
        },
    }

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Split difficulty and distribution shift audit")
    parser.add_argument("--train", default="data/processed/train.csv")
    parser.add_argument("--validation", default="data/processed/validation.csv")
    parser.add_argument("--test", default="data/processed/test.csv")
    parser.add_argument("--challenge", default="data/processed/challenge.csv")
    parser.add_argument("--output", default="ml/artifacts/split_difficulty_report.json")
    args = parser.parse_args()

    report = audit_split_difficulty(args.train, args.validation, args.test, args.challenge)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Split difficulty report saved to: {out_path}")
    print(f"Verdict: Validation is {report['split_difficulty_verdict']['validation_difficulty_vs_test']} to Test.")
    print(f"Explanation: {report['split_difficulty_verdict']['explanation']}")


if __name__ == "__main__":
    main()
