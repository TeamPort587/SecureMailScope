"""
Scenario-Based Synthetic Dataset Generator
==========================================

Generates realistic, logically consistent email security feature vectors
across all four risk classes (LOW, MEDIUM, HIGH, CRITICAL) and protocols
(SMTP, IMAP, POP3) using the canonical Risk Aggregator.

Architecture:
    UNDERLYING SECURITY SCENARIO
            ↓
    FEATURE STATE (Protocol, Encryption, TLS, Cert)
            ↓
    FINDING SEVERITY COUNTS
            ↓
    CANONICAL RISK AGGREGATOR
            ↓
    RISK LABEL & VALIDATION

CLI Usage::

    python -m ml.training.synthetic_generator \\
        --samples 1600 \\
        --random-state 42 \\
        --output data/processed/synthetic_dataset.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.dataset_validator import validate_feature_row


# ── Scenario Families ───────────────────────────────────────────────

SCENARIO_FAMILIES: Dict[str, List[str]] = {
    "LOW": [
        "LOW_MODERN_TLS_PFS",
        "LOW_IMPLICIT_MODERN_TLS",
        "LOW_STARTTLS_UNOBSERVABLE_CERT",
        "LOW_IMPLICIT_UNOBSERVABLE_CERT",
        "LOW_MODERN_TLS_CLEAN_WITH_INFO",
        "LOW_IMPLICIT_CLEAN_LOW_FINDING",
        "LOW_BOUNDARY_STRONG_TLS_MINOR_LOW",
    ],
    "MEDIUM": [
        "MED_SELF_SIGNED_CERT",
        "MED_MISSING_PFS",
        "MED_LIMITED_CERT_VISIBILITY",
        "MED_MINOR_FINDINGS_COMBINED",
        "MED_SELF_SIGNED_IMPLICIT",
        "MED_PFS_MISSING_IMPLICIT",
        "MED_BOUNDARY_PFS_MISSING_WITH_LOWS",
    ],
    "HIGH": [
        "HIGH_DEPRECATED_TLS",
        "HIGH_WEAK_CIPHER",
        "HIGH_EXPIRED_CERT",
        "HIGH_NOT_YET_VALID_CERT",
        "HIGH_WEAK_KEY",
        "HIGH_FAILED_STARTTLS",
        "HIGH_DEPRECATED_AND_WEAK_CIPHER",
        "HIGH_WEAK_KEY_AND_EXPIRED_CERT",
        "HIGH_PFS_AND_SELF_SIGNED_COMPOUNDING",
        "HIGH_BOUNDARY_WEAK_CIPHER_WITH_MEDS",
    ],
    "CRITICAL": [
        "CRIT_PLAINTEXT_TRAFFIC",
        "CRIT_PLAINTEXT_WITH_AUTH",
        "CRIT_STARTTLS_AUTH_BEFORE_TLS",
        "CRIT_STARTTLS_AUTH_EARLY_AND_FAILED_UPGRADE",
        "CRIT_PLAINTEXT_MULTIPLE_EXPOSURES",
        "CRIT_STARTTLS_AUTH_EARLY_WEAK_CIPHER",
        "CRIT_COMPOUNDING_FAILURES_NO_CRIT_FINDINGS",
    ],
}


def _sample_protocol(rng: np.random.Generator) -> str:
    """Sample protocol: SMTP ~40%, IMAP ~35%, POP3 ~25%."""
    return str(rng.choice(["SMTP", "IMAP", "POP3"], p=[0.40, 0.35, 0.25]))


def generate_scenario_features(
    family: str,
    target_class: str,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Generate underlying security scenario features and finding counts.

    The final label is NOT hardcoded here; it is determined by the Canonical
    Risk Aggregator based on the complete observable state.
    """
    row: Dict[str, Any] = {f: np.nan for f in ALL_FEATURES}
    proto = _sample_protocol(rng)

    row["protocol_smtp"] = 1.0 if proto == "SMTP" else 0.0
    row["protocol_imap"] = 1.0 if proto == "IMAP" else 0.0
    row["protocol_pop3"] = 1.0 if proto == "POP3" else 0.0

    crit_cnt = 0
    high_cnt = 0
    med_cnt = 0
    low_cnt = 0

    # ── 1. LOW Scenario Families ─────────────────────────────────────
    if target_class == "LOW":
        is_implicit = ("IMPLICIT" in family)
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0

        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0

        if "UNOBSERVABLE_CERT" in family:
            row["expired_cert"] = np.nan
            row["not_yet_valid_cert"] = np.nan
            row["weak_key"] = np.nan
            row["self_signed"] = np.nan
        else:
            row["expired_cert"] = 0.0
            row["not_yet_valid_cert"] = 0.0
            row["weak_key"] = 0.0
            row["self_signed"] = 0.0

        # Non-zero low findings allowed for benign traffic
        if "LOW_FINDING" in family or "WITH_INFO" in family or "MINOR_LOW" in family:
            low_cnt = int(rng.choice([1, 2]))
        else:
            low_cnt = int(rng.choice([0, 1], p=[0.6, 0.4]))

        crit_cnt = 0
        high_cnt = 0
        med_cnt = 0

    # ── 2. MEDIUM Scenario Families ──────────────────────────────────
    elif target_class == "MEDIUM":
        is_implicit = ("IMPLICIT" in family)
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0

        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["pfs_missing"] = 0.0

        if "SELF_SIGNED" in family:
            row["self_signed"] = 1.0
            med_cnt = int(rng.choice([1, 2]))
            low_cnt = int(rng.choice([0, 1, 2]))
        elif "MISSING_PFS" in family or "PFS_MISSING" in family:
            row["pfs_missing"] = 1.0
            med_cnt = int(rng.choice([1, 2]))
            low_cnt = int(rng.choice([0, 1]))
        elif "LIMITED_CERT_VISIBILITY" in family:
            row["expired_cert"] = np.nan
            row["not_yet_valid_cert"] = np.nan
            row["weak_key"] = np.nan
            row["self_signed"] = np.nan
            low_cnt = int(rng.choice([2, 3]))
            med_cnt = int(rng.choice([0, 1]))
        else:  # Minor findings combined
            row["pfs_missing"] = float(rng.choice([0.0, 1.0], p=[0.6, 0.4]))
            med_cnt = int(rng.choice([1, 2]))
            low_cnt = int(rng.choice([1, 2, 3]))

        crit_cnt = 0
        high_cnt = 0

    # ── 3. HIGH Scenario Families ────────────────────────────────────
    elif target_class == "HIGH":
        if "FAILED_STARTTLS" in family:
            row["encryption_plaintext"] = 0.0
            row["encryption_starttls"] = 1.0
            row["encryption_implicit"] = 0.0
            row["tls_upgrade_failed"] = 1.0
            row["auth_before_tls"] = 0.0
            # Failed upgrade implies unobservable TLS & cert
            row["deprecated_tls"] = np.nan
            row["weak_cipher"] = np.nan
            row["pfs_missing"] = np.nan
            row["expired_cert"] = np.nan
            row["not_yet_valid_cert"] = np.nan
            row["weak_key"] = np.nan
            row["self_signed"] = np.nan
            high_cnt = int(rng.choice([1, 2]))
            med_cnt = int(rng.choice([0, 1]))
        elif "PFS_AND_SELF_SIGNED_COMPOUNDING" in family:
            # Compounding medium weaknesses escalating to HIGH without high_count >= 1!
            is_implicit = bool(rng.choice([True, False]))
            row["encryption_plaintext"] = 0.0
            row["encryption_starttls"] = 0.0 if is_implicit else 1.0
            row["encryption_implicit"] = 1.0 if is_implicit else 0.0
            row["tls_upgrade_failed"] = 0.0
            row["auth_before_tls"] = 0.0
            row["deprecated_tls"] = 0.0
            row["weak_cipher"] = 0.0
            row["expired_cert"] = 0.0
            row["not_yet_valid_cert"] = 0.0
            row["weak_key"] = 0.0
            row["self_signed"] = 1.0
            row["pfs_missing"] = 1.0
            high_cnt = 0  # Demonstrates HIGH with high_count == 0!
            med_cnt = int(rng.choice([2, 3]))
            low_cnt = int(rng.choice([0, 1, 2]))
        else:
            is_implicit = bool(rng.choice([True, False], p=[0.4, 0.6]))
            row["encryption_plaintext"] = 0.0
            row["encryption_starttls"] = 0.0 if is_implicit else 1.0
            row["encryption_implicit"] = 1.0 if is_implicit else 0.0
            row["tls_upgrade_failed"] = 0.0
            row["auth_before_tls"] = 0.0

            row["deprecated_tls"] = 0.0
            row["weak_cipher"] = 0.0
            row["pfs_missing"] = float(rng.choice([0.0, 1.0]))
            row["expired_cert"] = 0.0
            row["not_yet_valid_cert"] = 0.0
            row["weak_key"] = 0.0
            row["self_signed"] = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))

            if "DEPRECATED_TLS" in family:
                row["deprecated_tls"] = 1.0
                high_cnt = int(rng.choice([1, 2]))
            elif "WEAK_CIPHER" in family:
                row["weak_cipher"] = 1.0
                high_cnt = int(rng.choice([1, 2]))
            elif "EXPIRED_CERT" in family:
                row["expired_cert"] = 1.0
                high_cnt = int(rng.choice([1, 2]))
            elif "NOT_YET_VALID_CERT" in family:
                row["not_yet_valid_cert"] = 1.0
                high_cnt = int(rng.choice([1, 2]))
            elif "WEAK_KEY" in family:
                row["weak_key"] = 1.0
                high_cnt = int(rng.choice([1, 2]))
            elif "DEPRECATED_AND_WEAK_CIPHER" in family:
                row["deprecated_tls"] = 1.0
                row["weak_cipher"] = 1.0
                high_cnt = int(rng.choice([2, 3]))
            elif "WEAK_KEY_AND_EXPIRED_CERT" in family:
                row["weak_key"] = 1.0
                row["expired_cert"] = 1.0
                high_cnt = int(rng.choice([2, 3]))

            med_cnt = med_cnt or int(rng.choice([0, 1, 2]))
            low_cnt = low_cnt or int(rng.choice([0, 1, 2]))

        crit_cnt = 0

    # ── 4. CRITICAL Scenario Families ────────────────────────────────
    elif target_class == "CRITICAL":
        if "PLAINTEXT" in family:
            row["encryption_plaintext"] = 1.0
            row["encryption_starttls"] = 0.0
            row["encryption_implicit"] = 0.0
            row["tls_upgrade_failed"] = 0.0
            # Plaintext implies TLS and cert are not observable
            row["deprecated_tls"] = np.nan
            row["weak_cipher"] = np.nan
            row["pfs_missing"] = np.nan
            row["expired_cert"] = np.nan
            row["not_yet_valid_cert"] = np.nan
            row["weak_key"] = np.nan
            row["self_signed"] = np.nan

            if "WITH_AUTH" in family or "MULTIPLE_EXPOSURES" in family:
                row["auth_before_tls"] = 1.0
                crit_cnt = int(rng.choice([1, 2, 3]))
                high_cnt = int(rng.choice([0, 1, 2]))
            else:
                row["auth_before_tls"] = float(rng.choice([0.0, 1.0], p=[0.4, 0.6]))
                # CRITICAL with critical_count == 0! (Plaintext observable exposure)
                crit_cnt = int(rng.choice([0, 1, 2], p=[0.3, 0.4, 0.3]))
                high_cnt = int(rng.choice([0, 1]))

            med_cnt = int(rng.choice([0, 1]))
            low_cnt = int(rng.choice([0, 1]))

        elif "COMPOUNDING_FAILURES_NO_CRIT_FINDINGS" in family:
            # Demonstrates CRITICAL with critical_count == 0 due to compounding failure states!
            row["encryption_plaintext"] = 0.0
            row["encryption_starttls"] = 1.0
            row["encryption_implicit"] = 0.0
            row["tls_upgrade_failed"] = 1.0
            row["auth_before_tls"] = 0.0
            row["deprecated_tls"] = 1.0
            row["weak_cipher"] = 1.0
            row["pfs_missing"] = 1.0
            row["expired_cert"] = 0.0
            row["not_yet_valid_cert"] = 0.0
            row["weak_key"] = 0.0
            row["self_signed"] = 0.0
            crit_cnt = 0  # CRITICAL with zero critical findings!
            high_cnt = int(rng.choice([2, 3]))
            med_cnt = int(rng.choice([1, 2]))
            low_cnt = int(rng.choice([0, 1]))

        else:
            # STARTTLS with auth_before_tls
            row["encryption_plaintext"] = 0.0
            row["encryption_starttls"] = 1.0
            row["encryption_implicit"] = 0.0
            row["auth_before_tls"] = 1.0

            if "FAILED_UPGRADE" in family:
                row["tls_upgrade_failed"] = 1.0
                row["deprecated_tls"] = np.nan
                row["weak_cipher"] = np.nan
                row["pfs_missing"] = np.nan
                row["expired_cert"] = np.nan
                row["not_yet_valid_cert"] = np.nan
                row["weak_key"] = np.nan
                row["self_signed"] = np.nan
                crit_cnt = int(rng.choice([0, 1, 2], p=[0.25, 0.45, 0.30]))
                high_cnt = int(rng.choice([1, 2]))
            else:
                row["tls_upgrade_failed"] = 0.0
                row["deprecated_tls"] = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
                row["weak_cipher"] = 1.0 if "WEAK_CIPHER" in family else float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
                row["pfs_missing"] = float(rng.choice([0.0, 1.0]))
                row["expired_cert"] = 0.0
                row["not_yet_valid_cert"] = 0.0
                row["weak_key"] = 0.0
                row["self_signed"] = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
                crit_cnt = int(rng.choice([0, 1, 2], p=[0.2, 0.5, 0.3]))
                high_cnt = int(rng.choice([0, 1, 2]))

            med_cnt = int(rng.choice([0, 1, 2]))
            low_cnt = int(rng.choice([0, 1, 2]))

    row["critical_count"] = crit_cnt
    row["high_count"] = high_cnt
    row["medium_count"] = med_cnt
    row["low_count"] = low_cnt

    return row


def generate_synthetic_dataset(
    n_samples: int = 1600,
    random_state: int = 42,
) -> pd.DataFrame:
    """Generate a balanced, validated synthetic dataset of email security feature rows."""
    rng = np.random.default_rng(random_state)

    classes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    base_target = n_samples // len(classes)
    remainder = n_samples % len(classes)
    targets = {c: base_target + (1 if i < remainder else 0) for i, c in enumerate(classes)}

    rows: List[Dict[str, Any]] = []
    seen_signatures: set = set()
    sample_counter = 0

    for target_class in classes:
        target_count = targets[target_class]
        families = SCENARIO_FAMILIES[target_class]
        generated_for_class = 0

        family_idx = 0
        attempts = 0
        max_attempts = target_count * 25

        while generated_for_class < target_count and attempts < max_attempts:
            attempts += 1
            family = families[family_idx % len(families)]
            family_idx += 1

            candidate = generate_scenario_features(family, target_class, rng)

            # Determine risk label using the Canonical Risk Aggregator
            derived_label, reasons = calculate_session_risk(candidate)

            # Strict rule: Ensure derived label matches target class
            if derived_label != target_class:
                continue

            candidate["risk_label"] = derived_label

            # Validate against domain constraints
            is_valid, errors = validate_feature_row(candidate)
            if not is_valid:
                continue

            sample_counter += 1
            generated_for_class += 1

            proto_name = "smtp" if candidate["protocol_smtp"] == 1 else (
                "imap" if candidate["protocol_imap"] == 1 else "pop3"
            )

            full_row: Dict[str, Any] = {
                "analysis_id": f"synthetic-{sample_counter // 4 + 1:05d}",
                "session_id": f"{proto_name}-{sample_counter:06d}",
                "scenario_id": f"{family}-{generated_for_class:04d}",
                "scenario_family": family,
                "data_source": "CURATED_SYNTHETIC",
            }
            for feat in ALL_FEATURES:
                full_row[feat] = candidate[feat]
            full_row["risk_label"] = derived_label

            rows.append(full_row)

    df = pd.DataFrame(rows)
    metadata_cols = ["analysis_id", "session_id", "scenario_id", "scenario_family", "data_source"]
    final_cols = metadata_cols + ALL_FEATURES + ["risk_label"]
    return df[final_cols]


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate validated scenario-based synthetic dataset for SecureMailScope."
    )
    parser.add_argument("--samples", type=int, default=1600, help="Number of samples to generate.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument("--output", default="data/processed/synthetic_dataset.csv", help="Output path.")
    args = parser.parse_args(argv)

    print(f"Generating {args.samples} synthetic samples via Canonical Risk Aggregator...")
    df = generate_synthetic_dataset(args.samples, args.random_state)

    print(f"  Generated {len(df)} rows.")
    print("  Class distribution:")
    for label, count in df["risk_label"].value_counts().items():
        print(f"    {label}: {count}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"  Saved synthetic dataset to: {output_path}")


if __name__ == "__main__":
    main()
