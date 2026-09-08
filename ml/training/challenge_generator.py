"""
Independent Challenge Dataset Generator
=======================================

Generates 300–500 out-of-distribution, boundary, and rare email security
feature combinations to rigorously evaluate model generalization.

Properties:
- Uses independent scenario logic not present in the main training templates.
- Includes complex boundary cases, unusual protocol distributions, and high-NaN captures.
- Tagged with metadata ``data_source = CHALLENGE_SYNTHETIC``.
- Strictly isolated: NEVER used during model fitting or validation selection.
- All rows are derived through the Canonical Risk Aggregator and validated against domain constraints.

CLI Usage::

    python -m ml.training.challenge_generator \\
        --samples 400 \\
        --random-state 1337 \\
        --output data/processed/challenge.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.dataset_validator import validate_feature_row


CHALLENGE_FAMILIES = [
    # ── Boundary & Rare Low/Medium ───────────────────────────────────
    "CHALLENGE_LOW_IMPLICIT_HIGH_NAN_BENIGN",
    "CHALLENGE_LOW_POP3_UNUSUAL_PORT_CLEAN",
    "CHALLENGE_MED_TLS13_SELF_SIGNED_ISOLATED",
    "CHALLENGE_MED_PARTIAL_CAPTURE_PFS_MISSING",
    "CHALLENGE_MED_STARTTLS_MULTIPLE_LOW_FINDINGS",

    # ── Boundary & Rare Medium/High ──────────────────────────────────
    "CHALLENGE_HIGH_COMPOUNDING_MED_WEAKNESSES",
    "CHALLENGE_HIGH_RARE_POP3_DEPRECATED_TLS",
    "CHALLENGE_HIGH_NOT_YET_VALID_PARTIAL_CERT",
    "CHALLENGE_HIGH_WEAK_CIPHER_WITH_PFS",
    "CHALLENGE_HIGH_FAILED_STARTTLS_POP3",

    # ── Boundary & Rare High/Critical ────────────────────────────────
    "CHALLENGE_CRIT_PLAINTEXT_HIGH_FINDINGS_NO_CRIT_COUNT",
    "CHALLENGE_CRIT_COMPOUNDING_MAJOR_FAILURES_NO_CRIT",
    "CHALLENGE_CRIT_EARLY_AUTH_WITH_EXPIRED_CERT",
    "CHALLENGE_CRIT_STARTTLS_DOWNGRADE_AND_FAIL",
    "CHALLENGE_CRIT_PLAINTEXT_POP3_MINIMAL_CAPTURE",
]


def generate_challenge_row(
    family: str,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Generate a single challenge session featuring novel or boundary conditions."""
    row: Dict[str, Any] = {f: np.nan for f in ALL_FEATURES}

    # Protocol sampling: challenge set deliberately stresses POP3 and IMAP
    proto = str(rng.choice(["SMTP", "IMAP", "POP3"], p=[0.30, 0.35, 0.35]))
    row["protocol_smtp"] = 1.0 if proto == "SMTP" else 0.0
    row["protocol_imap"] = 1.0 if proto == "IMAP" else 0.0
    row["protocol_pop3"] = 1.0 if proto == "POP3" else 0.0

    crit_cnt = 0
    high_cnt = 0
    med_cnt = 0
    low_cnt = 0

    if family == "CHALLENGE_LOW_IMPLICIT_HIGH_NAN_BENIGN":
        # Implicit TLS with unobservable cert, zero findings
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0
        row["encryption_implicit"] = 1.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        # Cert entirely unobservable (high NaN)
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        low_cnt = 0

    elif family == "CHALLENGE_LOW_POP3_UNUSUAL_PORT_CLEAN":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        low_cnt = int(rng.choice([1, 2]))

    elif family == "CHALLENGE_MED_TLS13_SELF_SIGNED_ISOLATED":
        # TLS 1.3 with isolated self-signed cert
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = float(rng.choice([0.0, 1.0]))
        row["encryption_implicit"] = 1.0 - row["encryption_starttls"]
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 1.0
        med_cnt = 1
        low_cnt = 0

    elif family == "CHALLENGE_MED_PARTIAL_CAPTURE_PFS_MISSING":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 1.0
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        med_cnt = 1
        low_cnt = 1

    elif family == "CHALLENGE_MED_STARTTLS_MULTIPLE_LOW_FINDINGS":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        low_cnt = 3
        med_cnt = 0

    elif family == "CHALLENGE_HIGH_COMPOUNDING_MED_WEAKNESSES":
        # Compounding moderate weaknesses (self-signed + missing PFS) with zero high findings
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = float(rng.choice([0.0, 1.0]))
        row["encryption_implicit"] = 1.0 - row["encryption_starttls"]
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 1.0
        row["pfs_missing"] = 1.0
        high_cnt = 0  # High risk via compounding!
        med_cnt = 2
        low_cnt = 1

    elif family == "CHALLENGE_HIGH_RARE_POP3_DEPRECATED_TLS":
        row["protocol_pop3"] = 1.0
        row["protocol_smtp"] = 0.0
        row["protocol_imap"] = 0.0
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 1.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        high_cnt = 1
        med_cnt = 0

    elif family == "CHALLENGE_HIGH_NOT_YET_VALID_PARTIAL_CERT":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = np.nan
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 1.0
        row["weak_key"] = np.nan
        row["self_signed"] = 0.0
        high_cnt = 1

    elif family == "CHALLENGE_HIGH_WEAK_CIPHER_WITH_PFS":
        # Rare state: weak cipher negotiated despite PFS support
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 1.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        high_cnt = 1
        med_cnt = 1

    elif family == "CHALLENGE_HIGH_FAILED_STARTTLS_POP3":
        row["protocol_pop3"] = 1.0
        row["protocol_smtp"] = 0.0
        row["protocol_imap"] = 0.0
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 1.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = np.nan
        row["weak_cipher"] = np.nan
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        high_cnt = 1

    elif family == "CHALLENGE_CRIT_PLAINTEXT_HIGH_FINDINGS_NO_CRIT_COUNT":
        # Plaintext session with high_count = 2, critical_count = 0 -> Still CRITICAL!
        row["encryption_plaintext"] = 1.0
        row["encryption_starttls"] = 0.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = np.nan
        row["weak_cipher"] = np.nan
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        crit_cnt = 0  # CRITICAL with zero critical findings!
        high_cnt = 2
        med_cnt = 1

    elif family == "CHALLENGE_CRIT_COMPOUNDING_MAJOR_FAILURES_NO_CRIT":
        # STARTTLS upgrade failed + weak cipher + deprecated TLS (compounding critical)
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
        high_cnt = 3
        med_cnt = 1

    elif family == "CHALLENGE_CRIT_EARLY_AUTH_WITH_EXPIRED_CERT":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 1.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 1.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        crit_cnt = 1
        high_cnt = 1

    elif family == "CHALLENGE_CRIT_STARTTLS_DOWNGRADE_AND_FAIL":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 1.0
        row["auth_before_tls"] = 1.0
        row["deprecated_tls"] = np.nan
        row["weak_cipher"] = np.nan
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        crit_cnt = 1
        high_cnt = 1

    else:  # CHALLENGE_CRIT_PLAINTEXT_POP3_MINIMAL_CAPTURE
        row["protocol_pop3"] = 1.0
        row["protocol_smtp"] = 0.0
        row["protocol_imap"] = 0.0
        row["encryption_plaintext"] = 1.0
        row["encryption_starttls"] = 0.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 1.0
        row["deprecated_tls"] = np.nan
        row["weak_cipher"] = np.nan
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        crit_cnt = 1
        low_cnt = 1

    row["critical_count"] = crit_cnt
    row["high_count"] = high_cnt
    row["medium_count"] = med_cnt
    row["low_count"] = low_cnt

    return row


def generate_challenge_dataset(
    n_samples: int = 400,
    random_state: int = 1337,
) -> pd.DataFrame:
    """Generate the independent challenge dataset."""
    rng = np.random.default_rng(random_state)
    rows: List[Dict[str, Any]] = []

    samples_per_family = max(1, n_samples // len(CHALLENGE_FAMILIES))
    count = 0

    for family in CHALLENGE_FAMILIES:
        for _ in range(samples_per_family):
            candidate = generate_challenge_row(family, rng)
            derived_label, _ = calculate_session_risk(candidate)
            candidate["risk_label"] = derived_label

            is_valid, errors = validate_feature_row(candidate)
            if not is_valid:
                continue

            count += 1
            proto_name = "smtp" if candidate["protocol_smtp"] == 1 else (
                "imap" if candidate["protocol_imap"] == 1 else "pop3"
            )

            full_row: Dict[str, Any] = {
                "analysis_id": f"challenge-{count // 4 + 1:04d}",
                "session_id": f"{proto_name}-ch-{count:05d}",
                "scenario_id": f"{family}-{count:04d}",
                "scenario_family": family,
                "data_source": "CHALLENGE_SYNTHETIC",
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
    parser = argparse.ArgumentParser(description="Generate independent challenge dataset.")
    parser.add_argument("--samples", type=int, default=400, help="Number of challenge samples.")
    parser.add_argument("--random-state", type=int, default=1337, help="Random seed.")
    parser.add_argument("--output", default="data/processed/challenge.csv", help="Output path.")
    args = parser.parse_args(argv)

    print(f"Generating {args.samples} independent challenge samples (seed={args.random_state})...")
    df = generate_challenge_dataset(args.samples, args.random_state)

    print(f"  Generated {len(df)} challenge rows.")
    print("  Class distribution:")
    for label, count in df["risk_label"].value_counts().items():
        print(f"    {label}: {count}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"  Saved challenge dataset to: {output_path}")


if __name__ == "__main__":
    main()
