"""
Independent Challenge Dataset Generator — Boundary & Adversarial Engine
========================================================================

Generates out-of-distribution, boundary, and rare email security feature combinations
via independent parameter space exploration and adversarial-but-valid probing.

Key Architecture:
- Does NOT reuse training scenario family templates.
- Employs 4 distinct exploration strategies:
  1. BOUNDARY_SEARCH: Probes decision boundaries across all adjacent risk classes.
  2. PARTIAL_CAPTURE_SIMULATION: Stresses missing evidence (high NaN) in TLS handshakes.
  3. RARE_INTERACTION_EXPLORATION: Samples uncommon but RFC-valid protocol/cipher pairings.
  4. ADVERSARIAL_VALID_PROBING: Decouples finding counts from features within valid domain limits.
- Tagged with metadata ``data_source = CHALLENGE_SYNTHETIC``.
- Ground-truth risk labels derived strictly via `calculate_session_risk`.
- Validated via `validate_feature_row`.

CLI Usage::

    python -m ml.training.challenge_generator \\
        --samples 500 \\
        --random-state 1337 \\
        --output data/processed/challenge.csv
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS
from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.dataset_validator import validate_feature_row


CHALLENGE_EXPLORATION_MODES = [
    # ── 1. Boundary Search Modes ──
    "CHALLENGE_BOUNDARY_LOW_MED_CERT_VISIBILITY",
    "CHALLENGE_BOUNDARY_LOW_MED_MIN_FINDINGS",
    "CHALLENGE_BOUNDARY_MED_HIGH_COMPOUNDING_MODERATE",
    "CHALLENGE_BOUNDARY_MED_HIGH_ISOLATED_WEAK_KEY",
    "CHALLENGE_BOUNDARY_HIGH_CRIT_ZERO_CRIT_PLAINTEXT",
    "CHALLENGE_BOUNDARY_HIGH_CRIT_EARLY_AUTH_WITH_TLS13",
    "CHALLENGE_BOUNDARY_HIGH_CRIT_STARTTLS_FAIL_COMPOUNDING",

    # ── 2. Partial Capture Simulation Modes ──
    "CHALLENGE_PARTIAL_CAPTURE_UNOBSERVED_CERT_POP3",
    "CHALLENGE_PARTIAL_CAPTURE_UNOBSERVED_CERT_IMAP",
    "CHALLENGE_PARTIAL_CAPTURE_STARTTLS_NEGOTIATION_TRUNCATED",
    "CHALLENGE_PARTIAL_CAPTURE_IMPLICIT_HIGH_NAN_CLEAN",

    # ── 3. Rare Interaction Exploration ──
    "CHALLENGE_RARE_POP3_STARTTLS_LEGACY_CIPHER",
    "CHALLENGE_RARE_IMAP_DEPRECATED_TLS_WITH_PFS",
    "CHALLENGE_RARE_SMTP_WEAK_CIPHER_WITH_CLEAN_CERT",
    "CHALLENGE_RARE_NOT_YET_VALID_CERT_ISOLATED",
    "CHALLENGE_RARE_POP3_PLAINTEXT_HIGH_ACTIVITY",

    # ── 4. Adversarial Valid Probing ──
    "CHALLENGE_ADVERSARIAL_MULTIPLE_HIGH_NO_CRIT_LABEL",
    "CHALLENGE_ADVERSARIAL_CRITICAL_WITH_ZERO_FINDINGS",
    "CHALLENGE_ADVERSARIAL_HIGH_WITH_ZERO_HIGH_COUNT",
    "CHALLENGE_ADVERSARIAL_MED_WITH_HIGH_LOW_COUNT",
]


def _explore_challenge_state(
    mode: str,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Construct an out-of-distribution feature state based on the exploration mode."""
    row: Dict[str, Any] = {f: np.nan for f in ALL_FEATURES}

    # Challenge set stresses POP3 (40%) and IMAP (35%) over SMTP (25%)
    if "POP3" in mode:
        proto = "POP3"
    elif "IMAP" in mode:
        proto = "IMAP"
    elif "SMTP" in mode:
        proto = "SMTP"
    else:
        proto = str(rng.choice(["POP3", "IMAP", "SMTP"], p=[0.40, 0.35, 0.25]))

    row["protocol_smtp"] = 1.0 if proto == "SMTP" else 0.0
    row["protocol_imap"] = 1.0 if proto == "IMAP" else 0.0
    row["protocol_pop3"] = 1.0 if proto == "POP3" else 0.0

    # ── 1. Boundary Search Modes ──
    if mode == "CHALLENGE_BOUNDARY_LOW_MED_CERT_VISIBILITY":
        # Tests boundary where unobservable cert + low_count = 1 -> LOW, but low_count >= 2 -> MEDIUM
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        # Cert unobservable (NaN)
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        # Boundary trigger: low_count determines whether LOW (1) or MEDIUM (2)
        row["low_count"] = int(rng.choice([1, 2], p=[0.5, 0.5]))
        row["medium_count"] = 0
        row["high_count"] = 0
        row["critical_count"] = 0

    elif mode == "CHALLENGE_BOUNDARY_LOW_MED_MIN_FINDINGS":
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = float(rng.choice([0.0, 1.0], p=[0.5, 0.5]))
        row["low_count"] = int(rng.choice([1, 2, 3]))
        row["medium_count"] = 1 if row["self_signed"] == 1.0 else 0
        row["high_count"] = 0
        row["critical_count"] = 0

    elif mode == "CHALLENGE_BOUNDARY_MED_HIGH_COMPOUNDING_MODERATE":
        # Tests compounding moderate flaws: self_signed + pfs_missing + med_cnt >= 2 -> HIGH
        # vs self_signed + pfs_missing + med_cnt = 1 -> MEDIUM
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 1.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 1.0
        row["critical_count"] = 0
        row["high_count"] = 0
        # Boundary trigger: med_cnt >= 2 escalates to HIGH, med_cnt == 1 stays MEDIUM
        row["medium_count"] = int(rng.choice([1, 2, 3], p=[0.35, 0.45, 0.20]))
        row["low_count"] = int(rng.choice([0, 1, 2]))

    elif mode == "CHALLENGE_BOUNDARY_MED_HIGH_ISOLATED_WEAK_KEY":
        is_implicit = bool(rng.choice([True, False]))
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
        row["weak_key"] = 1.0
        row["self_signed"] = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([0, 1], p=[0.3, 0.7]))
        row["medium_count"] = int(rng.choice([0, 1, 2]))
        row["low_count"] = int(rng.choice([0, 1]))

    elif mode == "CHALLENGE_BOUNDARY_HIGH_CRIT_ZERO_CRIT_PLAINTEXT":
        # Plaintext with zero critical findings -> CRITICAL via plaintext exposure rule
        row["encryption_plaintext"] = 1.0
        row["encryption_starttls"] = 0.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = float(rng.choice([0.0, 1.0], p=[0.5, 0.5]))
        row["deprecated_tls"] = np.nan
        row["weak_cipher"] = np.nan
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([0, 1, 2], p=[0.5, 0.35, 0.15]))
        row["medium_count"] = int(rng.choice([0, 1, 2]))
        row["low_count"] = int(rng.choice([0, 1]))

    elif mode == "CHALLENGE_BOUNDARY_HIGH_CRIT_EARLY_AUTH_WITH_TLS13":
        # Modern TLS negotiated, but auth transmitted before STARTTLS -> CRITICAL
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 1.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = int(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        row["high_count"] = int(rng.choice([0, 1]))
        row["medium_count"] = 0
        row["low_count"] = 0

    elif mode == "CHALLENGE_BOUNDARY_HIGH_CRIT_STARTTLS_FAIL_COMPOUNDING":
        # STARTTLS upgrade failed combined with weak cipher / deprecated TLS -> CRITICAL
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 1.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = float(rng.choice([0.0, 1.0], p=[0.5, 0.5]))
        row["weak_cipher"] = 1.0 if row["deprecated_tls"] == 0.0 else float(rng.choice([0.0, 1.0]))
        row["pfs_missing"] = np.nan
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([1, 2, 3]))
        row["medium_count"] = int(rng.choice([0, 1]))
        row["low_count"] = 0

    # ── 2. Partial Capture Simulation Modes ──
    elif "PARTIAL_CAPTURE" in mode:
        is_implicit = ("IMPLICIT" in mode)
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 1.0 if "TRUNCATED" in mode else 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = float(rng.choice([0.0, 1.0]))
        row["expired_cert"] = np.nan
        row["not_yet_valid_cert"] = np.nan
        row["weak_key"] = np.nan
        row["self_signed"] = np.nan
        row["critical_count"] = 0
        row["high_count"] = 1 if row["tls_upgrade_failed"] == 1.0 else 0
        row["medium_count"] = 1 if row["pfs_missing"] == 1.0 else 0
        row["low_count"] = int(rng.choice([0, 1]))

    # ── 3. Rare Interaction Exploration ──
    elif mode == "CHALLENGE_RARE_POP3_STARTTLS_LEGACY_CIPHER":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 1.0
        row["weak_cipher"] = 1.0
        row["pfs_missing"] = 1.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
        row["self_signed"] = float(rng.choice([0.0, 1.0], p=[0.6, 0.4]))
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([1, 2, 3]))
        row["medium_count"] = int(rng.choice([0, 1, 2]))
        row["low_count"] = 0

    elif mode == "CHALLENGE_RARE_IMAP_DEPRECATED_TLS_WITH_PFS":
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 1.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0  # Rare: TLS 1.0/1.1 with ECDHE
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([0, 1, 2], p=[0.25, 0.65, 0.10]))
        row["medium_count"] = int(rng.choice([0, 1]))
        row["low_count"] = int(rng.choice([0, 1]))

    elif mode == "CHALLENGE_RARE_SMTP_WEAK_CIPHER_WITH_CLEAN_CERT":
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 1.0
        row["encryption_implicit"] = 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 1.0
        row["pfs_missing"] = float(rng.choice([0.0, 1.0]))
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([0, 1], p=[0.25, 0.75]))
        row["medium_count"] = int(rng.choice([0, 1]))
        row["low_count"] = int(rng.choice([0, 1]))

    elif mode == "CHALLENGE_RARE_NOT_YET_VALID_CERT_ISOLATED":
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 1.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([0, 1], p=[0.3, 0.7]))
        row["medium_count"] = int(rng.choice([0, 1]))
        row["low_count"] = 0

    elif mode == "CHALLENGE_RARE_POP3_PLAINTEXT_HIGH_ACTIVITY":
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
        row["critical_count"] = int(rng.choice([1, 2, 3], p=[0.5, 0.35, 0.15]))
        row["high_count"] = int(rng.choice([1, 2]))
        row["medium_count"] = 1
        row["low_count"] = 1

    # ── 4. Adversarial Valid Probing ──
    elif mode == "CHALLENGE_ADVERSARIAL_MULTIPLE_HIGH_NO_CRIT_LABEL":
        # 3 high findings on a deprecated TLS session, but no compounding into CRITICAL -> HIGH
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 1.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = int(rng.choice([2, 3]))
        row["medium_count"] = int(rng.choice([1, 2]))
        row["low_count"] = int(rng.choice([1, 2]))

    elif mode == "CHALLENGE_ADVERSARIAL_CRITICAL_WITH_ZERO_FINDINGS":
        # Plaintext session with ZERO findings across all severities -> CRITICAL
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
        row["critical_count"] = 0
        row["high_count"] = 0
        row["medium_count"] = 0
        row["low_count"] = 0

    elif mode == "CHALLENGE_ADVERSARIAL_HIGH_WITH_ZERO_HIGH_COUNT":
        # Deprecated TLS session with zero high findings -> HIGH
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 1.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 0.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = 0
        row["medium_count"] = int(rng.choice([1, 2]))
        row["low_count"] = int(rng.choice([0, 1]))

    else:  # CHALLENGE_ADVERSARIAL_MED_WITH_HIGH_LOW_COUNT
        is_implicit = bool(rng.choice([True, False]))
        row["encryption_plaintext"] = 0.0
        row["encryption_starttls"] = 0.0 if is_implicit else 1.0
        row["encryption_implicit"] = 1.0 if is_implicit else 0.0
        row["tls_upgrade_failed"] = 0.0
        row["auth_before_tls"] = 0.0
        row["deprecated_tls"] = 0.0
        row["weak_cipher"] = 0.0
        row["pfs_missing"] = 1.0
        row["expired_cert"] = 0.0
        row["not_yet_valid_cert"] = 0.0
        row["weak_key"] = 0.0
        row["self_signed"] = 0.0
        row["critical_count"] = 0
        row["high_count"] = 0
        row["medium_count"] = 0  # Missing PFS but zero medium findings
        row["low_count"] = int(rng.choice([3, 4]))

    return row


def generate_challenge_dataset(
    n_samples: int = 500,
    random_state: int = 1337,
    exclude_signatures: Optional[Set[Tuple[float, ...]]] = None,
) -> pd.DataFrame:
    """Generate an independent, boundary-focused challenge dataset."""
    rng = np.random.default_rng(random_state)
    rows: List[Dict[str, Any]] = []

    if exclude_signatures is None:
        train_path = Path("data/processed/train.csv")
        if train_path.is_file():
            tdf = pd.read_csv(train_path)
            exclude_signatures = set(tuple(r.fillna(-999.0)) for _, r in tdf[ALL_FEATURES].iterrows())

    mode_idx = 0
    attempts = 0
    max_attempts = n_samples * 100

    while len(rows) < n_samples and attempts < max_attempts:
        attempts += 1
        mode = CHALLENGE_EXPLORATION_MODES[mode_idx % len(CHALLENGE_EXPLORATION_MODES)]
        mode_idx += 1

        candidate = _explore_challenge_state(mode, rng)

        # 1. Canonical Risk Aggregator derives risk label
        derived_label, reasons = calculate_session_risk(candidate)
        candidate["risk_label"] = derived_label

        # 2. Validate against domain constraints
        is_valid, errors = validate_feature_row(candidate)
        if not is_valid:
            continue

        # 3. Ensure zero overlap with training signatures
        sig = tuple(
            -999.0 if (candidate.get(f) is None or (isinstance(candidate.get(f), float) and math.isnan(candidate[f])))
            else float(candidate[f])
            for f in ALL_FEATURES
        )
        if exclude_signatures and sig in exclude_signatures:
            continue

        sample_idx = len(rows) + 1
        proto_name = "smtp" if candidate["protocol_smtp"] == 1 else (
            "imap" if candidate["protocol_imap"] == 1 else "pop3"
        )

        full_row: Dict[str, Any] = {
            "analysis_id": f"challenge-{sample_idx // 4 + 1:04d}",
            "session_id": f"chal-{proto_name}-{sample_idx:05d}",
            "scenario_id": f"{mode}-{sample_idx:04d}",
            "scenario_family": mode,
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
    parser = argparse.ArgumentParser(
        description="Generate independent challenge dataset for SecureMailScope."
    )
    parser.add_argument("--samples", type=int, default=500, help="Number of challenge samples.")
    parser.add_argument("--random-state", type=int, default=1337, help="Random seed.")
    parser.add_argument("--output", default="data/processed/challenge.csv", help="Output CSV path.")
    args = parser.parse_args(argv)

    print(f"Generating {args.samples} independent challenge samples...")
    df = generate_challenge_dataset(args.samples, args.random_state)

    print(f"  Generated {len(df)} challenge samples.")
    print("  Class distribution:")
    for label, count in df["risk_label"].value_counts().items():
        print(f"    {label}: {count}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"  Saved challenge dataset to: {output_path}")


if __name__ == "__main__":
    main()
