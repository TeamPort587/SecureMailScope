"""
Scenario-Based Synthetic Dataset Generator — Feature-First Realism Engine
========================================================================

Generates realistic, logically consistent, diverse email security feature vectors
using a feature-first and risk-derived architecture:

    Generate valid session state
            ↓
    Generate observable security features (Protocol, Encryption, TLS, Certificate, Auth)
            ↓
    Apply controlled domain variability (Allowed variations, missing evidence, edge cases)
            ↓
    Generate finding counts (Probabilistic constrained reflection of security state)
            ↓
    Validate domain constraints
            ↓
    Apply Canonical Risk Aggregator (Risk label is an OUTPUT of the feature state)

Principles:
- Strict preservation of the canonical 19-feature schema.
- Deterministic risk derivation via `calculate_session_risk`.
- `critical_count >= 1` ALWAYS produces CRITICAL.
- CRITICAL can also occur with `critical_count == 0` (e.g., plaintext, early auth, compounding failures).
- Controlled domain variability: NO arbitrary label flips, NO invalid feature flips.
- High feature signature diversity across 6,000+ samples.

CLI Usage::

    python -m ml.training.synthetic_generator \\
        --samples 6400 \\
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


# ── Scenario & Posture Definitions ───────────────────────────────────

# Security Postures represent real-world email infrastructure archetypes
SECURITY_POSTURES = [
    # ── Modern / Benign Postures (Expected LOW) ──
    "POSTURE_MODERN_STRICT_TLS13",
    "POSTURE_MODERN_IMPLICIT_TLS",
    "POSTURE_MODERN_STARTTLS_CLEAN",
    "POSTURE_MODERN_TLS_OBSCURED_CERT",
    "POSTURE_MODERN_BENIGN_INFO_ALERTS",
    "POSTURE_BOUNDARY_LOW_MED_UNOBSERVED_HANDSHAKE",
    "POSTURE_BOUNDARY_LOW_MED_MINOR_LOW_FINDINGS",

    # ── Moderate Weakness Postures (Expected MEDIUM) ──
    "POSTURE_INTERNAL_SELF_SIGNED",
    "POSTURE_LEGACY_CIPHER_NO_PFS",
    "POSTURE_MODERATE_LIMITED_VISIBILITY",
    "POSTURE_SELF_SIGNED_IMPLICIT",
    "POSTURE_PFS_MISSING_IMPLICIT",
    "POSTURE_BOUNDARY_MED_HIGH_PFS_AND_SELF_SIGNED",
    "POSTURE_BOUNDARY_MED_HIGH_WEAK_KEY_ISOLATED",
    "POSTURE_BOUNDARY_LOW_MED_SELF_SIGNED_CLEAN_CIPHER",

    # ── Severe Flaw Postures (Expected HIGH) ──
    "POSTURE_DEPRECATED_TLS_LEGACY",
    "POSTURE_OBSOLETE_WEAK_CIPHER",
    "POSTURE_EXPIRED_CERTIFICATE",
    "POSTURE_NOT_YET_VALID_CERTIFICATE",
    "POSTURE_INSECURE_SHORT_KEY",
    "POSTURE_REJECTED_STARTTLS_UPGRADE",
    "POSTURE_DEPRECATED_TLS_AND_WEAK_CIPHER",
    "POSTURE_WEAK_KEY_AND_EXPIRED_CERT",
    "POSTURE_COMPOUNDING_MODERATE_ESCALATION",
    "POSTURE_BOUNDARY_HIGH_CRIT_STARTTLS_FAIL_OBSCURED",
    "POSTURE_BOUNDARY_HIGH_CRIT_MULTIPLE_HIGH_FINDINGS",

    # ── Critical Exposure Postures (Expected CRITICAL) ──
    "POSTURE_PLAINTEXT_TRAFFIC_UNENCRYPTED",
    "POSTURE_PLAINTEXT_WITH_AUTHENTICATION",
    "POSTURE_PLAINTEXT_MULTIPLE_SENSITIVE_EXPOSURES",
    "POSTURE_STARTTLS_AUTH_BEFORE_TLS_STRICT",
    "POSTURE_STARTTLS_AUTH_BEFORE_TLS_PERMISSIVE",
    "POSTURE_STARTTLS_EARLY_AUTH_FAILED_UPGRADE",
    "POSTURE_STARTTLS_EARLY_AUTH_WEAK_CIPHER",
    "POSTURE_COMPOUNDING_FAILURES_NO_CRIT_COUNT",
]


def sample_protocol(rng: np.random.Generator) -> str:
    """Sample protocol according to realistic mail server traffic.

    SMTP ~40%, IMAP ~35%, POP3 ~25%.
    """
    return str(rng.choice(["SMTP", "IMAP", "POP3"], p=[0.40, 0.35, 0.25]))


def generate_protocol_state(protocol: str) -> Dict[str, float]:
    """Generate one-hot protocol feature state."""
    return {
        "protocol_smtp": 1.0 if protocol == "SMTP" else 0.0,
        "protocol_imap": 1.0 if protocol == "IMAP" else 0.0,
        "protocol_pop3": 1.0 if protocol == "POP3" else 0.0,
    }


def generate_encryption_state(
    posture: str,
    protocol: str,
    rng: np.random.Generator,
) -> Tuple[str, Dict[str, float]]:
    """Determine encryption mode and one-hot encoding conditioned on posture and protocol.

    Modes: PLAINTEXT, STARTTLS, IMPLICIT_TLS.
    """
    if "PLAINTEXT" in posture:
        mode = "PLAINTEXT"
    elif "IMPLICIT" in posture:
        mode = "IMPLICIT_TLS"
    elif "STARTTLS" in posture or "REJECTED" in posture:
        mode = "STARTTLS"
    else:
        # Default distribution based on protocol:
        # SMTP: mostly STARTTLS (75%), implicit (25%)
        # IMAP/POP3: implicit (55%), STARTTLS (45%)
        if protocol == "SMTP":
            mode = str(rng.choice(["STARTTLS", "IMPLICIT_TLS"], p=[0.75, 0.25]))
        else:
            mode = str(rng.choice(["IMPLICIT_TLS", "STARTTLS"], p=[0.55, 0.45]))

    return mode, {
        "encryption_plaintext": 1.0 if mode == "PLAINTEXT" else 0.0,
        "encryption_starttls": 1.0 if mode == "STARTTLS" else 0.0,
        "encryption_implicit": 1.0 if mode == "IMPLICIT_TLS" else 0.0,
    }


def generate_tls_state(
    posture: str,
    enc_mode: str,
    rng: np.random.Generator,
) -> Dict[str, float]:
    """Generate TLS feature state conditioned on encryption mode and posture.

    Plaintext sessions MUST have NaN for all TLS features.
    Failed STARTTLS sessions MUST have NaN for negotiated TLS features.
    """
    if enc_mode == "PLAINTEXT":
        return {
            "tls_upgrade_failed": 0.0,
            "deprecated_tls": np.nan,
            "weak_cipher": np.nan,
            "pfs_missing": np.nan,
        }

    # STARTTLS upgrade failure scenarios
    if "REJECTED" in posture or "FAILED_UPGRADE" in posture:
        return {
            "tls_upgrade_failed": 1.0,
            "deprecated_tls": np.nan,
            "weak_cipher": np.nan,
            "pfs_missing": np.nan,
        }

    if "BOUNDARY_HIGH_CRIT_STARTTLS_FAIL" in posture:
        return {
            "tls_upgrade_failed": 1.0,
            # In boundary case, client may have attempted fallback or observed partial handshake
            "deprecated_tls": np.nan,
            "weak_cipher": np.nan,
            "pfs_missing": np.nan,
        }

    tls_fail = 0.0

    # Base TLS states by posture
    if "DEPRECATED_TLS" in posture:
        dep_tls = 1.0
        weak_ciph = 1.0 if "WEAK_CIPHER" in posture else float(rng.choice([0.0, 1.0], p=[0.6, 0.4]))
        pfs_miss = float(rng.choice([0.0, 1.0], p=[0.3, 0.7]))
    elif "WEAK_CIPHER" in posture or "OBSOLETE" in posture:
        dep_tls = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
        weak_ciph = 1.0
        pfs_miss = float(rng.choice([0.0, 1.0], p=[0.4, 0.6]))
    elif "NO_PFS" in posture or "PFS_MISSING" in posture:
        dep_tls = 0.0
        weak_ciph = 0.0
        pfs_miss = 1.0
    elif "COMPOUNDING_FAILURES_NO_CRIT" in posture:
        dep_tls = 1.0
        weak_ciph = 1.0
        pfs_miss = 1.0
        tls_fail = float(rng.choice([0.0, 1.0], p=[0.3, 0.7]))
    elif "COMPOUNDING_MODERATE" in posture or "PFS_AND_SELF_SIGNED" in posture:
        dep_tls = 0.0
        weak_ciph = 0.0
        pfs_miss = 1.0
    else:
        # Clean modern TLS (TLS 1.2 or 1.3)
        dep_tls = 0.0
        weak_ciph = 0.0
        # Controlled variation: PFS missing occasionally even in modern TLS (10%)
        pfs_miss = float(rng.choice([0.0, 1.0], p=[0.88, 0.12]))

    return {
        "tls_upgrade_failed": tls_fail,
        "deprecated_tls": dep_tls,
        "weak_cipher": weak_ciph,
        "pfs_missing": pfs_miss,
    }


def generate_certificate_state(
    posture: str,
    enc_mode: str,
    tls_state: Dict[str, float],
    rng: np.random.Generator,
) -> Dict[str, float]:
    """Generate X.509 certificate feature state conditioned on TLS state and posture.

    Plaintext or failed upgrade sessions MUST have NaN for certificate features.
    """
    if enc_mode == "PLAINTEXT" or tls_state.get("tls_upgrade_failed") == 1.0:
        return {
            "expired_cert": np.nan,
            "not_yet_valid_cert": np.nan,
            "weak_key": np.nan,
            "self_signed": np.nan,
        }

    # Unobservable certificate cases (partial capture, session resumption, external termination)
    if "OBSCURED_CERT" in posture or "LIMITED_VISIBILITY" in posture or "UNOBSERVED_HANDSHAKE" in posture:
        return {
            "expired_cert": np.nan,
            "not_yet_valid_cert": np.nan,
            "weak_key": np.nan,
            "self_signed": np.nan,
        }

    # Base cert parameters
    exp_cert = 0.0
    nyv_cert = 0.0
    weak_k = 0.0
    self_sign = 0.0

    if "EXPIRED_CERT" in posture:
        exp_cert = 1.0
        weak_k = float(rng.choice([0.0, 1.0], p=[0.75, 0.25]))
        self_sign = float(rng.choice([0.0, 1.0], p=[0.70, 0.30]))
    elif "NOT_YET_VALID" in posture:
        nyv_cert = 1.0
        weak_k = float(rng.choice([0.0, 1.0], p=[0.85, 0.15]))
        self_sign = float(rng.choice([0.0, 1.0], p=[0.80, 0.20]))
    elif "WEAK_KEY" in posture or "INSECURE_SHORT_KEY" in posture:
        weak_k = 1.0
        self_sign = float(rng.choice([0.0, 1.0], p=[0.65, 0.35]))
    elif "SELF_SIGNED" in posture:
        self_sign = 1.0
        weak_k = float(rng.choice([0.0, 1.0], p=[0.85, 0.15]))
    else:
        # Generally clean cert, with small realistic variation
        exp_cert = 0.0
        nyv_cert = 0.0
        weak_k = 0.0
        self_sign = 0.0

    # Ensure mutual exclusivity: cert cannot be both expired AND not yet valid
    if exp_cert == 1.0 and nyv_cert == 1.0:
        nyv_cert = 0.0

    return {
        "expired_cert": exp_cert,
        "not_yet_valid_cert": nyv_cert,
        "weak_key": weak_k,
        "self_signed": self_sign,
    }


def generate_authentication_state(
    posture: str,
    protocol: str,
    enc_mode: str,
    rng: np.random.Generator,
) -> float:
    """Generate authentication timing feature (auth_before_tls).

    IMPLICIT_TLS cannot have auth_before_tls = 1 (TLS handshake occurs before protocol commands).
    PLAINTEXT can have cleartext authentication observation.
    STARTTLS can suffer from misconfigured early authentication before STARTTLS command.
    """
    if enc_mode == "IMPLICIT_TLS":
        return 0.0

    if "AUTH_BEFORE_TLS" in posture or "EARLY_AUTH" in posture:
        return 1.0

    if enc_mode == "PLAINTEXT":
        if "WITH_AUTHENTICATION" in posture or "MULTIPLE_SENSITIVE" in posture:
            return 1.0
        # In general plaintext, auth is observed ~60% of sessions
        return float(rng.choice([0.0, 1.0], p=[0.40, 0.60]))

    if enc_mode == "STARTTLS":
        # Benign STARTTLS strictly authenticates after TLS
        return 0.0

    return 0.0


def apply_controlled_variations(
    feature_dict: Dict[str, Any],
    posture: str,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Apply domain-valid controlled stochastic variation.

    Allowed Variations:
    - Variant A: Toggle secondary cryptographic features (e.g. PFS, self-signed) when domain valid.
    - Variant B: Convert observable cert fields to NaN to simulate limited capture visibility.
    - Variant C: Introduce subtle cross-protocol edge cases.
    NO invalid combinations, NO contradictory TLS states, NO one-hot violations.
    """
    row = dict(feature_dict)
    enc_mode = "PLAINTEXT" if row["encryption_plaintext"] == 1.0 else (
        "IMPLICIT_TLS" if row["encryption_implicit"] == 1.0 else "STARTTLS"
    )

    # 1. Observational uncertainty / Partial capture visibility (12% of TLS sessions)
    if enc_mode in ("STARTTLS", "IMPLICIT_TLS") and row["tls_upgrade_failed"] != 1.0:
        if rng.random() < 0.12 and "STRICT" not in posture:
            # Certificate packet dropped or handshake truncated
            row["expired_cert"] = np.nan
            row["not_yet_valid_cert"] = np.nan
            row["weak_key"] = np.nan
            row["self_signed"] = np.nan

    # 2. Key-length / PFS variation in legacy TLS
    if row.get("deprecated_tls") == 1.0 and not np.isnan(row.get("weak_key", np.nan)):
        # In deprecated TLS, weak key occurrence is 30% stochastic
        if rng.random() < 0.30:
            row["weak_key"] = 1.0

    # 3. Isolated self-signed certificate on modern TLS (15% stochastic variation in permissive postures)
    if (
        "PERMISSIVE" in posture
        and enc_mode != "PLAINTEXT"
        and row.get("tls_upgrade_failed") != 1.0
        and not np.isnan(row.get("self_signed", np.nan))
    ):
        if rng.random() < 0.25:
            row["self_signed"] = 1.0

    return row


def generate_finding_counts(
    feature_dict: Dict[str, Any],
    posture: str,
    rng: np.random.Generator,
) -> Tuple[int, int, int, int]:
    """Generate finding counts as a probabilistic, constrained reflection of observable security state.

    Finding counts represent rule engine emissions from captured network evidence.
    In real-world captures, incomplete capture or rule suppression may yield fewer finding counts
    (e.g. weak cipher producing high_count = 1 or high_count = 0).

    Mandatory Rules:
    - critical_count >= 1 ALWAYS yields CRITICAL.
    - CRITICAL can also have critical_count = 0 (via plaintext, early auth, compounding failures).
    - Finding counts alone must NOT be a deterministic linear shortcut for class labels.
    """
    enc_plain = feature_dict["encryption_plaintext"] == 1.0
    auth_early = feature_dict["auth_before_tls"] == 1.0
    tls_fail = feature_dict["tls_upgrade_failed"] == 1.0
    dep_tls = feature_dict["deprecated_tls"] == 1.0
    weak_ciph = feature_dict["weak_cipher"] == 1.0
    pfs_miss = feature_dict["pfs_missing"] == 1.0
    exp_cert = feature_dict["expired_cert"] == 1.0
    nyv_cert = feature_dict["not_yet_valid_cert"] == 1.0
    weak_k = feature_dict["weak_key"] == 1.0
    self_sign = feature_dict["self_signed"] == 1.0

    major_weakness_count = sum(1 for w in (dep_tls, weak_ciph, exp_cert, weak_k, tls_fail, nyv_cert) if w)
    moderate_weakness_count = sum(1 for m in (pfs_miss, self_sign) if m)

    crit_cnt = 0
    high_cnt = 0
    med_cnt = 0
    low_cnt = 0

    # ── Critical State Finding Generation ──
    if enc_plain or auth_early:
        # Critical exposure is present. Rule engine emits critical_count with moderate probability,
        # but in realistic captures with rule suppression or partial logging, critical_count is 0 in ~45% of sessions!
        if "MULTIPLE_SENSITIVE" in posture or "STRICT" in posture:
            crit_cnt = int(rng.choice([0, 1, 2], p=[0.25, 0.50, 0.25]))
            high_cnt = int(rng.choice([0, 1, 2], p=[0.50, 0.35, 0.15]))
        else:
            # 45% of plaintext / early-auth sessions emit 0 critical findings, relying on observable state
            crit_cnt = int(rng.choice([0, 1, 2], p=[0.45, 0.40, 0.15]))
            high_cnt = int(rng.choice([0, 1, 2], p=[0.50, 0.35, 0.15]))

        med_cnt = int(rng.choice([0, 1, 2], p=[0.50, 0.35, 0.15]))
        low_cnt = int(rng.choice([0, 1, 2], p=[0.50, 0.35, 0.15]))

    elif "COMPOUNDING_FAILURES_NO_CRIT" in posture:
        # Explicit zero critical findings demonstrating compounding failures escalation
        crit_cnt = 0
        high_cnt = int(rng.choice([1, 2, 3], p=[0.30, 0.50, 0.20]))
        med_cnt = int(rng.choice([1, 2], p=[0.50, 0.50]))
        low_cnt = int(rng.choice([0, 1], p=[0.70, 0.30]))

    # ── Major Weakness Finding Generation ──
    elif major_weakness_count > 0:
        crit_cnt = 0
        # Probabilistic emission: in 30% of cases high_cnt is 0 (issue flagged at medium or suppressed)
        if "MULTIPLE_HIGH" in posture or major_weakness_count >= 2:
            high_cnt = int(rng.choice([1, 2, 3], p=[0.40, 0.45, 0.15]))
            med_cnt = int(rng.choice([0, 1, 2], p=[0.35, 0.45, 0.20]))
        else:
            # Single major flaw: high_cnt is 1 in 60%, 0 in 30%, 2 in 10%
            high_cnt = int(rng.choice([0, 1, 2], p=[0.30, 0.60, 0.10]))
            med_cnt = int(rng.choice([0, 1, 2], p=[0.40, 0.40, 0.20]))

        low_cnt = int(rng.choice([0, 1, 2], p=[0.45, 0.40, 0.15]))

    # ── Moderate Weakness Finding Generation ──
    elif moderate_weakness_count > 0:
        crit_cnt = 0
        high_cnt = 0
        # If compounding moderate (e.g. self_signed + pfs_missing), med_cnt can be 2+
        if moderate_weakness_count >= 2:
            med_cnt = int(rng.choice([1, 2, 3], p=[0.35, 0.50, 0.15]))
        else:
            # Moderate flaw: med_cnt is 0 in 35% of cases!
            med_cnt = int(rng.choice([0, 1, 2], p=[0.35, 0.55, 0.10]))

        low_cnt = int(rng.choice([0, 1, 2], p=[0.40, 0.40, 0.20]))

    # ── Benign / Clean Modern TLS ──
    else:
        crit_cnt = 0
        high_cnt = 0
        med_cnt = 0
        # Low findings for benign informational alerts (e.g. cipher preference, SNI note)
        if "INFO_ALERTS" in posture or "MINOR_LOW" in posture:
            low_cnt = int(rng.choice([1, 2, 3], p=[0.40, 0.45, 0.15]))
        else:
            low_cnt = int(rng.choice([0, 1, 2], p=[0.55, 0.35, 0.10]))

    return crit_cnt, high_cnt, med_cnt, low_cnt


def generate_feature_first_candidate(
    posture: str,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Generate a single session candidate starting from network security state."""
    proto = sample_protocol(rng)
    proto_state = generate_protocol_state(proto)
    enc_mode, enc_state = generate_encryption_state(posture, proto, rng)
    tls_state = generate_tls_state(posture, enc_mode, rng)
    cert_state = generate_certificate_state(posture, enc_mode, tls_state, rng)
    auth_state = generate_authentication_state(posture, proto, enc_mode, rng)

    candidate: Dict[str, Any] = {
        **proto_state,
        **enc_state,
        **tls_state,
        **cert_state,
        "auth_before_tls": auth_state,
    }

    # Apply controlled domain variability
    candidate = apply_controlled_variations(candidate, posture, rng)

    # Generate probabilistic finding counts
    crit_cnt, high_cnt, med_cnt, low_cnt = generate_finding_counts(candidate, posture, rng)
    candidate["critical_count"] = crit_cnt
    candidate["high_count"] = high_cnt
    candidate["medium_count"] = med_cnt
    candidate["low_count"] = low_cnt

    return candidate


def generate_synthetic_dataset(
    n_samples: int = 6400,
    random_state: int = 42,
) -> pd.DataFrame:
    """Generate a balanced, realistic, domain-validated synthetic dataset of 6,000+ samples.

    The ground-truth risk label is assigned by the Canonical Risk Aggregator as an OUTPUT
    of the feature state.
    """
    rng = np.random.default_rng(random_state)
    classes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    base_target = n_samples // len(classes)
    remainder = n_samples % len(classes)
    targets = {c: base_target + (1 if i < remainder else 0) for i, c in enumerate(classes)}

    rows: List[Dict[str, Any]] = []
    class_counts: Dict[str, int] = {c: 0 for c in classes}
    sample_counter = 0

    posture_idx = 0
    max_attempts = n_samples * 40
    attempts = 0

    while any(class_counts[c] < targets[c] for c in classes) and attempts < max_attempts:
        attempts += 1
        posture = SECURITY_POSTURES[posture_idx % len(SECURITY_POSTURES)]
        posture_idx += 1

        candidate = generate_feature_first_candidate(posture, rng)

        # 1. Canonical Risk Aggregator derives the risk label
        derived_label, reasons = calculate_session_risk(candidate)
        candidate["risk_label"] = derived_label

        # Check if we still need samples for this derived class
        if class_counts[derived_label] >= targets[derived_label]:
            continue

        # 2. Validate against domain constraints
        is_valid, errors = validate_feature_row(candidate)
        if not is_valid:
            continue

        class_counts[derived_label] += 1
        sample_counter += 1

        proto_name = "smtp" if candidate["protocol_smtp"] == 1 else (
            "imap" if candidate["protocol_imap"] == 1 else "pop3"
        )

        full_row: Dict[str, Any] = {
            "analysis_id": f"synthetic-{sample_counter // 4 + 1:05d}",
            "session_id": f"{proto_name}-{sample_counter:06d}",
            "scenario_id": f"{posture}-{class_counts[derived_label]:04d}",
            "scenario_family": posture,
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
        description="Generate validated feature-first synthetic dataset for SecureMailScope."
    )
    parser.add_argument("--samples", type=int, default=6400, help="Number of samples to generate.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument("--output", default="data/processed/synthetic_dataset.csv", help="Output path.")
    args = parser.parse_args(argv)

    print(f"Generating {args.samples} synthetic samples via Feature-First Architecture...")
    df = generate_synthetic_dataset(args.samples, args.random_state)

    print(f"  Generated {len(df)} rows.")
    print("  Class distribution:")
    for label, count in df["risk_label"].value_counts().items():
        print(f"    {label}: {count}")

    # Feature signature diversity
    signatures = df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1)
    unique_sigs = int(signatures.nunique())
    print(f"  Unique feature signatures: {unique_sigs} / {len(df)} ({unique_sigs / len(df):.2%})")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"  Saved synthetic dataset to: {output_path}")


if __name__ == "__main__":
    main()
