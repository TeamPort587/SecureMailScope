"""
Independent Partial Capture Challenge Generator
===============================================

Generates an independent benchmark dataset specifically simulating incomplete,
truncated, asymmetric, and partially observed PCAP sessions across 12 realistic
capture scenarios:

1. FULL_SESSION: Complete observable session.
2. START_MID_SESSION: Capture begins after protocol session has already started.
3. START_AFTER_STARTTLS: STARTTLS negotiation happened before capture started.
4. MISSING_CLIENT_HELLO: TLS client handshake partially missing.
5. MISSING_SERVER_HELLO: Server handshake partially missing.
6. MISSING_CERTIFICATE: Certificate exchange unobservable.
7. MISSING_TLS_FINISHED: TLS negotiation truncated mid-handshake.
8. TRUNCATED_SESSION: Capture ends before the session finishes.
9. ASYMMETRIC_CAPTURE: Only one direction of traffic is partially available.
10. PACKET_LOSS_SIMULATION: Some protocol evidence is dropped/unavailable.
11. AUTH_NOT_OBSERVED: Authentication phase unobservable.
12. STARTTLS_NOT_OBSERVED: Upgrade negotiation unobservable.

Guarantees:
- Independent generation logic from training templates.
- Strict preservation of canonical 19-feature schema + 6 observability features.
- Strict domain-validity (no impossible protocol states).
- Deterministic risk derivation via `calculate_session_risk`.
- Tagged with ``data_source = PARTIAL_CAPTURE_CHALLENGE`` and ``capture_scenario``.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    EXTENDED_FEATURES,
    OBSERVABILITY_FEATURES,
    RISK_LABELS,
)
from ml.risk.risk_aggregator import calculate_session_risk
from ml.training.dataset_validator import validate_feature_row


PARTIAL_CAPTURE_SCENARIOS: List[str] = [
    "FULL_SESSION",
    "START_MID_SESSION",
    "START_AFTER_STARTTLS",
    "MISSING_CLIENT_HELLO",
    "MISSING_SERVER_HELLO",
    "MISSING_CERTIFICATE",
    "MISSING_TLS_FINISHED",
    "TRUNCATED_SESSION",
    "ASYMMETRIC_CAPTURE",
    "PACKET_LOSS_SIMULATION",
    "AUTH_NOT_OBSERVED",
    "STARTTLS_NOT_OBSERVED",
]


def _sample_base_security_state(
    scenario: str,
    protocol: str,
    rng: np.random.Generator,
) -> Tuple[Dict[str, Any], Dict[str, float]]:
    """Sample a realistic underlying security state and its observability flags."""
    # Choose base posture archetype:
    # 0 = Benign Modern (TLS 1.2/1.3, valid cert)
    # 1 = Moderate (Self-signed or missing PFS)
    # 2 = High (Deprecated TLS, weak cipher, expired cert, or short key)
    # 3 = Critical (Plaintext, auth before TLS, or compounding failures)
    archetype = rng.choice(["BENIGN", "MODERATE", "HIGH", "CRITICAL"], p=[0.35, 0.25, 0.25, 0.15])

    # Choose encryption mode
    if archetype == "CRITICAL" and rng.random() < 0.50:
        enc_mode = "PLAINTEXT"
    elif protocol == "SMTP":
        enc_mode = "STARTTLS" if rng.random() < 0.70 else "IMPLICIT_TLS"
    else:
        enc_mode = "IMPLICIT_TLS" if rng.random() < 0.60 else "STARTTLS"

    # Base features
    feat: Dict[str, Any] = {
        "protocol_smtp": 1.0 if protocol == "SMTP" else 0.0,
        "protocol_imap": 1.0 if protocol == "IMAP" else 0.0,
        "protocol_pop3": 1.0 if protocol == "POP3" else 0.0,
        "encryption_plaintext": 1.0 if enc_mode == "PLAINTEXT" else 0.0,
        "encryption_starttls": 1.0 if enc_mode == "STARTTLS" else 0.0,
        "encryption_implicit": 1.0 if enc_mode == "IMPLICIT_TLS" else 0.0,
        "deprecated_tls": 0.0,
        "weak_cipher": 0.0,
        "pfs_missing": 0.0,
        "expired_cert": 0.0,
        "not_yet_valid_cert": 0.0,
        "weak_key": 0.0,
        "self_signed": 0.0,
        "auth_before_tls": 0.0,
        "tls_upgrade_failed": 0.0,
        "critical_count": 0.0,
        "high_count": 0.0,
        "medium_count": 0.0,
        "low_count": 0.0,
    }

    # Observability flags (defaults for full session)
    obs: Dict[str, float] = {
        "tls_handshake_observed": 0.0 if enc_mode == "PLAINTEXT" else 1.0,
        "certificate_observed": 0.0 if enc_mode == "PLAINTEXT" else 1.0,
        "starttls_command_observed": 1.0 if enc_mode == "STARTTLS" else 0.0,
        "authentication_observed": 1.0,
        "session_truncated": 0.0,
        "asymmetric_capture": 0.0,
    }

    # Configure base vulnerabilities according to archetype
    if enc_mode == "PLAINTEXT":
        feat["deprecated_tls"] = np.nan
        feat["weak_cipher"] = np.nan
        feat["pfs_missing"] = np.nan
        feat["expired_cert"] = np.nan
        feat["not_yet_valid_cert"] = np.nan
        feat["weak_key"] = np.nan
        feat["self_signed"] = np.nan
        feat["auth_before_tls"] = 1.0 if rng.random() < 0.60 else 0.0
    else:
        if archetype == "BENIGN":
            feat["pfs_missing"] = 1.0 if rng.random() < 0.10 else 0.0
            feat["low_count"] = float(rng.choice([0, 1], p=[0.7, 0.3]))
        elif archetype == "MODERATE":
            if rng.random() < 0.50:
                feat["self_signed"] = 1.0
                feat["medium_count"] = 1.0
            else:
                feat["pfs_missing"] = 1.0
                feat["medium_count"] = 1.0
        elif archetype == "HIGH":
            flaw = rng.choice(["DEP_TLS", "WEAK_CIPHER", "EXPIRED_CERT", "WEAK_KEY"])
            if flaw == "DEP_TLS":
                feat["deprecated_tls"] = 1.0
                feat["pfs_missing"] = float(rng.choice([0.0, 1.0], p=[0.3, 0.7]))
            elif flaw == "WEAK_CIPHER":
                feat["weak_cipher"] = 1.0
            elif flaw == "EXPIRED_CERT":
                feat["expired_cert"] = 1.0
            else:
                feat["weak_key"] = 1.0
            feat["high_count"] = 1.0
        elif archetype == "CRITICAL":
            if enc_mode == "STARTTLS" and rng.random() < 0.50:
                feat["auth_before_tls"] = 1.0
                feat["critical_count"] = float(rng.choice([0, 1], p=[0.4, 0.6]))
            else:
                feat["deprecated_tls"] = 1.0
                feat["weak_cipher"] = 1.0
                feat["expired_cert"] = 1.0
                feat["high_count"] = 2.0

    # ── Apply capture scenario perturbations ──
    if scenario == "FULL_SESSION":
        pass  # Everything observed as configured

    elif scenario == "START_MID_SESSION":
        # Capture began after greeting/negotiation
        if enc_mode == "STARTTLS":
            obs["starttls_command_observed"] = 0.0
        if rng.random() < 0.50:
            obs["tls_handshake_observed"] = 0.0
            feat["deprecated_tls"] = np.nan
            feat["weak_cipher"] = np.nan
            feat["pfs_missing"] = np.nan
        obs["authentication_observed"] = float(rng.choice([0.0, 1.0], p=[0.5, 0.5]))
        if obs["authentication_observed"] == 0.0:
            feat["auth_before_tls"] = np.nan

    elif scenario == "START_AFTER_STARTTLS":
        # In STARTTLS, capture began during established TLS; STARTTLS command missed
        if enc_mode == "STARTTLS":
            obs["starttls_command_observed"] = 0.0
            if feat["critical_count"] == 0 and feat["auth_before_tls"] == 1.0:
                feat["auth_before_tls"] = np.nan
                obs["authentication_observed"] = 0.0

    elif scenario == "MISSING_CLIENT_HELLO":
        # Server hello captured, but client hello dropped
        if enc_mode != "PLAINTEXT":
            if rng.random() < 0.30:
                obs["tls_handshake_observed"] = 0.0
                feat["pfs_missing"] = np.nan

    elif scenario == "MISSING_SERVER_HELLO":
        # Server hello missing -> TLS version and cipher negotiation unobserved
        if enc_mode != "PLAINTEXT":
            obs["tls_handshake_observed"] = 0.0
            feat["deprecated_tls"] = np.nan
            feat["weak_cipher"] = np.nan
            feat["pfs_missing"] = np.nan

    elif scenario == "MISSING_CERTIFICATE":
        # Certificate message missing/encrypted (TLS 1.3 resumption or dropped)
        if enc_mode != "PLAINTEXT":
            obs["certificate_observed"] = 0.0
            feat["expired_cert"] = np.nan
            feat["not_yet_valid_cert"] = np.nan
            feat["weak_key"] = np.nan
            feat["self_signed"] = np.nan

    elif scenario == "MISSING_TLS_FINISHED":
        # Truncated handshake
        obs["session_truncated"] = 1.0
        if enc_mode != "PLAINTEXT":
            if rng.random() < 0.50:
                obs["certificate_observed"] = 0.0
                feat["expired_cert"] = np.nan
                feat["not_yet_valid_cert"] = np.nan
                feat["weak_key"] = np.nan
                feat["self_signed"] = np.nan

    elif scenario == "TRUNCATED_SESSION":
        # Session abruptly terminated
        obs["session_truncated"] = 1.0
        if rng.random() < 0.40:
            obs["authentication_observed"] = 0.0
            feat["auth_before_tls"] = np.nan

    elif scenario == "ASYMMETRIC_CAPTURE":
        # Only client-to-server or server-to-client captured
        obs["asymmetric_capture"] = 1.0
        if rng.random() < 0.60 and enc_mode != "PLAINTEXT":
            obs["certificate_observed"] = 0.0
            feat["expired_cert"] = np.nan
            feat["not_yet_valid_cert"] = np.nan
            feat["weak_key"] = np.nan
            feat["self_signed"] = np.nan
        if rng.random() < 0.50:
            obs["authentication_observed"] = 0.0
            feat["auth_before_tls"] = np.nan
            if enc_mode == "STARTTLS":
                obs["starttls_command_observed"] = 0.0

    elif scenario == "PACKET_LOSS_SIMULATION":
        # Random packet loss
        if enc_mode != "PLAINTEXT":
            if rng.random() < 0.40:
                obs["certificate_observed"] = 0.0
                feat["expired_cert"] = np.nan
                feat["not_yet_valid_cert"] = np.nan
                feat["weak_key"] = np.nan
                feat["self_signed"] = np.nan
            if rng.random() < 0.30:
                obs["tls_handshake_observed"] = 0.0
                feat["deprecated_tls"] = np.nan
                feat["weak_cipher"] = np.nan
                feat["pfs_missing"] = np.nan

    elif scenario == "AUTH_NOT_OBSERVED":
        obs["authentication_observed"] = 0.0
        feat["auth_before_tls"] = np.nan

    elif scenario == "STARTTLS_NOT_OBSERVED":
        if enc_mode == "STARTTLS":
            obs["starttls_command_observed"] = 0.0
            if rng.random() < 0.50:
                feat["auth_before_tls"] = np.nan

    return feat, obs


def generate_partial_capture_dataset(
    samples_per_scenario: int = 100,
    random_state: int = 2026,
    exclude_signatures: Optional[Set[Tuple[float, ...]]] = None,
) -> pd.DataFrame:
    """Generate the independent partial capture challenge dataset.

    Returns DataFrame with metadata, 19 canonical features, 6 observability features,
    and ground-truth risk_label derived strictly via `calculate_session_risk`.
    """
    rng = np.random.default_rng(random_state)
    rows: List[Dict[str, Any]] = []

    if exclude_signatures is None:
        train_path = Path("data/processed/train.csv")
        if train_path.is_file():
            tdf = pd.read_csv(train_path)
            exclude_signatures = set(tuple(r.fillna(-999.0)) for _, r in tdf[ALL_FEATURES].iterrows())

    for scenario in PARTIAL_CAPTURE_SCENARIOS:
        idx = 0
        attempts = 0
        max_attempts = samples_per_scenario * 50
        while idx < samples_per_scenario and attempts < max_attempts:
            attempts += 1
            # Rotate protocols
            protocol = ["SMTP", "IMAP", "POP3"][idx % 3]

            feat, obs = _sample_base_security_state(scenario, protocol, rng)

            # Strict domain rule: calculate canonical risk label
            risk_label, reasons = calculate_session_risk(feat)

            # Ensure zero overlap with training signatures
            sig = tuple(
                -999.0 if (feat.get(f) is None or (isinstance(feat.get(f), float) and math.isnan(feat[f])))
                else float(feat[f])
                for f in ALL_FEATURES
            )
            if exclude_signatures and sig in exclude_signatures:
                continue

            # Metadata
            session_id = f"partial_{scenario.lower()}_{idx:04d}"
            analysis_id = f"ANALYSIS_PARTIAL_{scenario}_{idx:04d}"

            row: Dict[str, Any] = {
                "analysis_id": analysis_id,
                "session_id": session_id,
                "scenario_id": f"{analysis_id}_{session_id}",
                "scenario_family": f"PARTIAL_CAPTURE_{scenario}",
                "data_source": "PARTIAL_CAPTURE_CHALLENGE",
                "capture_scenario": scenario,
                "risk_label": risk_label,
            }

            # Canonical 19 features
            for f in ALL_FEATURES:
                row[f] = feat[f]

            # Observability features
            for f in OBSERVABILITY_FEATURES:
                row[f] = obs[f]

            rows.append(row)
            idx += 1

    df = pd.DataFrame(rows)

    # Validate all rows
    for _, r in df.iterrows():
        validate_feature_row(r.to_dict())

    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate partial capture challenge dataset")
    parser.add_argument("--samples-per-scenario", type=int, default=100, help="Samples per scenario (total = 12 * n)")
    parser.add_argument("--random-state", type=int, default=2026, help="Random seed")
    parser.add_argument("--output", type=str, default="data/processed/partial_capture_challenge.csv", help="Output CSV path")
    args = parser.parse_args()

    df = generate_partial_capture_dataset(args.samples_per_scenario, args.random_state)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    print(f"Generated {len(df)} partial capture challenge samples across {len(PARTIAL_CAPTURE_SCENARIOS)} scenarios.")
    print("Class distribution:")
    print(df["risk_label"].value_counts().to_string())
    print(f"Saved to {out_path}")


if __name__ == "__main__":
    main()
