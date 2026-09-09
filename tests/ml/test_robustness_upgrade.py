"""
Tests for ML Robustness Upgrade (Phases 17-23).

Covers all 12 verification criteria:
1. Certificate unobserved != valid cert (cert features NaN, not 0).
2. TLS unobserved != modern TLS (TLS features NaN, not 0).
3. Missing STARTTLS evidence != STARTTLS not used.
4. Partial capture scenarios preserve domain validity.
5. Mandatory CRITICAL conditions remain CRITICAL (reconciliation invariant).
6. Observability features survive preprocessing.
7. Missingness does not silently become zero (MissingIndicator retained).
8. Group-aware split has zero signature overlap (train/val/test).
9. Partial capture dataset is independent (zero signature overlap with train).
10. Perfect model audit detects label permutation failure.
11. Evidence quality correctly assigned (HIGH, PARTIAL, LOW, UNKNOWN).
12. Existing inference contracts remain backwards-compatible.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import pytest

from ml.feature_engineering.encoder import (
    build_pipeline,
    extended_features_to_dataframe,
    prepare_extended_feature_matrix,
    prepare_feature_matrix,
)
from ml.feature_engineering.extractor import (
    extract_extended_session_features,
    extract_observability_features,
    extract_session_features,
)
from ml.feature_engineering.schema import (
    ALL_FEATURES,
    CERT_FEATURES,
    EVIDENCE_HIGH,
    EVIDENCE_LOW,
    EVIDENCE_PARTIAL,
    EVIDENCE_UNKNOWN,
    EXTENDED_FEATURES,
    FEATURE_COUNT,
    OBSERVABILITY_FEATURES,
    QUALITY_LOW,
    QUALITY_SUFFICIENT,
    SCHEMA_VERSION,
    TLS_QUALITY_FEATURES,
)
from ml.inference.predictor import (
    RiskPredictor,
    assess_prediction_quality,
    calculate_evidence_quality,
)
from ml.training.model_selection_policy import reconcile_risk


# ── Helpers ────────────────────────────────────────────────────────

def _get_signatures(df: pd.DataFrame) -> set[tuple]:
    """Extract signature tuples with NaN replaced by -999.0."""
    return set(df[ALL_FEATURES].apply(lambda r: tuple(r.fillna(-999.0)), axis=1))


def _make_mock_session(
    protocol: str = "SMTP",
    encryption_mode: str = "STARTTLS",
    tls: dict | None = None,
    certificate: dict | None = None,
    flags: list | None = None,
    capture_scenario: str = "FULL_SESSION",
) -> dict:
    """Create a mock session dict simulating extraction pipeline output."""
    return {
        "session_id": "test_sess_001",
        "protocol": protocol,
        "security": {
            "encryption_mode": encryption_mode,
            "upgrade_advertised": True,
            "upgrade_requested": True,
            "upgrade_succeeded": True,
            "authentication_before_tls": False,
        },
        "tls": tls,
        "certificate": certificate,
        "flags": flags or [],
        "capture_scenario": capture_scenario,
    }


# ── Test 1: Certificate unobserved != valid cert ───────────────────

def test_certificate_unobserved_produces_nans_not_zeros():
    """When certificate is unobserved, cert features must be NaN, not 0.0."""
    session = _make_mock_session(
        protocol="SMTP",
        encryption_mode="STARTTLS",
        tls={"version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "has_pfs": True},
        certificate=None,
    )
    features = extract_extended_session_features(session, [])

    # Certificate was not observed
    assert features["certificate_observed"] == 0.0

    # Cert features MUST be NaN, never 0.0 (which would falsely imply a valid cert)
    for feat in CERT_FEATURES + ["self_signed"]:
        assert math.isnan(features[feat]), f"{feat} should be NaN when cert unobserved"


# ── Test 2: TLS unobserved != modern TLS ───────────────────────────

def test_tls_unobserved_produces_nans_not_modern_tls():
    """When TLS handshake is unobserved, TLS features must be NaN, not 0.0."""
    session = _make_mock_session(
        protocol="IMAP",
        encryption_mode="STARTTLS",
        tls=None,
        certificate=None,
    )
    features = extract_extended_session_features(session, [])

    assert features["tls_handshake_observed"] == 0.0

    # TLS features MUST be NaN, not 0.0 (0.0 would falsely imply modern TLS / no weak cipher)
    for feat in ["deprecated_tls", "weak_cipher", "pfs_missing"]:
        assert math.isnan(features[feat]), f"{feat} should be NaN when TLS unobserved"


# ── Test 3: Missing STARTTLS evidence != STARTTLS not used ──────────

def test_missing_starttls_evidence_distinct_from_plaintext():
    """When STARTTLS is unobserved/ambiguous, it should not default to plaintext."""
    session = _make_mock_session(
        protocol="SMTP",
        encryption_mode="UNKNOWN",
        tls=None,
        certificate=None,
    )
    features = extract_extended_session_features(session, [])

    assert features["starttls_command_observed"] == 0.0
    # encryption_plaintext should not be falsely asserted as 1.0
    assert features["encryption_plaintext"] != 1.0


# ── Test 4: Partial capture scenarios preserve domain validity ─────

def test_partial_capture_scenarios_domain_validity():
    """Partial capture challenge dataset preserves valid labels and feature domains."""
    challenge_path = Path("data/processed/partial_capture_challenge.csv")
    if not challenge_path.exists():
        pytest.skip("partial_capture_challenge.csv not present")

    df = pd.read_csv(challenge_path)
    assert len(df) == 1200
    assert "capture_scenario" in df.columns
    assert len(df["capture_scenario"].unique()) == 12

    valid_labels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(df["risk_label"].unique()).issubset(valid_labels)

    # Verify that unobserved scenarios actually carry NaNs
    no_cert_df = df[df["capture_scenario"] == "MISSING_CERTIFICATE"]
    assert len(no_cert_df) > 0
    assert (no_cert_df["certificate_observed"] == 0.0).all()
    assert no_cert_df["expired_cert"].isna().all()


# ── Test 5: Mandatory CRITICAL conditions remain CRITICAL ──────────

def test_mandatory_critical_conditions_remain_critical():
    """Mandatory security invariant: critical_count >= 1 MUST ALWAYS yield CRITICAL."""
    predictor = RiskPredictor(model_dir="ml/artifacts")

    # Session with critical finding (e.g. plaintext password before TLS)
    session = _make_mock_session(
        protocol="SMTP",
        encryption_mode="PLAINTEXT",
        tls=None,
        certificate=None,
    )
    findings = [
        {
            "finding_id": "f_crit_01",
            "session_id": "test_sess_001",
            "severity": "CRITICAL",
            "type": "AUTH_BEFORE_TLS",
            "title": "Plaintext credentials exposed",
        }
    ]

    result = predictor.predict_session(session, findings)
    features = extract_session_features(session, findings)
    reconciled = reconcile_risk(features, result["risk"]["level"])
    assert reconciled == "CRITICAL", (
        f"Reconciled risk must be CRITICAL when critical findings exist, got {reconciled}"
    )


# ── Test 6: Observability features survive preprocessing ───────────

def test_observability_features_survive_preprocessing():
    """Extended features with observability flags pass through pipeline without errors."""
    row = {f: 0.0 for f in EXTENDED_FEATURES}
    row["tls_handshake_observed"] = 0.0
    row["certificate_observed"] = 0.0
    row["deprecated_tls"] = float("nan")
    row["expired_cert"] = float("nan")

    mat = prepare_extended_feature_matrix([row])
    assert mat.shape == (1, len(EXTENDED_FEATURES))
    assert np.isnan(mat[0, EXTENDED_FEATURES.index("deprecated_tls")])
    assert mat[0, EXTENDED_FEATURES.index("tls_handshake_observed")] == 0.0


# ── Test 7: Missingness does not silently become zero ───────────────

def test_missingness_does_not_silently_become_zero():
    """Imputer with add_indicator=True preserves missingness indicators."""
    rows = [
        {f: 1.0 for f in ALL_FEATURES},
        {f: 0.0 for f in ALL_FEATURES},
    ]
    rows[1]["expired_cert"] = float("nan")

    pipeline = build_pipeline(n_estimators=5, random_state=42)
    mat = prepare_feature_matrix(rows)
    pipeline.fit(mat, ["HIGH", "LOW"])

    imputer = pipeline.named_steps["imputer"]
    assert hasattr(imputer, "indicator_")
    assert imputer.indicator_ is not None, "MissingIndicator must be present in imputer"


# ── Test 8: Group-aware split has zero signature overlap ───────────

def test_split_has_zero_signature_overlap():
    """Train, Val, and Test splits must have zero feature signature overlap."""
    train_path = Path("data/processed/train.csv")
    val_path = Path("data/processed/validation.csv")
    test_path = Path("data/processed/test.csv")

    if not (train_path.exists() and val_path.exists() and test_path.exists()):
        pytest.skip("Dataset splits not found")

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    train_sigs = _get_signatures(train_df)
    val_sigs = _get_signatures(val_df)
    test_sigs = _get_signatures(test_df)

    assert len(train_sigs & val_sigs) == 0, "Train and Val share signatures!"
    assert len(train_sigs & test_sigs) == 0, "Train and Test share signatures!"
    assert len(val_sigs & test_sigs) == 0, "Val and Test share signatures!"


# ── Test 9: Partial capture dataset is independent (zero overlap) ───

def test_partial_capture_dataset_zero_overlap_with_train():
    """Partial capture challenge dataset has 0 signature overlap with train.csv."""
    train_path = Path("data/processed/train.csv")
    pc_path = Path("data/processed/partial_capture_challenge.csv")

    if not (train_path.exists() and pc_path.exists()):
        pytest.skip("Train or partial capture dataset not found")

    train_df = pd.read_csv(train_path)
    pc_df = pd.read_csv(pc_path)

    train_sigs = _get_signatures(train_df)
    pc_sigs = _get_signatures(pc_df)

    overlap = train_sigs & pc_sigs
    assert len(overlap) == 0, f"Found {len(overlap)} overlapping signatures between train and partial capture!"


# ── Test 10: Perfect model audit detects label permutation failure ──

def test_perfect_model_audit_detects_permutation_failure():
    """Label permutation audit confirms models collapse to random chance under permutation."""
    report_path = Path("ml/artifacts/perfect_model_audit_report.json")
    if not report_path.exists():
        pytest.skip("perfect_model_audit_report.json not found")

    with open(report_path, "r", encoding="utf-8") as f:
        rep = json.load(f)

    test_a = rep["test_results"]["TEST_A_LABEL_PERMUTATION"]
    assert test_a["status"] == "PASS", "Label permutation test should pass by detecting collapse"

    for model_name, metrics in test_a["models"].items():
        assert metrics["macro_f1"] < 0.40, (
            f"{model_name} did not collapse under permutation: F1 = {metrics['macro_f1']}"
        )


# ── Test 11: Evidence quality correctly assigned ───────────────────

def test_evidence_quality_assignment():
    """Evidence quality maps correctly to HIGH, PARTIAL, LOW, and UNKNOWN."""
    vec = {f: 0.0 for f in ALL_FEATURES}
    vec["protocol_smtp"] = 1.0
    vec["encryption_starttls"] = 1.0

    # All TLS and Cert observed -> EVIDENCE_HIGH
    eq = calculate_evidence_quality(vec)
    assert eq == EVIDENCE_HIGH

    # Cert features unobserved -> EVIDENCE_PARTIAL
    for f in CERT_FEATURES + ["self_signed"]:
        vec[f] = float("nan")
    eq = calculate_evidence_quality(vec)
    assert eq == EVIDENCE_PARTIAL

    # TLS features also unobserved -> EVIDENCE_LOW
    for f in ["deprecated_tls", "weak_cipher", "pfs_missing"]:
        vec[f] = float("nan")
    eq = calculate_evidence_quality(vec)
    assert eq == EVIDENCE_LOW

    # All features NaN -> EVIDENCE_UNKNOWN
    all_nan = {f: float("nan") for f in ALL_FEATURES}
    eq = calculate_evidence_quality(all_nan)
    assert eq == EVIDENCE_UNKNOWN


# ── Test 12: Existing inference contracts remain backwards compatible ─

def test_inference_contracts_backwards_compatible():
    """RiskPredictor handles session input while providing both legacy and new keys."""
    predictor = RiskPredictor(model_dir="ml/artifacts")

    session = _make_mock_session(
        protocol="SMTP",
        encryption_mode="STARTTLS",
        tls={"version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "has_pfs": True},
        certificate={"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2028-01-01T00:00:00Z", "key_type": "RSA", "key_size": 2048},
    )

    result = predictor.predict_session(session, [])

    # Legacy contract checks
    assert "session_id" in result
    assert "risk" in result
    risk = result["risk"]
    assert "level" in risk
    assert "confidence" in risk
    assert "prediction_quality" in risk
    assert "model_version" in risk

    # Phase 23 robustness extensions
    assert "ml_confidence" in risk
    assert "evidence_quality" in risk
    assert risk["evidence_quality"] in {EVIDENCE_HIGH, EVIDENCE_PARTIAL, EVIDENCE_LOW, EVIDENCE_UNKNOWN}
    assert 0.0 <= risk["ml_confidence"] <= 1.0
