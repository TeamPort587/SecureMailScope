"""
Inference Predictor
===================

Loads the trained pipeline, validates metadata, extracts features
from analysis JSON, predicts risk per session, and returns
structured, explainable, JSON-serializable output.

Includes guardrails for:

- Missing model artifact.
- Schema version mismatch.
- Feature count mismatch.
- Low-evidence detection (too many NaN features).

CLI Usage::

    python -m ml.inference.predictor \\
        --analysis data/curated/example.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from ml.feature_engineering.extractor import (
    extract_all_sessions,
    extract_session_features,
    feature_vector_to_ordered_list,
)
from ml.feature_engineering.schema import (
    ALL_FEATURES,
    BINARY_FEATURES,
    EVIDENCE_HIGH,
    EVIDENCE_LOW,
    EVIDENCE_PARTIAL,
    EVIDENCE_UNKNOWN,
    FEATURE_COUNT,
    LOW_EVIDENCE_THRESHOLD,
    QUALITY_LOW,
    QUALITY_SUFFICIENT,
    SCHEMA_VERSION,
)
from ml.feature_engineering.validator import validate_analysis_strict

MODEL_FILENAME: str = "risk_model.joblib"
METADATA_FILENAME: str = "model_metadata.json"


# ── Exceptions ─────────────────────────────────────────────────────

class ModelLoadError(Exception):
    """Raised when the model artifact cannot be loaded."""


class SchemaVersionMismatch(Exception):
    """Raised when the model's schema version does not match."""


class FeatureCountMismatch(Exception):
    """Raised when the model expects a different feature count."""


# ── Evidence quality ──────────────────────────────────────────────

def assess_prediction_quality(
    feature_vec: Dict[str, float],
) -> tuple[str, list[str]]:
    """Assess whether there is enough evidence for a confident prediction.

    Returns
    -------
    Tuple[str, List[str]]
        ``(quality_level, warnings)``
    """
    warnings: List[str] = []

    # Count NaN binary features
    nan_binary = sum(
        1 for f in BINARY_FEATURES
        if isinstance(feature_vec.get(f), float) and math.isnan(feature_vec.get(f, 0))
    )
    binary_total = len(BINARY_FEATURES)
    nan_ratio = nan_binary / binary_total if binary_total > 0 else 0

    if nan_ratio >= LOW_EVIDENCE_THRESHOLD:
        quality = QUALITY_LOW
    else:
        quality = QUALITY_SUFFICIENT

    # Specific warnings
    tls_features = ["deprecated_tls", "weak_cipher", "pfs_missing"]
    if all(_is_nan(feature_vec.get(f)) for f in tls_features):
        warnings.append("TLS details unavailable")

    cert_features = ["expired_cert", "not_yet_valid_cert", "weak_key", "self_signed"]
    if all(_is_nan(feature_vec.get(f)) for f in cert_features):
        warnings.append("Certificate details unavailable")

    enc_features = ["encryption_plaintext", "encryption_starttls", "encryption_implicit"]
    if all(_is_nan(feature_vec.get(f)) for f in enc_features):
        warnings.append("Encryption mode unknown")

    proto_features = ["protocol_smtp", "protocol_imap", "protocol_pop3"]
    if all(_is_nan(feature_vec.get(f)) for f in proto_features):
        warnings.append("Protocol unknown")

    return quality, warnings


def calculate_evidence_quality(
    feature_vec: Dict[str, float],
) -> str:
    """Calculate granular evidence quality level for uncertainty handling (Phase 23).

    Returns
    -------
    str
        One of 'HIGH_EVIDENCE', 'PARTIAL_EVIDENCE', 'LOW_EVIDENCE', 'UNKNOWN_EVIDENCE'.
    """
    proto_features = ["protocol_smtp", "protocol_imap", "protocol_pop3"]
    if all(_is_nan(feature_vec.get(f)) for f in proto_features):
        return EVIDENCE_UNKNOWN

    enc_features = ["encryption_plaintext", "encryption_starttls", "encryption_implicit"]
    if all(_is_nan(feature_vec.get(f)) for f in enc_features):
        return EVIDENCE_UNKNOWN

    nan_binary = sum(
        1 for f in BINARY_FEATURES
        if _is_nan(feature_vec.get(f))
    )
    nan_ratio = nan_binary / len(BINARY_FEATURES) if BINARY_FEATURES else 0.0

    if nan_ratio >= 0.70:
        return EVIDENCE_UNKNOWN

    is_plaintext = feature_vec.get("encryption_plaintext") == 1.0
    if is_plaintext:
        return EVIDENCE_HIGH if nan_ratio <= 0.50 else EVIDENCE_PARTIAL

    # Encrypted session (STARTTLS or IMPLICIT_TLS)
    tls_features = ["deprecated_tls", "weak_cipher", "pfs_missing"]
    cert_features = ["expired_cert", "not_yet_valid_cert", "weak_key", "self_signed"]

    tls_observed = any(not _is_nan(feature_vec.get(f)) for f in tls_features)
    cert_observed = any(not _is_nan(feature_vec.get(f)) for f in cert_features)

    if tls_observed and cert_observed:
        return EVIDENCE_HIGH if nan_ratio < 0.25 else EVIDENCE_PARTIAL
    elif tls_observed or cert_observed:
        return EVIDENCE_PARTIAL
    else:
        return EVIDENCE_LOW


def _is_nan(value: Any) -> bool:
    return isinstance(value, float) and math.isnan(value)


def _extract_risk_signals(feature_vec: Dict[str, float]) -> List[Dict[str, Any]]:
    """Identify features that are active risk signals (value == 1)."""
    risk_signal_features = [
        "encryption_plaintext",
        "deprecated_tls",
        "weak_cipher",
        "expired_cert",
        "not_yet_valid_cert",
        "weak_key",
        "auth_before_tls",
        "tls_upgrade_failed",
        "pfs_missing",
        "self_signed",
    ]
    signals: List[Dict[str, Any]] = []
    for feat in risk_signal_features:
        val = feature_vec.get(feat)
        if val == 1:
            signals.append({"feature": feat, "value": 1})
    return signals


# ── Predictor class ────────────────────────────────────────────────

class RiskPredictor:
    """Loads a trained model and predicts session risk."""

    def __init__(
        self,
        model_dir: str | Path = "ml/artifacts",
    ) -> None:
        self.model_dir = Path(model_dir)
        self.pipeline: Any = None
        self.metadata: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load model and metadata, applying guardrails."""
        model_path = self.model_dir / MODEL_FILENAME
        meta_path = self.model_dir / METADATA_FILENAME

        if not model_path.is_file():
            raise ModelLoadError(
                f"Model artifact not found: {model_path}"
            )

        if not meta_path.is_file():
            raise ModelLoadError(
                f"Model metadata not found: {meta_path}"
            )

        # Load metadata first for validation
        with open(meta_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        # Schema version check
        model_schema = self.metadata.get("schema_version", "")
        if model_schema != SCHEMA_VERSION:
            raise SchemaVersionMismatch(
                f"Model schema version '{model_schema}' does not match "
                f"current schema version '{SCHEMA_VERSION}'"
            )

        # Feature count check
        model_feat_count = self.metadata.get("feature_count", 0)
        if model_feat_count != FEATURE_COUNT:
            raise FeatureCountMismatch(
                f"Model expects {model_feat_count} features, "
                f"but schema defines {FEATURE_COUNT}"
            )

        # Feature names check
        model_features = self.metadata.get("feature_names", [])
        if model_features != ALL_FEATURES:
            raise FeatureCountMismatch(
                f"Model feature names do not match canonical schema. "
                f"Model: {model_features}, Schema: {ALL_FEATURES}"
            )

        self.pipeline = joblib.load(model_path)

    def predict_session(
        self,
        session: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Predict risk for a single session.

        Returns
        -------
        Dict[str, Any]
            JSON-serializable prediction result.
        """
        feature_vec = extract_session_features(session, findings)
        ordered = feature_vector_to_ordered_list(feature_vec)

        # Run prediction
        X = np.array([ordered])
        predicted_label = self.pipeline.predict(X)[0]
        probas = self.pipeline.predict_proba(X)[0]
        confidence = float(max(probas))

        # Evidence quality
        quality, warnings = assess_prediction_quality(feature_vec)
        evidence_quality = calculate_evidence_quality(feature_vec)

        # Risk signals
        risk_signals = _extract_risk_signals(feature_vec)

        # Clean features for output (convert NaN to None for JSON)
        features_used = {}
        for feat in ALL_FEATURES:
            val = feature_vec[feat]
            features_used[feat] = None if _is_nan(val) else val

        return {
            "session_id": session.get("session_id", "unknown"),
            "risk": {
                "level": str(predicted_label),
                "confidence": round(confidence, 4),
                "ml_confidence": round(confidence, 4),
                "model_version": self.metadata.get("model_version", "unknown"),
                "prediction_quality": quality,
                "evidence_quality": evidence_quality,
            },
            "evidence_quality": evidence_quality,
            "risk_signals": risk_signals,
            "warnings": warnings,
            "features_used": features_used,
        }

    def predict_analysis(
        self,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Predict risk for all sessions in an analysis.

        Returns
        -------
        Dict[str, Any]
            Batch result with all session predictions.
        """
        validate_analysis_strict(analysis)

        sessions = analysis.get("sessions", [])
        findings = analysis.get("findings", [])

        session_predictions = [
            self.predict_session(session, findings)
            for session in sessions
        ]

        return {
            "model_version": self.metadata.get("model_version", "unknown"),
            "feature_schema_version": SCHEMA_VERSION,
            "session_predictions": session_predictions,
        }


# ── PCAP-level aggregation (MVP helper) ───────────────────────────

def aggregate_pcap_risk(
    session_predictions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """MVP PCAP-level risk aggregation.

    Simple deterministic logic:
    - If any session is CRITICAL → overall CRITICAL
    - Else if any HIGH → overall HIGH
    - Else if any MEDIUM → overall MEDIUM
    - Else → LOW

    Confidence = max confidence among sessions at the highest risk level.

    .. note::
        This is MVP logic and does NOT replace the rule engine.
    """
    level_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    if not session_predictions:
        return {
            "overall_risk_level": "LOW",
            "overall_confidence": 0.0,
            "note": "No sessions to aggregate.",
        }

    highest_level = "LOW"
    highest_priority = 1

    for pred in session_predictions:
        risk = pred.get("risk", {})
        level = risk.get("level", "LOW")
        priority = level_priority.get(level, 0)
        if priority > highest_priority:
            highest_priority = priority
            highest_level = level

    # Max confidence among sessions at the highest risk level
    max_confidence = 0.0
    for pred in session_predictions:
        risk = pred.get("risk", {})
        if risk.get("level") == highest_level:
            max_confidence = max(max_confidence, risk.get("confidence", 0.0))

    return {
        "overall_risk_level": highest_level,
        "overall_confidence": round(max_confidence, 4),
        "note": "MVP deterministic aggregation. Does not replace rule engine.",
    }


# ── CLI ────────────────────────────────────────────────────────────

def main(argv: List[str] | None = None) -> None:
    """CLI entry point for inference."""
    parser = argparse.ArgumentParser(
        description="Predict risk for sessions in an analysis JSON."
    )
    parser.add_argument(
        "--analysis", required=True,
        help="Path to analysis JSON file.",
    )
    parser.add_argument(
        "--model-dir", default="ml/artifacts",
        help="Directory containing model artifacts.",
    )

    args = parser.parse_args(argv)

    print(f"Loading model from: {args.model_dir}")
    predictor = RiskPredictor(args.model_dir)

    print(f"Loading analysis: {args.analysis}")
    with open(args.analysis, "r", encoding="utf-8") as f:
        analysis = json.load(f)

    results = predictor.predict_analysis(analysis)

    # Also compute PCAP-level aggregation
    pcap_risk = aggregate_pcap_risk(results["session_predictions"])
    results["pcap_aggregation"] = pcap_risk

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
