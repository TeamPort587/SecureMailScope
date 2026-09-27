"""
Isolation Forest — Anomaly Detection Service
==============================================

High-level service that coordinates feature extraction, inference,
and explanation for a session. This is the entry point called by
the pipeline.

Provides the public interface:
    analyze_session_anomaly(session, profile, findings) -> AnomalyResult
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from analysis.feature_extraction.models import Finding, SecurityProfile, Session
from analysis.anomaly_detection.feature_extractor import extract_anomaly_features
from analysis.anomaly_detection.feature_schema import (
    ANOMALY_STATUS_ERROR,
    ANOMALY_STATUS_UNAVAILABLE,
    IF_MODEL_VERSION,
    IF_SCHEMA_VERSION,
)
from analysis.anomaly_detection.explanation import explain_anomaly

logger = logging.getLogger(__name__)

# Cached singleton predictor
_PREDICTOR = None
_PREDICTOR_LOAD_ATTEMPTED = False


def _get_predictor():
    """Retrieve or initialize the cached AnomalyPredictor singleton."""
    global _PREDICTOR, _PREDICTOR_LOAD_ATTEMPTED

    if _PREDICTOR is not None:
        return _PREDICTOR

    if _PREDICTOR_LOAD_ATTEMPTED:
        return None  # Already tried and failed, don't retry every request

    _PREDICTOR_LOAD_ATTEMPTED = True

    try:
        from analysis.anomaly_detection.inference import AnomalyPredictor
        artifact_dir = Path(__file__).resolve().parent / "artifacts"
        _PREDICTOR = AnomalyPredictor(artifact_dir=artifact_dir)
        logger.info("AnomalyPredictor initialized successfully.")
        return _PREDICTOR
    except Exception as exc:
        logger.warning(
            "Could not load AnomalyPredictor: %s. "
            "Anomaly detection will be unavailable.", exc
        )
        return None


def analyze_session_anomaly(
    session: Session,
    profile: SecurityProfile,
    findings: List[Finding],
) -> Dict[str, Any]:
    """Run Isolation Forest anomaly detection on a single session.

    This is the main public API called by the pipeline.
    It NEVER raises exceptions — all failures produce explicit status results.

    Parameters
    ----------
    session : Session
        Reconstructed TCP session.
    profile : SecurityProfile
        Normalized security profile.
    findings : List[Finding]
        Deterministic findings for THIS session (pre-filtered).

    Returns
    -------
    Dict containing the anomaly assessment for this session.
    """
    predictor = _get_predictor()

    if predictor is None:
        return _unavailable_result()

    try:
        # Extract features
        feature_vector = extract_anomaly_features(session, profile, findings)

        # Run inference
        prediction = predictor.predict(feature_vector)

        # Generate explanation
        finding_dicts = [f.to_dict() for f in findings]
        explanation = explain_anomaly(
            feature_vector=feature_vector,
            prediction=prediction,
            baseline_stats=predictor.baseline_stats,
            session_findings=finding_dicts,
        )

        return {
            "session_id": profile.session_id,
            "anomaly": {
                **prediction,
                "explanation": explanation,
            },
        }

    except Exception as exc:
        s_id = getattr(profile, "session_id", "unknown") if profile else "unknown"
        logger.warning(
            "Anomaly analysis error for session %s: %s",
            s_id, exc,
        )
        return {
            "session_id": s_id,
            "anomaly": {
                "status": ANOMALY_STATUS_ERROR,
                "classification": None,
                "is_anomalous": None,
                "raw_score": None,
                "decision_score": None,
                "threshold": None,
                "model_version": IF_MODEL_VERSION,
                "feature_schema_version": IF_SCHEMA_VERSION,
                "warnings": [f"Anomaly analysis failed: {str(exc)}"],
                "explanation": {
                    "summary": "Anomaly assessment could not be completed due to an internal error.",
                    "deviations": [],
                    "related_findings": [],
                    "limitations": ["An internal error prevented anomaly analysis."],
                },
            },
        }


def aggregate_anomaly_results(
    session_anomalies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute PCAP-level anomaly summary from per-session results.

    Parameters
    ----------
    session_anomalies : List[Dict]
        Per-session anomaly results.

    Returns
    -------
    Dict with aggregate anomaly counts and status.
    """
    total = len(session_anomalies)
    anomalous = 0
    within_baseline = 0
    insufficient = 0
    unavailable = 0
    error = 0
    anomalous_session_ids = []

    for result in session_anomalies:
        anomaly = result.get("anomaly", {})
        status = anomaly.get("status", "")
        classification = anomaly.get("classification")

        if status == "COMPLETE":
            if anomaly.get("is_anomalous"):
                anomalous += 1
                anomalous_session_ids.append(result.get("session_id", ""))
            else:
                within_baseline += 1
        elif status == "INSUFFICIENT_EVIDENCE":
            insufficient += 1
        elif status == "MODEL_UNAVAILABLE":
            unavailable += 1
        else:
            error += 1

    # Overall status
    if unavailable == total:
        overall_status = ANOMALY_STATUS_UNAVAILABLE
    elif anomalous > 0:
        overall_status = "ANOMALIES_DETECTED"
    elif within_baseline == total:
        overall_status = "ALL_WITHIN_BASELINE"
    else:
        overall_status = "MIXED"

    return {
        "overall_status": overall_status,
        "total_sessions": total,
        "anomalous_count": anomalous,
        "within_baseline_count": within_baseline,
        "insufficient_evidence_count": insufficient,
        "unavailable_count": unavailable,
        "error_count": error,
        "anomalous_session_ids": anomalous_session_ids,
    }


def _unavailable_result() -> Dict[str, Any]:
    """Return a structured MODEL_UNAVAILABLE result."""
    return {
        "session_id": None,
        "anomaly": {
            "status": ANOMALY_STATUS_UNAVAILABLE,
            "classification": None,
            "is_anomalous": None,
            "raw_score": None,
            "decision_score": None,
            "threshold": None,
            "model_version": IF_MODEL_VERSION,
            "feature_schema_version": IF_SCHEMA_VERSION,
            "warnings": ["Isolation Forest model is not available."],
            "explanation": {
                "summary": "Anomaly detection model is not loaded.",
                "deviations": [],
                "related_findings": [],
                "limitations": ["Model artifacts not found or failed to load."],
            },
        },
    }
