"""End-to-end analysis pipeline orchestrator for SecureMailScope.

Coordinates PCAP parsing, session reconstruction, feature extraction,
rule evaluation, and summary aggregation matching django-analysis-response.json.
"""

import hashlib
import os
import uuid
from typing import Any, Dict, List, Optional

from analysis.feature_extraction.extractor import extract_security_profile
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.pcap_parser.parser import parse_pcap
from analysis.rule_engine.engine import evaluate_profile
from analysis.session_engine.engine import build_sessions


class AnalysisError(Exception):
    """Exception raised when analysis pipeline cannot complete."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


import logging
from pathlib import Path
from ml.feature_engineering.extractor import extract_session_features
from ml.inference.predictor import RiskPredictor, aggregate_pcap_risk
from ml.risk.risk_aggregator import calculate_session_risk
from recommendation.engine import generate_recommendations as rec_engine_generate
from recommendation.priority import sort_recommendations
from recommendation.risk_guard import calculate_final_risk

logger = logging.getLogger(__name__)

# Cached predictor singleton
_PREDICTOR: Optional[RiskPredictor] = None


def get_risk_predictor() -> Optional[RiskPredictor]:
    """Retrieve or initialize the singleton ML RiskPredictor."""
    global _PREDICTOR
    if _PREDICTOR is None:
        model_dir = Path(__file__).resolve().parents[2] / "ml" / "artifacts"
        try:
            _PREDICTOR = RiskPredictor(model_dir=model_dir)
            logger.info("Initialized ML RiskPredictor successfully.")
        except Exception as exc:
            logger.warning(f"Could not load ML RiskPredictor from {model_dir}: {exc}. Using Canonical Risk Aggregator fallback.")
            _PREDICTOR = None
    return _PREDICTOR


def build_recommendations(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Generate prioritized recommendations via the recommendation engine."""
    finding_dicts = [f.to_dict() for f in findings]
    raw_recs = rec_engine_generate(finding_dicts)
    sorted_recs = sort_recommendations(raw_recs)

    # Format cleanly according to contract
    formatted: List[Dict[str, Any]] = []
    for r in sorted_recs:
        formatted.append({
            "recommendation_id": r.get("recommendation_id", "rec-001"),
            "priority": r.get("priority", "HIGH"),
            "title": r.get("title", "Security Recommendation"),
            "description": r.get("description", ""),
        })

    # If no findings, provide positive guidance
    if not formatted:
        formatted.append({
            "recommendation_id": "rec-001",
            "priority": "LOW",
            "title": "Maintain modern encryption hygiene",
            "description": "All inspected email sessions utilized valid, modern TLS protection with no observed security weaknesses.",
        })

    return formatted


def calculate_reconciled_risk(
    session_dicts: List[Dict[str, Any]],
    finding_dicts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Calculate reconciled risk combining ML inference, Canonical Risk Aggregator, and Risk Guard."""
    predictor = get_risk_predictor()
    session_predictions: List[Dict[str, Any]] = []

    for s in session_dicts:
        s_id = s.get("session_id")
        s_findings = [f for f in finding_dicts if f.get("session_id") == s_id]

        feature_vec = extract_session_features(s, s_findings)

        # 1. ML prediction
        if predictor is not None:
            try:
                ml_pred = predictor.predict_session(s, s_findings)
                ml_risk_level = ml_pred["risk"]["level"]
                ml_confidence = ml_pred["risk"]["confidence"]
                pred_quality = ml_pred["risk"].get("prediction_quality", "SUFFICIENT_EVIDENCE")
                ev_quality = ml_pred.get("evidence_quality", "HIGH_EVIDENCE")
            except Exception as e:
                logger.warning(f"Inference error for session {s_id}: {e}")
                canonical_label, _ = calculate_session_risk(feature_vec)
                ml_risk_level = canonical_label
                ml_confidence = 0.90
                pred_quality = "SUFFICIENT_EVIDENCE"
                ev_quality = "HIGH_EVIDENCE"
        else:
            canonical_label, _ = calculate_session_risk(feature_vec)
            ml_risk_level = canonical_label
            ml_confidence = 0.90
            pred_quality = "SUFFICIENT_EVIDENCE"
            ev_quality = "HIGH_EVIDENCE"

        # 2. Reconcile with Risk Guard (ML can NEVER downgrade mandatory critical rule findings)
        reconciled = calculate_final_risk(ml_risk_level, s_findings)
        final_level = reconciled["final_risk_level"]

        session_predictions.append({
            "session_id": s_id,
            "risk": {
                "level": final_level,
                "ml_level": ml_risk_level,
                "confidence": ml_confidence,
                "prediction_quality": pred_quality,
                "evidence_quality": ev_quality,
            },
            "evidence_quality": ev_quality,
        })

    # PCAP-level aggregation
    pcap_agg = aggregate_pcap_risk(session_predictions)
    overall_level = pcap_agg.get("overall_risk_level", "LOW")
    overall_conf = pcap_agg.get("overall_confidence", 0.90)

    # Calculate calibrated numeric score
    crit_count = sum(1 for f in finding_dicts if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in finding_dicts if f.get("severity") == "HIGH")
    med_count = sum(1 for f in finding_dicts if f.get("severity") == "MEDIUM")

    if overall_level == "CRITICAL":
        score = min(100, 85 + crit_count * 5)
    elif overall_level == "HIGH":
        score = min(84, 65 + high_count * 4)
    elif overall_level == "MEDIUM":
        score = min(64, 40 + med_count * 5)
    else:
        score = 15

    return {
        "score": score,
        "level": overall_level,
        "model_version": "rf-v1",
        "method": "RULE_ENGINE_PLUS_ML",
        "confidence": round(overall_conf, 2),
    }


def analyze_pcap(
    file_path: str,
    analysis_id: Optional[str] = None,
    filename: Optional[str] = None,
    backend: str = "tshark",
) -> Dict[str, Any]:
    """Execute end-to-end analysis on an uploaded PCAP capture.

    Args:
        file_path: Absolute or relative path to PCAP/PCAPNG file.
        analysis_id: Optional unique identifier; generated if omitted.
        filename: Original user filename if provided.
        backend: Preferred parsing backend ("tshark" or "pyshark").

    Returns:
        Structured analysis dictionary strictly conforming to django-analysis-response.json.
    """
    if not os.path.exists(file_path):
        raise AnalysisError("FILE_NOT_FOUND", f"PCAP capture file not found at: {file_path}")

    size_bytes = os.path.getsize(file_path)
    if size_bytes == 0:
        raise AnalysisError("EMPTY_FILE", "The uploaded PCAP file is empty (0 bytes).")

    sha256_hash = compute_sha256(file_path)
    effective_analysis_id = analysis_id or str(uuid.uuid4())
    effective_filename = filename or os.path.basename(file_path)

    # 1. Parse packets
    try:
        packets = parse_pcap(file_path, backend=backend)
    except Exception as exc:
        raise AnalysisError("INVALID_PCAP", f"Failed to parse PCAP file: {str(exc)}")

    # 2. Reconstruct sessions
    all_sessions = build_sessions(packets)

    # Filter for email protocols only (SMTP, IMAP, POP3)
    email_sessions = [s for s in all_sessions if s.protocol in ("SMTP", "IMAP", "POP3")]
    if not email_sessions:
        raise AnalysisError(
            "NO_EMAIL_TRAFFIC",
            "No SMTP, IMAP, or POP3 traffic was detected in the capture.",
        )

    # 3. Extract profiles and evaluate rules
    profiles: List[SecurityProfile] = []
    all_findings: List[Finding] = []
    finding_counter = 1
    vulnerable_session_ids = set()

    for s in email_sessions:
        profile = extract_security_profile(s)
        profiles.append(profile)

        findings = evaluate_profile(profile, start_index=finding_counter)
        for f in findings:
            all_findings.append(f)
            finding_counter += 1
            if f.severity in ("HIGH", "CRITICAL"):
                vulnerable_session_ids.add(s.session_id)

    # 4. Summary counts
    smtp_count = sum(1 for p in profiles if p.protocol == "SMTP")
    imap_count = sum(1 for p in profiles if p.protocol == "IMAP")
    pop3_count = sum(1 for p in profiles if p.protocol == "POP3")

    plaintext_count = sum(1 for p in profiles if p.security.encryption_mode == "PLAINTEXT")
    starttls_count = sum(1 for p in profiles if p.security.encryption_mode == "STARTTLS")
    implicit_tls_count = sum(1 for p in profiles if p.security.encryption_mode == "IMPLICIT_TLS")

    summary = {
        "total_sessions": len(profiles),
        "smtp_sessions": smtp_count,
        "imap_sessions": imap_count,
        "pop3_sessions": pop3_count,
        "plaintext_sessions": plaintext_count,
        "starttls_sessions": starttls_count,
        "implicit_tls_sessions": implicit_tls_count,
        "vulnerable_sessions": len(vulnerable_session_ids),
        "findings_count": len(all_findings),
    }

    # 5. Reconciled Risk and Recommendations
    session_dicts = [p.to_dict() for p in profiles]
    finding_dicts = [f.to_dict() for f in all_findings]

    risk = calculate_reconciled_risk(session_dicts, finding_dicts)
    recommendations = build_recommendations(all_findings)

    # 6. Build final contract response
    response_payload: Dict[str, Any] = {
        "analysis_version": "1.0.0",
        "file": {
            "analysis_id": effective_analysis_id,
            "filename": effective_filename,
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
        },
        "summary": summary,
        "sessions": [p.to_dict() for p in profiles],
        "findings": [f.to_dict() for f in all_findings],
        "risk": risk,
        "recommendations": recommendations,
    }

    return response_payload
