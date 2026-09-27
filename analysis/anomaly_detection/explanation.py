"""
Isolation Forest — Anomaly Explanation
=======================================

Generates human-readable explanations for anomaly predictions
by comparing observed features against saved baseline statistics.

Does NOT claim to identify the exact cause — provides transparent
feature deviation information only.
"""

from __future__ import annotations

import math
import logging
from typing import Any, Dict, List, Optional

from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    ANOMALY_CLASSIFICATION_ANOMALOUS,
    ANOMALY_CLASSIFICATION_BASELINE,
)

logger = logging.getLogger(__name__)

# Human-readable feature descriptions
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "if_protocol_smtp": "Protocol: SMTP",
    "if_protocol_imap": "Protocol: IMAP",
    "if_protocol_pop3": "Protocol: POP3",
    "if_encryption_plaintext": "Encryption: Plaintext",
    "if_encryption_starttls": "Encryption: STARTTLS",
    "if_encryption_implicit": "Encryption: Implicit TLS",
    "if_upgrade_advertised": "STARTTLS upgrade advertised",
    "if_upgrade_requested": "STARTTLS upgrade requested",
    "if_upgrade_succeeded": "STARTTLS upgrade succeeded",
    "if_auth_before_tls": "Authentication before TLS",
    "if_tls_version_numeric": "TLS version",
    "if_cipher_strength": "Cipher suite strength",
    "if_pfs_present": "Perfect forward secrecy",
    "if_tls_handshake_incomplete": "TLS handshake completeness",
    "if_cert_visible": "Certificate visibility",
    "if_cert_key_size": "Certificate key size (bits)",
    "if_cert_self_signed": "Self-signed certificate",
    "if_cert_validity_days": "Certificate validity (days remaining)",
    "if_cert_key_algo_rsa": "Certificate algorithm: RSA",
    "if_cert_key_algo_ec": "Certificate algorithm: EC",
    "if_packet_count": "Packet count",
    "if_session_duration": "Session duration (seconds)",
    "if_client_packet_count": "Client packet count",
    "if_server_packet_count": "Server packet count",
    "if_packet_ratio": "Client/total packet ratio",
    "if_tcp_reset_count": "TCP reset count",
    "if_session_complete": "Session completeness",
    "if_finding_count": "Finding count",
    "if_high_sev_count": "High/critical finding count",
    "if_medium_sev_count": "Medium finding count",
}


def explain_anomaly(
    feature_vector: Dict[str, float],
    prediction: Dict[str, Any],
    baseline_stats: Dict[str, Any],
    session_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate a human-readable explanation for an anomaly prediction.

    Parameters
    ----------
    feature_vector : Dict[str, float]
        The 30-feature IF vector.
    prediction : Dict[str, Any]
        The inference result from AnomalyPredictor.predict().
    baseline_stats : Dict[str, Any]
        Saved baseline statistics from training.
    session_findings : List[Dict], optional
        Existing deterministic findings for this session.

    Returns
    -------
    Dict with summary, deviations, related findings, and limitations.
    """
    classification = prediction.get("classification")
    is_anomalous = prediction.get("is_anomalous")

    if classification is None:
        return _unavailable_explanation(prediction)

    deviations = _compute_deviations(feature_vector, baseline_stats)
    related_findings = _find_related_findings(deviations, session_findings or [])

    if is_anomalous:
        if deviations:
            summary = (
                f"This session differs from the learned baseline in {len(deviations)} "
                f"observed characteristic(s). The most notable deviations are listed below."
            )
        else:
            summary = (
                "This session was classified as anomalous by the statistical model, "
                "but no individual feature deviation was identified. The anomaly may "
                "arise from an unusual combination of features."
            )
    else:
        summary = (
            "This session's characteristics are within the expected baseline range "
            "learned during training."
        )

    return {
        "summary": summary,
        "deviations": deviations,
        "related_findings": related_findings,
        "limitations": [
            "Anomaly detection identifies statistical deviations, not confirmed attacks.",
            "Normal but uncommon traffic may be flagged as anomalous.",
            "The model sees only features extracted by the current parser.",
            "Raw anomaly scores are not attack probabilities.",
        ],
    }


def _compute_deviations(
    feature_vector: Dict[str, float],
    baseline_stats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Identify features that deviate notably from the training baseline."""
    deviations = []

    for feat_name in ALL_IF_FEATURES:
        val = feature_vector.get(feat_name)
        stats = baseline_stats.get(feat_name, {})

        if val is None or (isinstance(val, float) and math.isnan(val)):
            continue  # Skip unknown features

        median = stats.get("median")
        iqr = stats.get("iqr_scale", 1.0)
        q25 = stats.get("q25")
        q75 = stats.get("q75")

        if median is None or iqr is None:
            continue

        # Check if value is outside the IQR-based range
        # Use 1.5 * IQR as the threshold (standard outlier fence)
        lower_fence = q25 - 1.5 * iqr if q25 is not None else None
        upper_fence = q75 + 1.5 * iqr if q75 is not None else None

        is_deviation = False
        comparison = "within baseline range"

        if lower_fence is not None and val < lower_fence:
            is_deviation = True
            comparison = "below expected range"
        elif upper_fence is not None and val > upper_fence:
            is_deviation = True
            comparison = "above expected range"

        if is_deviation:
            description = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
            deviations.append({
                "feature": feat_name,
                "description": description,
                "observed": round(val, 4) if isinstance(val, float) else val,
                "baseline_median": round(median, 4) if isinstance(median, float) else median,
                "comparison": comparison,
                "interpretation": (
                    f"{description} is {comparison} compared to the training baseline."
                ),
            })

    # Sort by magnitude of deviation (most notable first)
    deviations.sort(
        key=lambda d: abs(d["observed"] - (d["baseline_median"] or 0)),
        reverse=True,
    )

    # Limit to top 10 most notable deviations
    return deviations[:10]


def _find_related_findings(
    deviations: List[Dict[str, Any]],
    session_findings: List[Dict[str, Any]],
) -> List[str]:
    """Map feature deviations to existing deterministic finding IDs."""
    related = []

    # Map IF features to finding types
    feature_to_finding_type = {
        "if_auth_before_tls": "AUTH_BEFORE_TLS",
        "if_cipher_strength": "WEAK_CIPHER",
        "if_tls_version_numeric": "DEPRECATED_TLS",
        "if_cert_self_signed": "SELF_SIGNED_CERT",
        "if_cert_validity_days": "EXPIRED_CERT",
        "if_cert_key_size": "WEAK_KEY",
        "if_pfs_present": "PFS_MISSING",
        "if_tls_handshake_incomplete": "FAILED_STARTTLS",
        "if_encryption_plaintext": "PLAINTEXT",
    }

    deviation_features = {d["feature"] for d in deviations}

    for finding in session_findings:
        finding_type = finding.get("finding_type", "")
        finding_id = finding.get("finding_id", "")

        for feat, ftype in feature_to_finding_type.items():
            if feat in deviation_features and finding_type == ftype:
                if finding_id not in related:
                    related.append(finding_id)

    return related


def _unavailable_explanation(prediction: Dict[str, Any]) -> Dict[str, Any]:
    """Return explanation when prediction is unavailable."""
    status = prediction.get("status", "UNKNOWN")
    return {
        "summary": f"Anomaly assessment is unavailable (status: {status}).",
        "deviations": [],
        "related_findings": [],
        "limitations": [
            "The anomaly model could not produce a result for this session.",
        ],
    }
