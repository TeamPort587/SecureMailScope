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

# Domain-specific human-readable interpretations for feature deviations
FEATURE_INTERPRETATIONS: Dict[str, Dict[str, str]] = {
    "if_encryption_plaintext": {
        "above": "Plaintext encryption mode diverges sharply from modern encrypted mail baseline; transmission lacks transport security.",
    },
    "if_auth_before_tls": {
        "above": "Authentication credentials transmitted in cleartext prior to TLS negotiation (violates baseline requirement).",
    },
    "if_upgrade_succeeded": {
        "below": "STARTTLS upgrade was not established; baseline sessions successfully upgrade to an encrypted channel.",
    },
    "if_upgrade_advertised": {
        "below": "STARTTLS upgrade was not advertised by the server; baseline mail servers advertise secure upgrade capability.",
    },
    "if_upgrade_requested": {
        "below": "STARTTLS upgrade was not requested by the client; baseline mail clients initiate secure upgrade.",
    },
    "if_tls_handshake_incomplete": {
        "above": "TLS handshake was incomplete or aborted before secure session establishment.",
    },
    "if_cert_visible": {
        "below": "Server certificate was not observable; baseline sessions present valid certificates during handshake.",
    },
    "if_cert_self_signed": {
        "above": "Self-signed certificate detected; diverges from baseline of publicly or CA-signed certificates.",
    },
    "if_tls_version_numeric": {
        "below": "Negotiated TLS version is deprecated/legacy compared to modern TLS 1.3 baseline.",
    },
    "if_cipher_strength": {
        "below": "Negotiated cipher suite strength is weaker than modern baseline standards.",
    },
    "if_pfs_present": {
        "below": "Perfect Forward Secrecy (PFS) is missing; baseline cipher suites support ephemeral key exchange.",
    },
    "if_cert_key_size": {
        "below": "Certificate key size is below the standard 2048-bit baseline.",
    },
    "if_cert_validity_days": {
        "below": "Certificate is expired or outside its valid date range.",
    },
    "if_tcp_reset_count": {
        "above": "Connection encountered abnormal TCP resets, indicating premature or forced termination.",
    },
    "if_session_complete": {
        "below": "Session terminated prematurely before normal protocol completion.",
    },
    "if_high_sev_count": {
        "above": "Session triggered high/critical severity security finding(s), absent in normal baseline.",
    },
    "if_finding_count": {
        "above": "Session accumulated security finding(s) that deviate from benign baseline traffic.",
    },
}

# Security importance ranking for deviation presentation ordering
SECURITY_PRIORITY: Dict[str, int] = {
    "if_encryption_plaintext": 100,
    "if_auth_before_tls": 95,
    "if_upgrade_succeeded": 90,
    "if_tls_handshake_incomplete": 85,
    "if_high_sev_count": 80,
    "if_finding_count": 75,
    "if_tls_version_numeric": 70,
    "if_cipher_strength": 65,
    "if_cert_self_signed": 60,
    "if_pfs_present": 55,
    "if_cert_key_size": 50,
    "if_cert_validity_days": 45,
    "if_upgrade_advertised": 40,
    "if_upgrade_requested": 35,
    "if_cert_visible": 30,
    "if_tcp_reset_count": 25,
    "if_session_complete": 20,
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
    summary = _generate_summary(bool(is_anomalous), deviations, feature_vector)

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


def _generate_summary(
    is_anomalous: bool,
    deviations: List[Dict[str, Any]],
    feature_vector: Dict[str, float],
) -> str:
    """Generate a clear, human-readable summary narrative."""
    if not is_anomalous:
        if deviations:
            primary_desc = deviations[0].get("description", "traffic metrics")
            return (
                f"This session's characteristics are within expected baseline limits, "
                f"with minor variance observed in {primary_desc.lower()}."
            )
        return (
            "This session's characteristics are within the expected baseline range "
            "learned during training."
        )

    # is_anomalous is True
    dev_features = {d["feature"] for d in deviations}

    if "if_auth_before_tls" in dev_features:
        return "Behavioral anomaly detected: plaintext credentials exposed prior to TLS negotiation."
    elif "if_encryption_plaintext" in dev_features:
        if feature_vector.get("if_protocol_imap") == 1.0:
            return "Behavioral anomaly detected: plaintext IMAP transmission with no TLS encryption layer."
        elif feature_vector.get("if_protocol_pop3") == 1.0:
            return "Behavioral anomaly detected: plaintext POP3 transmission with no TLS encryption layer."
        elif feature_vector.get("if_protocol_smtp") == 1.0:
            return "Behavioral anomaly detected: plaintext SMTP transmission with no TLS encryption layer."
        return "Behavioral anomaly detected: unencrypted plaintext transmission with no TLS encryption layer."
    elif "if_tls_handshake_incomplete" in dev_features or (
        "if_upgrade_succeeded" in dev_features and feature_vector.get("if_upgrade_advertised") == 1.0
    ):
        return "Behavioral anomaly detected: STARTTLS upgrade failed or TLS handshake was aborted."
    elif "if_tls_version_numeric" in dev_features:
        return "Behavioral anomaly detected: deprecated/legacy TLS version negotiated, deviating from modern baseline."
    elif "if_cipher_strength" in dev_features:
        return "Behavioral anomaly detected: weak cipher suite negotiated, deviating from modern baseline."
    elif "if_cert_self_signed" in dev_features:
        return "Behavioral anomaly detected: self-signed certificate presented, deviating from trusted baseline."
    elif "if_tcp_reset_count" in dev_features:
        return "Behavioral anomaly detected: abnormal connection termination with elevated TCP resets."
    elif deviations:
        primary_desc = deviations[0].get("description", "traffic patterns")
        return (
            f"Behavioral anomaly detected: session diverges from normal baseline in {len(deviations)} "
            f"observed characteristic(s), primarily in {primary_desc.lower()}."
        )
    else:
        return (
            "This session was classified as anomalous by the statistical model due to an unusual "
            "combination of multi-dimensional traffic features."
        )


def _compute_deviations(
    feature_vector: Dict[str, float],
    baseline_stats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Identify features that deviate notably from the training baseline."""
    deviations = []

    # Features evaluated via binary divergence
    binary_features = {
        "if_encryption_plaintext",
        "if_encryption_starttls",
        "if_encryption_implicit",
        "if_upgrade_advertised",
        "if_upgrade_requested",
        "if_upgrade_succeeded",
        "if_auth_before_tls",
        "if_tls_handshake_incomplete",
        "if_cert_visible",
        "if_cert_self_signed",
        "if_pfs_present",
        "if_session_complete",
    }

    # Features evaluated via non-zero / count divergence
    count_features = {
        "if_finding_count",
        "if_high_sev_count",
        "if_medium_sev_count",
        "if_tcp_reset_count",
    }

    # Features evaluated via ordinal ordering against baseline median
    ordinal_features = {
        "if_tls_version_numeric",
        "if_cipher_strength",
        "if_cert_key_size",
    }

    for feat_name in ALL_IF_FEATURES:
        val = feature_vector.get(feat_name)
        stats = baseline_stats.get(feat_name, {})

        if val is None or (isinstance(val, float) and math.isnan(val)):
            continue  # Skip unknown / non-applicable features

        # Skip protocol identifiers, key algorithm flags, and benign encrypted modes
        if feat_name in (
            "if_protocol_smtp",
            "if_protocol_imap",
            "if_protocol_pop3",
            "if_encryption_starttls",
            "if_encryption_implicit",
            "if_cert_key_algo_rsa",
            "if_cert_key_algo_ec",
        ):
            continue

        # If upgrade succeeded, don't flag advertised or requested flags as deviations
        if feat_name in ("if_upgrade_advertised", "if_upgrade_requested") and feature_vector.get("if_upgrade_succeeded") == 1.0:
            continue

        median = stats.get("median")
        iqr = stats.get("iqr_scale", 1.0)
        q25 = stats.get("q25")
        q75 = stats.get("q75")

        if median is None or iqr is None:
            continue

        is_deviation = False
        comparison = "within baseline range"

        if feat_name in binary_features:
            # Binary indicator: flip from expected baseline median (>= 0.5 difference)
            if abs(val - median) >= 0.5:
                is_deviation = True
                comparison = "above expected range" if val > median else "below expected range"
        elif feat_name in count_features:
            # Finding/event count: non-zero count when baseline median is zero, or exceeding fence
            if val > 0.0 and median == 0.0:
                is_deviation = True
                comparison = "above expected range"
            elif q75 is not None and val > q75 + 1.5 * iqr:
                is_deviation = True
                comparison = "above expected range"
        elif feat_name in ordinal_features:
            # Ordinal metric: directly below or above baseline median
            if val < median:
                is_deviation = True
                comparison = "below expected range"
            elif val > median:
                is_deviation = True
                comparison = "above expected range"
        elif feat_name == "if_cert_validity_days":
            # Certificate validity: expired (<= 0)
            if val <= 0.0:
                is_deviation = True
                comparison = "below expected range"
        else:
            # Continuous flow metrics: standard Tukey IQR fence
            lower_fence = q25 - 1.5 * iqr if q25 is not None else None
            upper_fence = q75 + 1.5 * iqr if q75 is not None else None

            if lower_fence is not None and val < lower_fence:
                is_deviation = True
                comparison = "below expected range"
            elif upper_fence is not None and val > upper_fence:
                is_deviation = True
                comparison = "above expected range"

        if is_deviation:
            description = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
            
            # Lookup domain-specific interpretation or fallback to descriptive template
            direction_key = "above" if "above" in comparison else "below"
            interpretation = (
                FEATURE_INTERPRETATIONS.get(feat_name, {}).get(direction_key)
                or f"{description} is {comparison} compared to the training baseline."
            )

            priority = SECURITY_PRIORITY.get(feat_name, 10)
            norm_magnitude = abs(val - median) / max(iqr, 1.0)

            deviations.append({
                "feature": feat_name,
                "description": description,
                "observed": round(val, 4) if isinstance(val, float) else val,
                "baseline_median": round(median, 4) if isinstance(median, float) else median,
                "comparison": comparison,
                "interpretation": interpretation,
                "_sort_key": (priority, norm_magnitude),
            })

    # Sort primarily by security priority, then by normalized deviation magnitude
    deviations.sort(
        key=lambda d: d["_sort_key"],
        reverse=True,
    )

    # Clean up internal sort key
    for d in deviations:
        d.pop("_sort_key", None)

    # Limit to top 10 most notable deviations
    return deviations[:10]


def _find_related_findings(
    deviations: List[Dict[str, Any]],
    session_findings: List[Dict[str, Any]],
) -> List[str]:
    """Map feature deviations to existing deterministic finding IDs."""
    related: List[str] = []

    # Map IF features to finding types
    feature_to_finding_types = {
        "if_auth_before_tls": ["AUTH_BEFORE_TLS"],
        "if_cipher_strength": ["WEAK_CIPHER"],
        "if_tls_version_numeric": ["DEPRECATED_TLS"],
        "if_cert_self_signed": ["SELF_SIGNED_CERT"],
        "if_cert_validity_days": ["EXPIRED_CERT", "NOT_YET_VALID_CERT"],
        "if_cert_key_size": ["WEAK_KEY"],
        "if_pfs_present": ["PFS_MISSING"],
        "if_tls_handshake_incomplete": ["FAILED_STARTTLS"],
        "if_upgrade_succeeded": ["FAILED_STARTTLS"],
        "if_encryption_plaintext": ["PLAINTEXT"],
    }

    deviation_features = {d["feature"] for d in deviations}

    for finding in session_findings:
        finding_type = finding.get("finding_type", "")
        finding_id = finding.get("finding_id", "")
        if not finding_id:
            continue

        matched = False
        for feat, ftypes in feature_to_finding_types.items():
            if feat in deviation_features and finding_type in ftypes:
                if finding_id not in related:
                    related.append(finding_id)
                matched = True

        # If general finding counts deviated, correlate any unmatched session findings
        if not matched and (
            "if_high_sev_count" in deviation_features
            or "if_finding_count" in deviation_features
        ):
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
