"""
Isolation Forest — Session-Level Feature Extractor
====================================================

Builds a 30-feature anomaly vector from the existing Session dataclass,
SecurityProfile, and findings — reusing the existing reconstructed objects
without re-parsing the PCAP.

Does NOT modify or depend on the 19-feature RF extractor.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from analysis.feature_extraction.models import (
    CertificateInfo,
    Finding,
    SecurityInfo,
    SecurityProfile,
    Session,
    TLSInfo,
)
from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    IF_FEATURE_COUNT,
    IF_SCHEMA_VERSION,
    TLS_VERSION_ENCODING,
    WEAK_CIPHER_TOKENS,
)

NaN = float("nan")

# Type alias
AnomalyFeatureVector = Dict[str, float]


def _tri_state_to_binary(val: str) -> float:
    """Convert YES/NO/UNKNOWN tri-state to 1.0/0.0/NaN."""
    if val == "YES":
        return 1.0
    elif val == "NO":
        return 0.0
    return NaN


def _encode_tls_version(version: Optional[str]) -> float:
    """Encode TLS version to ordinal numeric value."""
    if not version:
        return NaN
    return TLS_VERSION_ENCODING.get(version, NaN)


def _classify_cipher_strength(cipher_suite: Optional[str]) -> float:
    """Classify cipher suite strength: 0=weak, 1=moderate, 2=strong, NaN=unknown."""
    if not cipher_suite:
        return NaN
    upper = cipher_suite.upper()
    for tok in WEAK_CIPHER_TOKENS:
        if tok in upper:
            return 0.0  # weak
    # Modern GCM / CHACHA suites are strong
    if "GCM" in upper or "CHACHA" in upper or "CCM" in upper:
        return 2.0  # strong
    return 1.0  # moderate


def _compute_cert_validity_days(
    valid_until: Optional[str],
    now: Optional[datetime] = None,
) -> float:
    """Compute remaining certificate validity in days."""
    if not valid_until:
        return NaN
    try:
        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        ref = now or datetime.now(timezone.utc)
        delta = (expiry - ref).total_seconds() / 86400.0
        return round(delta, 2)
    except (ValueError, AttributeError):
        return NaN


def extract_anomaly_features(
    session: Session,
    profile: SecurityProfile,
    findings: List[Finding],
    *,
    now: Optional[datetime] = None,
) -> AnomalyFeatureVector:
    """Extract the 30-feature Isolation Forest vector for a single session.

    Parameters
    ----------
    session : Session
        The reconstructed TCP session (contains packets, packet counts).
    profile : SecurityProfile
        The normalized security profile for this session.
    findings : List[Finding]
        Findings for THIS session only (pre-filtered by caller).
    now : datetime, optional
        Reference time for certificate validity. Defaults to UTC now.

    Returns
    -------
    AnomalyFeatureVector
        Dict mapping each of the 30 IF feature names to a float value.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    sec: SecurityInfo = profile.security
    tls: Optional[TLSInfo] = profile.tls
    cert: Optional[CertificateInfo] = profile.certificate

    cert_visible = (
        cert is not None
        and cert.visibility != "NOT_OBSERVABLE"
    )

    vec: AnomalyFeatureVector = {}

    # ── A. Protocol & connection context ────────────────────────────
    proto = profile.protocol
    vec["if_protocol_smtp"] = 1.0 if proto == "SMTP" else (0.0 if proto in ("IMAP", "POP3") else NaN)
    vec["if_protocol_imap"] = 1.0 if proto == "IMAP" else (0.0 if proto in ("SMTP", "POP3") else NaN)
    vec["if_protocol_pop3"] = 1.0 if proto == "POP3" else (0.0 if proto in ("SMTP", "IMAP") else NaN)

    enc = sec.encryption_mode
    vec["if_encryption_plaintext"] = 1.0 if enc == "PLAINTEXT" else (0.0 if enc in ("STARTTLS", "IMPLICIT_TLS") else NaN)
    vec["if_encryption_starttls"] = 1.0 if enc in ("STARTTLS", "STLS") else (0.0 if enc in ("PLAINTEXT", "IMPLICIT_TLS") else NaN)
    vec["if_encryption_implicit"] = 1.0 if enc == "IMPLICIT_TLS" else (0.0 if enc in ("PLAINTEXT", "STARTTLS", "STLS") else NaN)

    vec["if_upgrade_advertised"] = _tri_state_to_binary(sec.upgrade_advertised)
    vec["if_upgrade_requested"] = _tri_state_to_binary(sec.upgrade_requested)
    vec["if_upgrade_succeeded"] = _tri_state_to_binary(sec.upgrade_succeeded)
    vec["if_auth_before_tls"] = _tri_state_to_binary(sec.authentication_before_tls)

    # ── B. TLS behavior ────────────────────────────────────────────
    if tls is not None:
        vec["if_tls_version_numeric"] = _encode_tls_version(tls.version)
        vec["if_cipher_strength"] = _classify_cipher_strength(tls.cipher_suite)
        vec["if_pfs_present"] = _tri_state_to_binary(tls.pfs)
        # Handshake incomplete if TLS is expected but cipher is missing
        if tls.cipher_suite:
            vec["if_tls_handshake_incomplete"] = 0.0
        else:
            vec["if_tls_handshake_incomplete"] = 1.0
    else:
        vec["if_tls_version_numeric"] = NaN
        vec["if_cipher_strength"] = NaN
        vec["if_pfs_present"] = NaN
        # If encryption mode suggests TLS should exist but tls is None
        if enc in ("STARTTLS", "STLS", "IMPLICIT_TLS"):
            vec["if_tls_handshake_incomplete"] = 1.0
        elif enc == "PLAINTEXT":
            vec["if_tls_handshake_incomplete"] = 0.0  # No TLS expected
        else:
            vec["if_tls_handshake_incomplete"] = NaN

    # ── C. Certificate characteristics ─────────────────────────────
    vec["if_cert_visible"] = 1.0 if cert_visible else 0.0

    if cert_visible and cert is not None:
        vec["if_cert_key_size"] = float(cert.key_size) if cert.key_size is not None else NaN
        if cert.self_signed is True:
            vec["if_cert_self_signed"] = 1.0
        elif cert.self_signed is False:
            vec["if_cert_self_signed"] = 0.0
        else:
            vec["if_cert_self_signed"] = NaN
        vec["if_cert_validity_days"] = _compute_cert_validity_days(cert.valid_until, now)
        vec["if_cert_key_algo_rsa"] = 1.0 if cert.key_type == "RSA" else (0.0 if cert.key_type else NaN)
        vec["if_cert_key_algo_ec"] = 1.0 if cert.key_type in ("EC", "ECDSA") else (0.0 if cert.key_type else NaN)
    else:
        vec["if_cert_key_size"] = NaN
        vec["if_cert_self_signed"] = NaN
        vec["if_cert_validity_days"] = NaN
        vec["if_cert_key_algo_rsa"] = NaN
        vec["if_cert_key_algo_ec"] = NaN

    # ── D. TCP & session behavior ──────────────────────────────────
    vec["if_packet_count"] = float(session.packet_count)

    # Duration from first to last packet timestamp
    if session.packets and len(session.packets) >= 2:
        first_ts = session.packets[0].timestamp
        last_ts = session.packets[-1].timestamp
        duration = last_ts - first_ts
        vec["if_session_duration"] = round(max(0.0, duration), 4)
    elif session.packets and len(session.packets) == 1:
        vec["if_session_duration"] = 0.0
    else:
        vec["if_session_duration"] = NaN

    vec["if_client_packet_count"] = float(len(session.client_packets))
    vec["if_server_packet_count"] = float(len(session.server_packets))

    total_pkts = float(session.packet_count) if session.packet_count > 0 else 1.0
    vec["if_packet_ratio"] = round(float(len(session.client_packets)) / total_pkts, 4)

    # TCP reset count
    reset_count = sum(1 for p in session.packets if p.tcp_flags_reset)
    vec["if_tcp_reset_count"] = float(reset_count)

    # Session completeness
    if session.completeness == "COMPLETE":
        vec["if_session_complete"] = 1.0
    elif session.completeness in ("PARTIAL", "UNKNOWN"):
        vec["if_session_complete"] = 0.0
    else:
        vec["if_session_complete"] = 0.0

    # ── E. Deterministic context ───────────────────────────────────
    vec["if_finding_count"] = float(len(findings))
    vec["if_high_sev_count"] = float(sum(1 for f in findings if f.severity in ("HIGH", "CRITICAL")))
    vec["if_medium_sev_count"] = float(sum(1 for f in findings if f.severity == "MEDIUM"))

    # ── Validation ─────────────────────────────────────────────────
    assert len(vec) == IF_FEATURE_COUNT, (
        f"IF feature vector has {len(vec)} features, expected {IF_FEATURE_COUNT}"
    )

    return vec


def feature_vector_to_ordered_list(vec: AnomalyFeatureVector) -> List[float]:
    """Convert IF feature dict to a list in canonical order."""
    return [vec[name] for name in ALL_IF_FEATURES]
