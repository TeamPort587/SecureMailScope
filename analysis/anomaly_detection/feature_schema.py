"""
Isolation Forest Feature Schema
================================

Single source of truth for the Isolation Forest anomaly detection feature
vector — names, ordering, version, and encoding policies.

This is INDEPENDENT from the 19-feature Random Forest schema in
ml/feature_engineering/schema.py.
"""

from __future__ import annotations
from typing import Dict, FrozenSet, List, Tuple

# ── Schema version ──────────────────────────────────────────────────
IF_SCHEMA_VERSION: str = "if-features-v1"

# ── Isolation Forest Feature Names (stable order) ───────────────────
# A. Protocol & connection context
PROTOCOL_FEATURES: List[str] = [
    "if_protocol_smtp",          # 1  one-hot
    "if_protocol_imap",          # 2  one-hot
    "if_protocol_pop3",          # 3  one-hot
    "if_encryption_plaintext",   # 4  one-hot
    "if_encryption_starttls",    # 5  one-hot
    "if_encryption_implicit",    # 6  one-hot
    "if_upgrade_advertised",     # 7  binary (1=YES, 0=NO, NaN=UNKNOWN)
    "if_upgrade_requested",      # 8  binary
    "if_upgrade_succeeded",      # 9  binary
    "if_auth_before_tls",        # 10 binary
]

# B. TLS behavior
TLS_FEATURES: List[str] = [
    "if_tls_version_numeric",    # 11 ordinal: 0=SSLv2, 1=SSLv3, 2=TLS1.0, 3=TLS1.1, 4=TLS1.2, 5=TLS1.3, NaN=unknown
    "if_cipher_strength",        # 12 ordinal: 0=weak, 1=moderate, 2=strong, NaN=unknown
    "if_pfs_present",            # 13 binary (1=YES, 0=NO, NaN=UNKNOWN)
    "if_tls_handshake_incomplete",  # 14 binary (1=incomplete, 0=complete, NaN=unknown)
]

# C. Certificate characteristics
CERT_FEATURES: List[str] = [
    "if_cert_visible",           # 15 binary (1=observed, 0=not observable)
    "if_cert_key_size",          # 16 numeric (bits, NaN if not observable)
    "if_cert_self_signed",       # 17 binary (1=yes, 0=no, NaN=unknown)
    "if_cert_validity_days",     # 18 numeric (remaining days, NaN if unknown)
    "if_cert_key_algo_rsa",      # 19 binary (1=RSA, 0=other, NaN=unknown)
    "if_cert_key_algo_ec",       # 20 binary (1=EC, 0=other, NaN=unknown)
]

# D. TCP & session behavior
SESSION_FEATURES: List[str] = [
    "if_packet_count",           # 21 numeric
    "if_session_duration",       # 22 numeric (seconds)
    "if_client_packet_count",    # 23 numeric
    "if_server_packet_count",    # 24 numeric
    "if_packet_ratio",           # 25 numeric (client/total, 0-1)
    "if_tcp_reset_count",        # 26 numeric
    "if_session_complete",       # 27 binary (1=COMPLETE, 0=PARTIAL/UNKNOWN)
]

# E. Deterministic context (counts only, not RF output)
CONTEXT_FEATURES: List[str] = [
    "if_finding_count",          # 28 numeric
    "if_high_sev_count",         # 29 numeric
    "if_medium_sev_count",       # 30 numeric
]

# ── Combined ordered list ──────────────────────────────────────────
ALL_IF_FEATURES: List[str] = (
    PROTOCOL_FEATURES
    + TLS_FEATURES
    + CERT_FEATURES
    + SESSION_FEATURES
    + CONTEXT_FEATURES
)

IF_FEATURE_COUNT: int = len(ALL_IF_FEATURES)

# ── Compile-time sanity checks ────────────────────────────────────
assert IF_FEATURE_COUNT == 30, (
    f"ALL_IF_FEATURES has {IF_FEATURE_COUNT} entries, expected 30"
)
assert len(ALL_IF_FEATURES) == len(set(ALL_IF_FEATURES)), (
    "Duplicate feature names detected in IF schema"
)

# ── TLS version encoding ─────────────────────────────────────────
TLS_VERSION_ENCODING: Dict[str, float] = {
    "SSLv2": 0.0,
    "SSLv3": 1.0,
    "TLS 1.0": 2.0,
    "TLS 1.1": 3.0,
    "TLS 1.2": 4.0,
    "TLS 1.3": 5.0,
}

# ── Cipher strength classification ────────────────────────────────
WEAK_CIPHER_TOKENS: Tuple[str, ...] = (
    "RC4", "3DES", "DES", "NULL", "EXPORT", "MD5",
)

# ── Anomaly statuses ─────────────────────────────────────────────
ANOMALY_STATUS_COMPLETE: str = "COMPLETE"
ANOMALY_STATUS_INSUFFICIENT: str = "INSUFFICIENT_EVIDENCE"
ANOMALY_STATUS_UNAVAILABLE: str = "MODEL_UNAVAILABLE"
ANOMALY_STATUS_ERROR: str = "ANALYSIS_ERROR"

ANOMALY_CLASSIFICATION_ANOMALOUS: str = "ANOMALOUS"
ANOMALY_CLASSIFICATION_BASELINE: str = "WITHIN_BASELINE"

# ── Model artifact filenames ─────────────────────────────────────
IF_MODEL_FILENAME: str = "isolation_forest.joblib"
IF_PREPROCESSOR_FILENAME: str = "if_preprocessor.joblib"
IF_METADATA_FILENAME: str = "if_metadata.json"
IF_BASELINE_STATS_FILENAME: str = "if_baseline_stats.json"

# ── Model version ────────────────────────────────────────────────
IF_MODEL_VERSION: str = "if-v1"
