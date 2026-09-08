"""
Canonical 19-Feature Schema for SecureMailScope ML Risk Scoring
===============================================================

This module is the **single source of truth** for:

- Feature names and their stable ordering
- Feature count constant
- Feature group definitions
- Schema version
- Risk label vocabulary
- UNKNOWN policy constants
- Finding-type → feature mapping
- Weak cipher / weak key policy
- Deprecated TLS version policy

EVERY other module (extractor, encoder, dataset_builder, train,
evaluate, predictor) MUST import feature definitions from here
to guarantee identical ordering across the full lifecycle.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Set, Tuple

# ── Schema version ──────────────────────────────────────────────────
SCHEMA_VERSION: str = "1.0"

# ── Canonical MVP Features (exactly 19, order is stable) ───────────
ALL_FEATURES: List[str] = [
    # Binary — encryption mode (one-hot)
    "encryption_plaintext",     # 1
    "encryption_starttls",      # 2
    "encryption_implicit",      # 3
    # Binary — TLS quality
    "deprecated_tls",           # 4
    "weak_cipher",              # 5
    # Binary — certificate issues
    "expired_cert",             # 6
    "not_yet_valid_cert",       # 7
    "weak_key",                 # 8
    # Binary — session security issues
    "auth_before_tls",          # 9
    "tls_upgrade_failed",       # 10
    "pfs_missing",              # 11
    "self_signed",              # 12
    # Binary — protocol one-hot
    "protocol_smtp",            # 13
    "protocol_imap",            # 14
    "protocol_pop3",            # 15
    # Count — finding severity counts
    "critical_count",           # 16
    "high_count",               # 17
    "medium_count",             # 18
    "low_count",                # 19
]

FEATURE_COUNT: int = 19

# Quick-access sets for group membership
BINARY_FEATURES: List[str] = ALL_FEATURES[:15]
COUNT_FEATURES: List[str] = ALL_FEATURES[15:]

ENCRYPTION_FEATURES: List[str] = ALL_FEATURES[0:3]
TLS_QUALITY_FEATURES: List[str] = ALL_FEATURES[3:5]
CERT_FEATURES: List[str] = ALL_FEATURES[5:8]
SESSION_SECURITY_FEATURES: List[str] = ALL_FEATURES[8:12]
PROTOCOL_FEATURES: List[str] = ALL_FEATURES[12:15]
SEVERITY_COUNT_FEATURES: List[str] = ALL_FEATURES[15:19]

# ── Compile-time sanity check ──────────────────────────────────────
assert len(ALL_FEATURES) == FEATURE_COUNT, (
    f"ALL_FEATURES has {len(ALL_FEATURES)} entries, expected {FEATURE_COUNT}"
)
assert len(ALL_FEATURES) == len(set(ALL_FEATURES)), "Duplicate feature names detected"

# ── Risk labels ────────────────────────────────────────────────────
RISK_LABELS: List[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_LABEL_SET: FrozenSet[str] = frozenset(RISK_LABELS)

# ── Valid protocol values ──────────────────────────────────────────
VALID_PROTOCOLS: FrozenSet[str] = frozenset({"SMTP", "IMAP", "POP3", "UNKNOWN"})

# ── Valid encryption modes ─────────────────────────────────────────
VALID_ENCRYPTION_MODES: FrozenSet[str] = frozenset({
    "PLAINTEXT", "STARTTLS", "STLS", "IMPLICIT_TLS", "UNKNOWN",
})

# ── Tri-state vocabulary (YES / NO / UNKNOWN) ─────────────────────
VALID_TRI_STATE: FrozenSet[str] = frozenset({"YES", "NO", "UNKNOWN"})

# ── Finding severity vocabulary ────────────────────────────────────
VALID_SEVERITIES: FrozenSet[str] = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
})

# ── Prediction quality levels ─────────────────────────────────────
QUALITY_SUFFICIENT: str = "SUFFICIENT_EVIDENCE"
QUALITY_LOW: str = "LOW_EVIDENCE"

# Configurable threshold: fraction of binary features that may be NaN
# before prediction quality is downgraded.
LOW_EVIDENCE_THRESHOLD: float = 0.50

# ── Finding type → feature mapping (centralised) ──────────────────
FINDING_TYPE_TO_FEATURE: Dict[str, str] = {
    "PLAINTEXT":          "encryption_plaintext",
    "AUTH_BEFORE_TLS":    "auth_before_tls",
    "FAILED_STARTTLS":    "tls_upgrade_failed",
    "FAILED_STLS":        "tls_upgrade_failed",
    "PFS_MISSING":        "pfs_missing",
    "SELF_SIGNED_CERT":   "self_signed",
    "DEPRECATED_TLS":     "deprecated_tls",
    "WEAK_CIPHER":        "weak_cipher",
    "EXPIRED_CERT":       "expired_cert",
    "NOT_YET_VALID_CERT": "not_yet_valid_cert",
    "WEAK_KEY":           "weak_key",
}

# ── Deprecated TLS versions ───────────────────────────────────────
DEPRECATED_TLS_VERSIONS: FrozenSet[str] = frozenset({
    "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1",
})

MODERN_TLS_VERSIONS: FrozenSet[str] = frozenset({
    "TLS 1.2", "TLS 1.3",
})

# ── Weak cipher patterns (case-insensitive substring matching) ────
# The policy: if *any* of these tokens appear in the cipher suite
# name, the cipher is classified as weak.  Unknown cipher suites
# (empty / None) produce NaN – they are NOT silently classified as
# strong.
WEAK_CIPHER_PATTERNS: Tuple[str, ...] = (
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5",
)

# ── Weak key policy ───────────────────────────────────────────────
# RSA keys < this size are considered weak.
RSA_MIN_KEY_SIZE: int = 2048

# For non-RSA key types we conservatively return NaN in the MVP
# unless the key size is documented here.
#   key_type -> minimum acceptable key size
# (Expand this dict as the team adds more key-type policies.)
KEY_SIZE_POLICY: Dict[str, int] = {
    "RSA": RSA_MIN_KEY_SIZE,
}
