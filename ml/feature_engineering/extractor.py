"""
Session Feature Extractor
=========================

Generates one 19-feature vector per session by combining session data
with matching findings.

Core rules:

* **UNKNOWN → NaN** (never silently 0).
* ``tls = null`` → TLS-dependent features are NaN.
* ``certificate = null`` or ``visibility = NOT_OBSERVABLE`` →
  certificate-dependent features are NaN.
* Severity counts are **session-specific** (only findings whose
  ``session_id`` matches the current session are counted).
* Explicit finding evidence (e.g. ``AUTH_BEFORE_TLS``) **overrides**
  field-level derivation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    DEPRECATED_TLS_VERSIONS,
    EXTENDED_FEATURE_COUNT,
    EXTENDED_FEATURES,
    FEATURE_COUNT,
    FINDING_TYPE_TO_FEATURE,
    KEY_SIZE_POLICY,
    MODERN_TLS_VERSIONS,
    OBSERVABILITY_FEATURES,
    WEAK_CIPHER_PATTERNS,
)


# ── Type alias ─────────────────────────────────────────────────────
FeatureVector = Dict[str, float]

NaN = float("nan")


# ── Helpers ────────────────────────────────────────────────────────

def _get_session_findings(
    session_id: str,
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return findings that belong to *session_id*."""
    return [f for f in findings if f.get("session_id") == session_id]


def _has_finding_type(
    session_findings: List[Dict[str, Any]],
    *finding_types: str,
) -> bool:
    """Return ``True`` if any finding matches one of *finding_types*."""
    return any(
        f.get("finding_type") in finding_types
        for f in session_findings
    )


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 datetime string to a timezone-aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _is_weak_cipher(cipher_suite: Optional[str]) -> Optional[bool]:
    """Classify a cipher suite.

    Returns:
        ``True``  — cipher is weak.
        ``False`` — cipher appears strong.
        ``None``  — cipher is unknown / empty (→ NaN).
    """
    if not cipher_suite:
        return None
    upper = cipher_suite.upper()
    for pattern in WEAK_CIPHER_PATTERNS:
        if pattern in upper:
            return True
    return False


# ── Main extraction ────────────────────────────────────────────────

def extract_session_features(
    session: Dict[str, Any],
    findings: List[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> FeatureVector:
    """Extract the canonical 19-feature vector for a single session.

    Parameters
    ----------
    session:
        A single session dict from the analysis JSON.
    findings:
        The **full** list of findings from the analysis JSON.
        The function internally filters to those matching
        ``session["session_id"]``.
    now:
        Override for the current UTC time (for deterministic tests).
        Defaults to ``datetime.now(timezone.utc)``.

    Returns
    -------
    FeatureVector
        A dict mapping each of the 19 canonical feature names to
        ``0``, ``1``, a non-negative count, or ``float('nan')``.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    session_id: str = session.get("session_id", "")
    sf = _get_session_findings(session_id, findings)

    security: Optional[Dict[str, Any]] = session.get("security")
    tls: Optional[Dict[str, Any]] = session.get("tls")
    cert: Optional[Dict[str, Any]] = session.get("certificate")

    # Certificate is unavailable if null, missing, or NOT_OBSERVABLE
    cert_available = (
        cert is not None
        and isinstance(cert, dict)
        and cert.get("visibility") != "NOT_OBSERVABLE"
    )

    vec: FeatureVector = {}

    # ── 1-3. Encryption mode (one-hot) ─────────────────────────────
    enc_mode = (security or {}).get("encryption_mode")
    if enc_mode == "PLAINTEXT":
        vec["encryption_plaintext"] = 1
        vec["encryption_starttls"] = 0
        vec["encryption_implicit"] = 0
    elif enc_mode in ("STARTTLS", "STLS"):
        vec["encryption_plaintext"] = 0
        vec["encryption_starttls"] = 1
        vec["encryption_implicit"] = 0
    elif enc_mode == "IMPLICIT_TLS":
        vec["encryption_plaintext"] = 0
        vec["encryption_starttls"] = 0
        vec["encryption_implicit"] = 1
    else:
        # UNKNOWN or missing → NaN
        vec["encryption_plaintext"] = NaN
        vec["encryption_starttls"] = NaN
        vec["encryption_implicit"] = NaN

    # ── 4. Deprecated TLS ──────────────────────────────────────────
    if _has_finding_type(sf, "DEPRECATED_TLS"):
        vec["deprecated_tls"] = 1
    elif tls is None:
        vec["deprecated_tls"] = NaN
    else:
        version = (tls or {}).get("version")
        if version in DEPRECATED_TLS_VERSIONS:
            vec["deprecated_tls"] = 1
        elif version in MODERN_TLS_VERSIONS:
            vec["deprecated_tls"] = 0
        else:
            vec["deprecated_tls"] = NaN

    # ── 5. Weak cipher ─────────────────────────────────────────────
    if _has_finding_type(sf, "WEAK_CIPHER"):
        vec["weak_cipher"] = 1
    elif tls is None:
        vec["weak_cipher"] = NaN
    else:
        cipher = (tls or {}).get("cipher_suite")
        result = _is_weak_cipher(cipher)
        if result is None:
            vec["weak_cipher"] = NaN
        else:
            vec["weak_cipher"] = 1 if result else 0

    # ── 6. Expired certificate ─────────────────────────────────────
    if _has_finding_type(sf, "EXPIRED_CERT"):
        vec["expired_cert"] = 1
    elif not cert_available:
        vec["expired_cert"] = NaN
    else:
        valid_until = _parse_iso_datetime(cert.get("valid_until"))  # type: ignore[union-attr]
        if valid_until is None:
            vec["expired_cert"] = NaN
        elif valid_until < now:
            vec["expired_cert"] = 1
        else:
            vec["expired_cert"] = 0

    # ── 7. Not-yet-valid certificate ───────────────────────────────
    if _has_finding_type(sf, "NOT_YET_VALID_CERT"):
        vec["not_yet_valid_cert"] = 1
    elif not cert_available:
        vec["not_yet_valid_cert"] = NaN
    else:
        valid_from = _parse_iso_datetime(cert.get("valid_from"))  # type: ignore[union-attr]
        if valid_from is None:
            vec["not_yet_valid_cert"] = NaN
        elif valid_from > now:
            vec["not_yet_valid_cert"] = 1
        else:
            vec["not_yet_valid_cert"] = 0

    # ── 8. Weak key ────────────────────────────────────────────────
    if _has_finding_type(sf, "WEAK_KEY"):
        vec["weak_key"] = 1
    elif not cert_available:
        vec["weak_key"] = NaN
    else:
        key_type = cert.get("key_type")  # type: ignore[union-attr]
        key_size = cert.get("key_size")  # type: ignore[union-attr]
        if key_type is None or key_size is None:
            vec["weak_key"] = NaN
        elif key_type in KEY_SIZE_POLICY:
            vec["weak_key"] = 1 if key_size < KEY_SIZE_POLICY[key_type] else 0
        else:
            # Non-RSA key types: conservative NaN for MVP
            vec["weak_key"] = NaN

    # ── 9. Auth before TLS ─────────────────────────────────────────
    if _has_finding_type(sf, "AUTH_BEFORE_TLS"):
        vec["auth_before_tls"] = 1
    else:
        auth_val = (security or {}).get("authentication_before_tls")
        if auth_val == "YES":
            vec["auth_before_tls"] = 1
        elif auth_val == "NO":
            vec["auth_before_tls"] = 0
        else:
            vec["auth_before_tls"] = NaN

    # ── 10. TLS upgrade failed ─────────────────────────────────────
    if _has_finding_type(sf, "FAILED_STARTTLS", "FAILED_STLS"):
        vec["tls_upgrade_failed"] = 1
    else:
        adv = (security or {}).get("upgrade_advertised")
        succ = (security or {}).get("upgrade_succeeded")
        if adv == "YES" and succ == "NO":
            vec["tls_upgrade_failed"] = 1
        elif succ == "YES":
            vec["tls_upgrade_failed"] = 0
        else:
            vec["tls_upgrade_failed"] = NaN

    # ── 11. PFS missing ───────────────────────────────────────────
    if _has_finding_type(sf, "PFS_MISSING"):
        vec["pfs_missing"] = 1
    elif tls is None:
        vec["pfs_missing"] = NaN
    else:
        pfs = (tls or {}).get("pfs")
        if pfs == "YES":
            vec["pfs_missing"] = 0
        elif pfs == "NO":
            vec["pfs_missing"] = 1
        else:
            vec["pfs_missing"] = NaN

    # ── 12. Self-signed ────────────────────────────────────────────
    if _has_finding_type(sf, "SELF_SIGNED_CERT"):
        vec["self_signed"] = 1
    elif not cert_available:
        vec["self_signed"] = NaN
    else:
        ss = cert.get("self_signed")  # type: ignore[union-attr]
        if ss is True:
            vec["self_signed"] = 1
        elif ss is False:
            vec["self_signed"] = 0
        else:
            vec["self_signed"] = NaN

    # ── 13-15. Protocol (one-hot) ──────────────────────────────────
    protocol = session.get("protocol")
    if protocol == "SMTP":
        vec["protocol_smtp"] = 1
        vec["protocol_imap"] = 0
        vec["protocol_pop3"] = 0
    elif protocol == "IMAP":
        vec["protocol_smtp"] = 0
        vec["protocol_imap"] = 1
        vec["protocol_pop3"] = 0
    elif protocol == "POP3":
        vec["protocol_smtp"] = 0
        vec["protocol_imap"] = 0
        vec["protocol_pop3"] = 1
    else:
        vec["protocol_smtp"] = NaN
        vec["protocol_imap"] = NaN
        vec["protocol_pop3"] = NaN

    # ── 16-19. Severity counts (session-specific) ──────────────────
    vec["critical_count"] = sum(1 for f in sf if f.get("severity") == "CRITICAL")
    vec["high_count"] = sum(1 for f in sf if f.get("severity") == "HIGH")
    vec["medium_count"] = sum(1 for f in sf if f.get("severity") == "MEDIUM")
    vec["low_count"] = sum(1 for f in sf if f.get("severity") == "LOW")

    # ── Assertion: exactly 19 features ─────────────────────────────
    assert len(vec) == FEATURE_COUNT, (
        f"Feature vector has {len(vec)} features, expected {FEATURE_COUNT}"
    )

    return vec


def extract_all_sessions(
    analysis: Dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Extract feature vectors for every session in an analysis.

    Returns
    -------
    List[Dict[str, Any]]
        A list of dicts, each containing ``session_id`` and the 19
        canonical features.
    """
    sessions = analysis.get("sessions", [])
    findings = analysis.get("findings", [])
    results: List[Dict[str, Any]] = []

    for session in sessions:
        vec = extract_session_features(session, findings, now=now)
        results.append({
            "session_id": session.get("session_id", "unknown"),
            **vec,
        })

    return results


def feature_vector_to_ordered_list(vec: FeatureVector) -> List[float]:
    """Convert a feature vector dict to a list in canonical order.

    Guarantees identical ordering during training and inference.
    """
    return [vec[name] for name in ALL_FEATURES]


# ── Observability feature extraction (Phase 17) ─────────────────────

def extract_observability_features(
    session: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Extract observability indicators representing whether evidence was observable.

    1.0 = observable / observed in capture
    0.0 = unobservable / not observed in capture

    Features:
    - tls_handshake_observed
    - certificate_observed
    - starttls_command_observed
    - authentication_observed
    - session_truncated
    - asymmetric_capture
    """
    session_id: str = session.get("session_id", "")
    sf = _get_session_findings(session_id, findings)

    security: Optional[Dict[str, Any]] = session.get("security")
    tls: Optional[Dict[str, Any]] = session.get("tls")
    cert: Optional[Dict[str, Any]] = session.get("certificate")

    # 1. TLS handshake observed
    # Observed if tls dictionary is present with version/cipher, or explicit TLS findings
    tls_handshake_obs = 0.0
    if tls is not None and isinstance(tls, dict):
        version = tls.get("version")
        cipher = tls.get("cipher_suite")
        if (version and version != "UNKNOWN") or (cipher and cipher != "UNKNOWN"):
            tls_handshake_obs = 1.0
    if _has_finding_type(sf, "DEPRECATED_TLS", "WEAK_CIPHER", "PFS_MISSING"):
        tls_handshake_obs = 1.0

    # 2. Certificate observed
    cert_obs = 0.0
    if (
        cert is not None
        and isinstance(cert, dict)
        and cert.get("visibility") != "NOT_OBSERVABLE"
    ):
        if any(cert.get(k) is not None for k in ("subject", "valid_from", "valid_until", "key_size", "self_signed")):
            cert_obs = 1.0
    if _has_finding_type(sf, "EXPIRED_CERT", "NOT_YET_VALID_CERT", "WEAK_KEY", "SELF_SIGNED_CERT"):
        cert_obs = 1.0

    # 3. STARTTLS command observed
    starttls_cmd_obs = 0.0
    enc_mode = (security or {}).get("encryption_mode")
    if (security or {}).get("upgrade_advertised") in ("YES", "NO") or (security or {}).get("upgrade_requested") in ("YES", "NO"):
        starttls_cmd_obs = 1.0
    elif _has_finding_type(sf, "FAILED_STARTTLS", "FAILED_STLS"):
        starttls_cmd_obs = 1.0
    elif enc_mode in ("STARTTLS", "STLS"):
        starttls_cmd_obs = 1.0

    # 4. Authentication observed
    auth_obs = 0.0
    if (security or {}).get("authentication_before_tls") in ("YES", "NO"):
        auth_obs = 1.0
    elif _has_finding_type(sf, "AUTH_BEFORE_TLS"):
        auth_obs = 1.0
    elif session.get("authentication") is not None:
        auth_obs = 1.0

    # 5. Session truncated
    flags = session.get("flags") or []
    if isinstance(flags, str):
        flags = [flags]
    sess_trunc = 1.0 if (
        session.get("truncated") is True
        or session.get("session_truncated") is True
        or "TRUNCATED" in flags
        or session.get("capture_scenario") in ("TRUNCATED_SESSION", "MISSING_TLS_FINISHED")
    ) else 0.0

    # 6. Asymmetric capture
    asym = 1.0 if (
        session.get("asymmetric") is True
        or session.get("asymmetric_capture") is True
        or session.get("traffic_direction") in ("INBOUND_ONLY", "OUTBOUND_ONLY", "ASYMMETRIC")
        or session.get("capture_scenario") == "ASYMMETRIC_CAPTURE"
    ) else 0.0

    return {
        "tls_handshake_observed": tls_handshake_obs,
        "certificate_observed": cert_obs,
        "starttls_command_observed": starttls_cmd_obs,
        "authentication_observed": auth_obs,
        "session_truncated": sess_trunc,
        "asymmetric_capture": asym,
    }


def extract_extended_session_features(
    session: Dict[str, Any],
    findings: List[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> Dict[str, float]:
    """Extract extended 25-feature vector combining 19 canonical + 6 observability features."""
    base_vec = extract_session_features(session, findings, now=now)
    obs_vec = extract_observability_features(session, findings)
    combined = {**base_vec, **obs_vec}
    assert len(combined) == EXTENDED_FEATURE_COUNT, (
        f"Extended vector has {len(combined)} features, expected {EXTENDED_FEATURE_COUNT}"
    )
    return combined


def extended_feature_vector_to_ordered_list(vec: Dict[str, float]) -> List[float]:
    """Convert an extended feature vector dict to a list in canonical extended order."""
    return [vec[name] for name in EXTENDED_FEATURES]

