"""
Canonical Risk Aggregator
=========================

The single source of truth for deriving session-level risk labels from observable
security feature states, rule engine finding severity counts, and compounding
vulnerability combinations.

Principles:
- critical_count >= 1 ALWAYS produces CRITICAL.
- CRITICAL can also occur when critical_count == 0 due to severe exposure
  (e.g., cleartext auth_before_tls == 1) or compounding high-risk states.
- HIGH results from major weaknesses or compounding moderate weaknesses (critical_count == 0).
- MEDIUM results from isolated moderate weaknesses (critical_count == 0, no severe exposure).
- LOW requires clean modern encryption with zero critical/high findings (optional low findings allowed).
- All decisions are based strictly on observable feature inputs without hidden variables.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple


def _is_one(val: Any) -> bool:
    if val is None:
        return False
    try:
        return float(val) == 1.0
    except (ValueError, TypeError):
        return False


def _is_nan(val: Any) -> bool:
    if val is None:
        return True
    try:
        return math.isnan(float(val))
    except (ValueError, TypeError):
        return False


def calculate_session_risk(
    features: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """Determine the canonical risk label and reason for a session.

    Parameters
    ----------
    features:
        Mapping containing the 19 canonical features (or subset of relevant ones).

    Returns
    -------
    Tuple[str, List[str]]
        ``(risk_label, reasons)``
        where risk_label is one of 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'.
    """
    reasons: List[str] = []

    crit_cnt = float(features.get("critical_count", 0) or 0)
    high_cnt = float(features.get("high_count", 0) or 0)
    med_cnt = float(features.get("medium_count", 0) or 0)
    low_cnt = float(features.get("low_count", 0) or 0)

    enc_plain = features.get("encryption_plaintext")
    enc_starttls = features.get("encryption_starttls")
    enc_implicit = features.get("encryption_implicit")

    dep_tls = features.get("deprecated_tls")
    weak_ciph = features.get("weak_cipher")
    pfs_miss = features.get("pfs_missing")

    exp_cert = features.get("expired_cert")
    nyv_cert = features.get("not_yet_valid_cert")
    weak_k = features.get("weak_key")
    self_sign = features.get("self_signed")

    auth_early = features.get("auth_before_tls")
    tls_fail = features.get("tls_upgrade_failed")

    # ─────────────────────────────────────────────────────────────────
    # 1. CRITICAL TIER EVALUATION
    # ─────────────────────────────────────────────────────────────────

    # Rule 1.1: Rule engine emitted CRITICAL findings
    if crit_cnt >= 1:
        reasons.append(f"Active critical finding count ({int(crit_cnt)})")
        return "CRITICAL", reasons

    # Rule 1.2: Cleartext authentication transmitted before encryption
    if _is_one(auth_early):
        reasons.append("Cleartext authentication transmitted prior to TLS negotiation")
        return "CRITICAL", reasons

    # Rule 1.3: Plaintext email session
    if _is_one(enc_plain):
        reasons.append("Unencrypted plaintext email communication")
        return "CRITICAL", reasons

    # Rule 1.4: Compounding high-severity vulnerabilities without critical findings
    # Multiple major weaknesses compounding into severe exposure
    major_weakness_count = sum(
        1 for w in (dep_tls, weak_ciph, exp_cert, weak_k, tls_fail, nyv_cert) if _is_one(w)
    )

    if (
        (_is_one(tls_fail) and (_is_one(weak_ciph) or _is_one(dep_tls)))
        or (_is_one(dep_tls) and _is_one(weak_ciph) and major_weakness_count >= 3)
    ):
        reasons.append(f"Compounding high-severity failure states ({major_weakness_count} major weaknesses)")
        return "CRITICAL", reasons

    # ─────────────────────────────────────────────────────────────────
    # 2. HIGH TIER EVALUATION
    # ─────────────────────────────────────────────────────────────────

    # Rule 2.1: Explicit high-severity findings
    if high_cnt >= 1:
        reasons.append(f"Active high severity findings ({int(high_cnt)})")
        return "HIGH", reasons

    # Rule 2.2: Individual major cryptographic or upgrade failure weaknesses
    if _is_one(dep_tls):
        reasons.append("Deprecated TLS version in use (SSLv3/TLS 1.0/TLS 1.1)")
        return "HIGH", reasons
    if _is_one(weak_ciph):
        reasons.append("Weak or obsolete cipher suite negotiated")
        return "HIGH", reasons
    if _is_one(exp_cert):
        reasons.append("Expired X.509 certificate presented")
        return "HIGH", reasons
    if _is_one(nyv_cert):
        reasons.append("Not-yet-valid X.509 certificate presented")
        return "HIGH", reasons
    if _is_one(weak_k):
        reasons.append("Insecure RSA key length (<2048 bits)")
        return "HIGH", reasons
    if _is_one(tls_fail):
        reasons.append("STARTTLS upgrade command rejected or failed")
        return "HIGH", reasons

    # Rule 2.3: Compounding moderate weaknesses (e.g. self-signed + missing PFS)
    moderate_weakness_count = sum(1 for m in (pfs_miss, self_sign) if _is_one(m))
    if moderate_weakness_count >= 2 and med_cnt >= 2:
        reasons.append("Compounding moderate weaknesses (self-signed and missing PFS)")
        return "HIGH", reasons

    # ─────────────────────────────────────────────────────────────────
    # 3. MEDIUM TIER EVALUATION
    # ─────────────────────────────────────────────────────────────────

    # Rule 3.1: Explicit medium-severity findings
    if med_cnt >= 1:
        reasons.append(f"Active medium severity findings ({int(med_cnt)})")
        return "MEDIUM", reasons

    # Rule 3.2: Moderate cryptographic or certificate weaknesses
    if _is_one(self_sign):
        reasons.append("Self-signed or untrusted certificate")
        return "MEDIUM", reasons
    if _is_one(pfs_miss):
        reasons.append("Cipher suite lacks Perfect Forward Secrecy (PFS)")
        return "MEDIUM", reasons

    # Rule 3.3: Limited certificate visibility with non-clean posture
    if _is_nan(exp_cert) and _is_nan(self_sign) and low_cnt >= 2:
        reasons.append("Unobservable certificate combined with multiple minor anomalies")
        return "MEDIUM", reasons

    # ─────────────────────────────────────────────────────────────────
    # 4. LOW TIER EVALUATION
    # ─────────────────────────────────────────────────────────────────
    # Benign session: modern encryption, no major or moderate flaws
    reasons.append("Modern encrypted session with acceptable security posture")
    return "LOW", reasons
