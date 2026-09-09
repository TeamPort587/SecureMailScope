"""
Dataset Constraint Validator
============================

Enforces logical consistency, structural constraints, and domain rules
on email security feature vectors.

Validates that synthetic (and processed) session feature rows do not
contain impossible, contradictory, or invalid security states.

CLI Usage::

    python -m ml.training.dataset_validator \\
        --input data/processed/synthetic_dataset.csv
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from ml.feature_engineering.schema import (
    ALL_FEATURES,
    RISK_LABEL_SET,
)


def _is_nan(val: Any) -> bool:
    """Check if value is NaN or None."""
    if val is None:
        return True
    try:
        return math.isnan(float(val))
    except (ValueError, TypeError):
        return False


def _is_one(val: Any) -> bool:
    """Check if value is 1 (or 1.0)."""
    if _is_nan(val):
        return False
    try:
        return float(val) == 1.0
    except (ValueError, TypeError):
        return False


def _is_zero(val: Any) -> bool:
    """Check if value is 0 (or 0.0)."""
    if _is_nan(val):
        return False
    try:
        return float(val) == 0.0
    except (ValueError, TypeError):
        return False


def validate_feature_row(
    row: Union[Dict[str, Any], pd.Series],
) -> Tuple[bool, List[str]]:
    """Validate a single feature row against all logical constraints.

    Parameters
    ----------
    row:
        Mapping or Series containing the 19 canonical features and
        optionally metadata columns and ``risk_label``.

    Returns
    -------
    Tuple[bool, List[str]]
        ``(is_valid, error_list)``. ``is_valid`` is True if errors is empty.
    """
    errors: List[str] = []

    # 1. Feature presence check
    for feat in ALL_FEATURES:
        if feat not in row:
            errors.append(f"Missing canonical feature: '{feat}'")

    if errors:
        return False, errors

    # Extract values
    enc_plain = row.get("encryption_plaintext")
    enc_starttls = row.get("encryption_starttls")
    enc_implicit = row.get("encryption_implicit")

    proto_smtp = row.get("protocol_smtp")
    proto_imap = row.get("protocol_imap")
    proto_pop3 = row.get("protocol_pop3")

    dep_tls = row.get("deprecated_tls")
    weak_ciph = row.get("weak_cipher")
    pfs_miss = row.get("pfs_missing")

    exp_cert = row.get("expired_cert")
    nyv_cert = row.get("not_yet_valid_cert")
    weak_k = row.get("weak_key")
    self_sign = row.get("self_signed")

    auth_early = row.get("auth_before_tls")
    tls_fail = row.get("tls_upgrade_failed")

    crit_cnt = row.get("critical_count", 0)
    high_cnt = row.get("high_count", 0)
    med_cnt = row.get("medium_count", 0)
    low_cnt = row.get("low_count", 0)

    # 2. Protocol one-hot: exactly one must be 1
    proto_sum = sum(1 for p in (proto_smtp, proto_imap, proto_pop3) if _is_one(p))
    if proto_sum != 1:
        errors.append(
            f"Protocol one-hot violation: exactly one protocol must be 1, found {proto_sum}"
        )

    # 3. Encryption mode one-hot: exactly one must be 1 for valid synthetic sessions
    enc_sum = sum(1 for e in (enc_plain, enc_starttls, enc_implicit) if _is_one(e))
    if enc_sum != 1:
        errors.append(
            f"Encryption one-hot violation: exactly one mode must be 1, found {enc_sum}"
        )

    # 4. Plaintext rules
    if _is_one(enc_plain):
        # TLS properties must not exist (must be NaN)
        if not _is_nan(dep_tls):
            errors.append("Plaintext session cannot have deprecated_tls defined (must be NaN)")
        if not _is_nan(weak_ciph):
            errors.append("Plaintext session cannot have weak_cipher defined (must be NaN)")
        if not _is_nan(pfs_miss):
            errors.append("Plaintext session cannot have pfs_missing defined (must be NaN)")

        # Cert properties must not exist (must be NaN)
        if not _is_nan(exp_cert):
            errors.append("Plaintext session cannot have expired_cert defined (must be NaN)")
        if not _is_nan(nyv_cert):
            errors.append("Plaintext session cannot have not_yet_valid_cert defined (must be NaN)")
        if not _is_nan(weak_k):
            errors.append("Plaintext session cannot have weak_key defined (must be NaN)")
        if not _is_nan(self_sign):
            errors.append("Plaintext session cannot have self_signed defined (must be NaN)")

        # tls_upgrade_failed cannot be 1
        if _is_one(tls_fail):
            errors.append("Plaintext session cannot have tls_upgrade_failed = 1")

    # 5. STARTTLS rules
    if _is_one(tls_fail):
        if not _is_one(enc_starttls):
            errors.append("tls_upgrade_failed = 1 is only valid when encryption_starttls = 1")
        # If upgrade failed, TLS details and cert details are unavailable
        if _is_one(dep_tls) or _is_one(weak_ciph) or _is_one(pfs_miss):
            errors.append("Failed STARTTLS upgrade cannot have established TLS properties")
        if _is_one(exp_cert) or _is_one(nyv_cert) or _is_one(weak_k) or _is_one(self_sign):
            errors.append("Failed STARTTLS upgrade cannot have established certificate properties")

    # 6. IMPLICIT TLS rules
    if _is_one(enc_implicit):
        if _is_one(tls_fail):
            errors.append("IMPLICIT_TLS cannot have tls_upgrade_failed = 1")
        if _is_one(auth_early):
            errors.append("IMPLICIT_TLS cannot have auth_before_tls = 1 (TLS precedes auth)")

    # 7. TLS vulnerabilities require TLS
    if _is_one(dep_tls) and not (_is_one(enc_starttls) or _is_one(enc_implicit)):
        errors.append("deprecated_tls = 1 requires STARTTLS or IMPLICIT_TLS")
    if _is_one(weak_ciph) and not (_is_one(enc_starttls) or _is_one(enc_implicit)):
        errors.append("weak_cipher = 1 requires STARTTLS or IMPLICIT_TLS")
    if _is_one(pfs_miss) and not (_is_one(enc_starttls) or _is_one(enc_implicit)):
        errors.append("pfs_missing = 1 requires STARTTLS or IMPLICIT_TLS")

    # 8. Certificate vulnerabilities require TLS and observable cert
    if (_is_one(exp_cert) or _is_one(nyv_cert) or _is_one(weak_k) or _is_one(self_sign)):
        if not (_is_one(enc_starttls) or _is_one(enc_implicit)):
            errors.append("Certificate properties require STARTTLS or IMPLICIT_TLS")

    # 9. Certificate validity contradiction
    if _is_one(exp_cert) and _is_one(nyv_cert):
        errors.append("Certificate cannot be both expired_cert = 1 and not_yet_valid_cert = 1")

    # 10. Non-negative finding counts
    for cnt_feat in ("critical_count", "high_count", "medium_count", "low_count"):
        val = row.get(cnt_feat)
        if val is not None and not _is_nan(val):
            try:
                num = float(val)
                if num < 0:
                    errors.append(f"{cnt_feat} must be >= 0, found {num}")
            except (ValueError, TypeError):
                errors.append(f"{cnt_feat} must be a number, found {val}")

    # 11. Risk label constraints (if present)
    if "risk_label" in row and row["risk_label"] is not None and not _is_nan(row["risk_label"]):
        label = str(row["risk_label"]).strip()
        if label not in RISK_LABEL_SET:
            errors.append(f"Invalid risk_label: '{label}'. Must be one of {sorted(RISK_LABEL_SET)}")
        else:
            c_cnt = float(crit_cnt) if not _is_nan(crit_cnt) else 0.0
            h_cnt = float(high_cnt) if not _is_nan(high_cnt) else 0.0

            # Mandatory rule: critical_count >= 1 MUST be CRITICAL
            if c_cnt >= 1 and label != "CRITICAL":
                errors.append(f"Sessions with critical_count >= 1 ({c_cnt}) MUST be labeled CRITICAL, found '{label}'")

            # LOW: no critical findings, no high findings, no known major vulnerabilities
            if label == "LOW":
                if c_cnt > 0:
                    errors.append(f"LOW label cannot have critical_count > 0 (found {c_cnt})")
                if h_cnt > 0:
                    errors.append(f"LOW label cannot have high_count > 0 (found {h_cnt})")
                if _is_one(enc_plain):
                    errors.append("LOW label cannot be PLAINTEXT")
                if _is_one(dep_tls):
                    errors.append("LOW label cannot have deprecated_tls = 1")
                if _is_one(weak_ciph):
                    errors.append("LOW label cannot have weak_cipher = 1")
                if _is_one(exp_cert):
                    errors.append("LOW label cannot have expired_cert = 1")
                if _is_one(nyv_cert):
                    errors.append("LOW label cannot have not_yet_valid_cert = 1")
                if _is_one(weak_k):
                    errors.append("LOW label cannot have weak_key = 1")
                if _is_one(auth_early):
                    errors.append("LOW label cannot have auth_before_tls = 1")
                if _is_one(tls_fail):
                    errors.append("LOW label cannot have tls_upgrade_failed = 1")

            # MEDIUM: no critical conditions (no plaintext, no auth_before_tls, critical_count == 0)
            elif label == "MEDIUM":
                if c_cnt > 0:
                    errors.append(f"MEDIUM label cannot have critical_count > 0 (found {c_cnt})")
                if _is_one(enc_plain):
                    errors.append("MEDIUM label cannot be PLAINTEXT")
                if _is_one(auth_early):
                    errors.append("MEDIUM label cannot have auth_before_tls = 1")

            # HIGH: must have at least one significant security concern and no critical findings
            elif label == "HIGH":
                if c_cnt > 0:
                    errors.append(f"HIGH label cannot have critical_count > 0 (found {c_cnt})")
                has_concern = (
                    _is_one(dep_tls)
                    or _is_one(weak_ciph)
                    or _is_one(exp_cert)
                    or _is_one(nyv_cert)
                    or _is_one(weak_k)
                    or _is_one(tls_fail)
                    or h_cnt >= 1
                    or (_is_one(self_sign) and _is_one(pfs_miss))
                )
                if not has_concern:
                    errors.append("HIGH label must have at least one major weakness or compounding combination")

            # CRITICAL: must have severe condition or compounding major failure
            elif label == "CRITICAL":
                major_count = sum(1 for w in (dep_tls, weak_ciph, exp_cert, weak_k, tls_fail, nyv_cert) if _is_one(w))
                has_severe = (
                    _is_one(enc_plain)
                    or _is_one(auth_early)
                    or c_cnt >= 1
                    or (_is_one(tls_fail) and (_is_one(weak_ciph) or _is_one(dep_tls)))
                    or (_is_one(dep_tls) and _is_one(weak_ciph) and major_count >= 3)
                )
                if not has_severe:
                    errors.append("CRITICAL label must have severe condition (plaintext, auth_before_tls, critical_count >= 1, or compounding major failure)")

    return len(errors) == 0, errors


def validate_dataset(df: pd.DataFrame) -> Tuple[int, int, List[Dict[str, Any]]]:
    """Validate all rows in a DataFrame.

    Returns
    -------
    Tuple[int, int, List[Dict[str, Any]]]
        ``(valid_count, invalid_count, failure_reports)``
    """
    valid_count = 0
    invalid_count = 0
    failures: List[Dict[str, Any]] = []

    for idx, row in df.iterrows():
        is_valid, errors = validate_feature_row(row)
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1
            failures.append({
                "row_index": int(idx),
                "session_id": str(row.get("session_id", f"row-{idx}")),
                "errors": errors,
            })

    return valid_count, invalid_count, failures


def main(argv: List[str] | None = None) -> None:
    """CLI entry point for dataset constraint validation."""
    parser = argparse.ArgumentParser(
        description="Validate feature rows against domain security constraints."
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to CSV dataset to validate.",
    )
    args = parser.parse_args(argv)

    csv_path = Path(args.input)
    if not csv_path.is_file():
        print(f"Error: File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(csv_path)
    print(f"Validating {len(df)} rows from: {csv_path}")

    valid_count, invalid_count, failures = validate_dataset(df)

    print(f"  Valid rows:   {valid_count}")
    print(f"  Invalid rows: {invalid_count}")

    if invalid_count > 0:
        print("\nFirst 5 validation failures:")
        for f in failures[:5]:
            print(f"  Row {f['row_index']} ({f['session_id']}): {f['errors']}")
        sys.exit(1)
    else:
        print("  All rows passed constraint validation successfully.")


if __name__ == "__main__":
    main()
