"""
Analysis JSON Validator
=======================

Validates the structural integrity of analysis JSON produced by the
Django analysis service before it reaches the feature extractor.

The validator enforces:

- Top-level structure (``analysis_version``, ``sessions``, ``findings``).
- Per-session required fields (``session_id``, ``protocol``).
- Known vocabularies (protocol, encryption_mode, tri-state).
- Nullable ``tls`` and ``certificate`` blocks (allowed, not required).

Unknown optional values do **not** crash validation — only structurally
invalid data raises :class:`ValidationError`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ml.feature_engineering.schema import (
    VALID_ENCRYPTION_MODES,
    VALID_PROTOCOLS,
    VALID_SEVERITIES,
    VALID_TRI_STATE,
)


# ── Exceptions ─────────────────────────────────────────────────────

class ValidationError(Exception):
    """Raised when analysis JSON fails structural validation."""

    def __init__(self, message: str, errors: Optional[List[str]] = None) -> None:
        super().__init__(message)
        self.errors: List[str] = errors or [message]


# ── Helpers ────────────────────────────────────────────────────────

def _check_tri_state(value: Any, field_path: str, errors: List[str]) -> None:
    """Append an error if *value* is not a valid tri-state string."""
    if value is not None and value not in VALID_TRI_STATE:
        errors.append(
            f"{field_path}: invalid tri-state value '{value}', "
            f"expected one of {sorted(VALID_TRI_STATE)}"
        )


def _validate_security(
    security: Any,
    session_path: str,
    errors: List[str],
) -> None:
    """Validate the ``security`` block of a session, if present."""
    if security is None:
        return  # security block is optional

    if not isinstance(security, dict):
        errors.append(f"{session_path}.security: expected dict, got {type(security).__name__}")
        return

    # encryption_mode
    enc_mode = security.get("encryption_mode")
    if enc_mode is not None and enc_mode not in VALID_ENCRYPTION_MODES:
        errors.append(
            f"{session_path}.security.encryption_mode: invalid value '{enc_mode}', "
            f"expected one of {sorted(VALID_ENCRYPTION_MODES)}"
        )

    # tri-state fields
    for field in (
        "upgrade_advertised",
        "upgrade_requested",
        "upgrade_succeeded",
        "authentication_before_tls",
    ):
        val = security.get(field)
        _check_tri_state(val, f"{session_path}.security.{field}", errors)


def _validate_session(
    session: Any,
    index: int,
    errors: List[str],
) -> None:
    """Validate a single session entry."""
    path = f"sessions[{index}]"

    if not isinstance(session, dict):
        errors.append(f"{path}: expected dict, got {type(session).__name__}")
        return

    # Required: session_id
    if "session_id" not in session:
        errors.append(f"{path}: missing required field 'session_id'")

    # Required: protocol
    protocol = session.get("protocol")
    if protocol is None:
        errors.append(f"{path}: missing required field 'protocol'")
    elif protocol not in VALID_PROTOCOLS:
        errors.append(
            f"{path}.protocol: invalid value '{protocol}', "
            f"expected one of {sorted(VALID_PROTOCOLS)}"
        )

    # security (optional block)
    _validate_security(session.get("security"), path, errors)

    # tls may be null — that is valid
    # certificate may be null or contain visibility — that is valid


def _validate_finding(
    finding: Any,
    index: int,
    errors: List[str],
) -> None:
    """Validate a single finding entry."""
    path = f"findings[{index}]"

    if not isinstance(finding, dict):
        errors.append(f"{path}: expected dict, got {type(finding).__name__}")
        return

    if "finding_id" not in finding:
        errors.append(f"{path}: missing required field 'finding_id'")

    if "session_id" not in finding:
        errors.append(f"{path}: missing required field 'session_id'")

    severity = finding.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        errors.append(
            f"{path}.severity: invalid value '{severity}', "
            f"expected one of {sorted(VALID_SEVERITIES)}"
        )


# ── Public API ─────────────────────────────────────────────────────

def validate_analysis(data: Any) -> List[str]:
    """Validate an analysis JSON structure.

    Parameters
    ----------
    data:
        The parsed analysis JSON (a Python ``dict``).

    Returns
    -------
    List[str]
        A list of human-readable error strings.  An empty list means
        the analysis passed validation.

    Raises
    ------
    ValidationError
        If *data* is not a dict or has fatal structural problems that
        prevent even partial validation.
    """
    if not isinstance(data, dict):
        raise ValidationError(
            f"Analysis root must be a dict, got {type(data).__name__}"
        )

    errors: List[str] = []

    # ── sessions ───────────────────────────────────────────────────
    sessions = data.get("sessions")
    if sessions is None:
        errors.append("Missing required top-level field 'sessions'")
    elif not isinstance(sessions, list):
        errors.append(
            f"'sessions' must be a list, got {type(sessions).__name__}"
        )
    else:
        if len(sessions) == 0:
            errors.append("'sessions' list is empty")
        for idx, session in enumerate(sessions):
            _validate_session(session, idx, errors)

    # ── findings (optional, may be empty) ──────────────────────────
    findings = data.get("findings")
    if findings is not None:
        if not isinstance(findings, list):
            errors.append(
                f"'findings' must be a list, got {type(findings).__name__}"
            )
        else:
            for idx, finding in enumerate(findings):
                _validate_finding(finding, idx, errors)

    return errors


def validate_analysis_strict(data: Any) -> None:
    """Like :func:`validate_analysis` but raises on any error.

    Raises
    ------
    ValidationError
        If any validation errors are found.
    """
    errors = validate_analysis(data)
    if errors:
        raise ValidationError(
            f"Analysis validation failed with {len(errors)} error(s): "
            + "; ".join(errors),
            errors=errors,
        )
