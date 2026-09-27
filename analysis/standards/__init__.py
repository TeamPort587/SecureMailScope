"""Standards Context and Configuration Comparison Module for SecureMailScope.

This module provides a separate standards-aware assessment layer that compares
observed session security configurations against authoritative guidance
(RFC 9325, RFC 8996, RFC 8314, NIST SP 800-52 Rev. 2, NIST SP 800-57).

This layer is strictly decoupled from deterministic rule evaluation,
Risk Guard, and ML risk scoring.
"""

from analysis.standards.models import (
    StandardsStatus,
    VisualizationType,
    StandardsSource,
    StandardsOption,
    ComparisonResult,
    StandardsProfile,
)
from analysis.standards.engine import evaluate_session_standards

__all__ = [
    "StandardsStatus",
    "VisualizationType",
    "StandardsSource",
    "StandardsOption",
    "ComparisonResult",
    "StandardsProfile",
    "evaluate_session_standards",
]
