"""
SecureMailScope Recommendation Models

Lightweight data models used by the recommendation and
risk intelligence pipeline.

These models do not contain business logic.
"""


from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Recommendation:
    """
    Represents a single security recommendation.
    """

    recommendation_id: str
    priority: str
    title: str
    description: str

    finding_types: List[str] = field(default_factory=list)
    affected_sessions: List[str] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self):
        """
        Convert the recommendation to a JSON-compatible dictionary.
        """
        return {
            "recommendation_id": self.recommendation_id,
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "finding_types": self.finding_types,
            "affected_sessions": self.affected_sessions,
            "finding_count": self.finding_count,
        }


@dataclass
class RiskResult:
    """
    Represents the result of combining ML risk with
    deterministic security findings.
    """

    ml_risk_level: str
    final_risk_level: str
    risk_adjusted: bool
    adjustment_reason: Optional[str] = None

    def to_dict(self):
        """
        Convert the risk result to a JSON-compatible dictionary.
        """
        return {
            "ml_risk_level": self.ml_risk_level,
            "final_risk_level": self.final_risk_level,
            "risk_adjusted": self.risk_adjusted,
            "adjustment_reason": self.adjustment_reason,
        }


@dataclass
class RiskSummary:
    """
    Counts findings by severity.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def to_dict(self):
        """
        Convert the risk summary to a JSON-compatible dictionary.
        """
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }