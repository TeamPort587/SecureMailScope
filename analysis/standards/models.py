"""Data models for Standards Context & Configuration Comparison."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class StandardsStatus(str, Enum):
    """Categorical classification of a configuration under authoritative standards."""
    DEPRECATED = "DEPRECATED"
    NOT_RECOMMENDED = "NOT_RECOMMENDED"
    ACCEPTABLE = "ACCEPTABLE"
    RECOMMENDED = "RECOMMENDED"
    PREFERRED = "PREFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VisualizationType(str, Enum):
    """Visualization layout for comparing observed configuration to standard options."""
    ORDERED_SPECTRUM = "ordered_spectrum"
    CATEGORICAL_SPECTRUM = "categorical_spectrum"
    CAPABILITY_COMPARISON = "capability_comparison"
    STATUS_ASSESSMENT = "status_assessment"


@dataclass
class StandardsSource:
    """Authoritative source reference for standards guidance."""
    name: str  # e.g., "RFC 9325"
    title: str  # e.g., "Recommendations for Secure Use of Transport Layer Security (TLS)"
    section: str  # e.g., "Section 3.1.1 (Protocol Versions)"
    url: str  # Link to authoritative standard specification
    published_date: Optional[str] = None  # e.g., "2022-11"
    effective_status: str = "CURRENT"  # "CURRENT", "SUBJECT_TO_PERIODIC_REVIEW", "HISTORIC"

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "name": self.name,
            "title": self.title,
            "section": self.section,
            "url": self.url,
            "effective_status": self.effective_status,
        }
        if self.published_date:
            res["published_date"] = self.published_date
        return res


@dataclass
class StandardsOption:
    """A possible configuration option on the comparison spectrum."""
    value: str  # e.g., "TLS 1.2"
    label: str  # e.g., "TLS 1.2"
    status: StandardsStatus  # e.g., StandardsStatus.ACCEPTABLE
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "value": self.value,
            "label": self.label,
            "status": self.status.value if isinstance(self.status, StandardsStatus) else str(self.status),
        }
        if self.description:
            res["description"] = self.description
        return res


@dataclass
class ComparisonResult:
    """Result of evaluating an observed configuration against a standards profile."""
    field: str  # Key identifier, e.g. "tls_version"
    label: str  # Human readable label, e.g. "TLS Version"
    observed: str  # Observed value, e.g. "TLS 1.2"
    status: StandardsStatus  # Status of observed value
    preferred: List[str]  # Values currently preferred under guidance
    visualization: VisualizationType
    options: List[StandardsOption]
    profile: str  # Machine identifier, e.g. "ietf-modern-tls"
    profile_name: str  # Human-readable profile name, e.g. "IETF Modern TLS (RFC 9325)"
    rationale: str  # Clear, concise narrative explaining the standing and guidance
    sources: List[StandardsSource]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "label": self.label,
            "observed": self.observed,
            "status": self.status.value if isinstance(self.status, StandardsStatus) else str(self.status),
            "preferred": self.preferred,
            "visualization": self.visualization.value if isinstance(self.visualization, VisualizationType) else str(self.visualization),
            "options": [opt.to_dict() for opt in self.options],
            "profile": self.profile,
            "profile_name": self.profile_name,
            "rationale": self.rationale,
            "sources": [src.to_dict() for src in self.sources],
            "metadata": self.metadata,
        }


@dataclass
class StandardsProfile:
    """Metadata describing a standards profile."""
    id: str  # e.g., "ietf-modern-tls"
    name: str  # e.g., "IETF Modern TLS Guidance"
    version: str  # e.g., "2024.1"
    description: str
    last_reviewed: str  # ISO date string e.g. "2026-01-15"
    sources: List[StandardsSource] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "last_reviewed": self.last_reviewed,
            "sources": [s.to_dict() for s in self.sources],
        }
