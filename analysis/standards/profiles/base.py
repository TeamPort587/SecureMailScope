"""Base class for standards profiles."""

from abc import ABC, abstractmethod
from typing import List
from analysis.feature_extraction.models import SecurityProfile
from analysis.standards.models import ComparisonResult, StandardsProfile


class BaseStandardsProfile(ABC):
    """Abstract base class for standards assessment profiles."""

    @property
    @abstractmethod
    def profile_info(self) -> StandardsProfile:
        """Return metadata describing this standards profile."""
        pass

    @abstractmethod
    def evaluate(self, session: SecurityProfile) -> List[ComparisonResult]:
        """Evaluate an observed session profile against this standards profile.
        
        Returns a list of ComparisonResult instances for all applicable fields.
        """
        pass
