"""Standards Comparison Engine.

Executes standards evaluation across configured standards profiles for an observed session.
"""

from typing import Any, Dict, List, Optional
from analysis.feature_extraction.models import SecurityProfile
from analysis.standards.models import ComparisonResult
from analysis.standards.profiles import ALL_STANDARDS_PROFILES, BaseStandardsProfile


def evaluate_session_standards(
    session: SecurityProfile,
    profiles: Optional[List[BaseStandardsProfile]] = None,
) -> List[Dict[str, Any]]:
    """Evaluate an observed session profile against all active standards profiles.

    Args:
        session: Extracted SecurityProfile for an email session.
        profiles: Optional list of profile evaluators. Defaults to ALL_STANDARDS_PROFILES.

    Returns:
        List of serialized ComparisonResult dictionaries.
    """
    active_profiles = profiles if profiles is not None else ALL_STANDARDS_PROFILES
    results: List[ComparisonResult] = []

    for prof in active_profiles:
        try:
            profile_results = prof.evaluate(session)
            results.extend(profile_results)
        except Exception:
            # Failure in one standards evaluator must not crash session analysis
            continue

    return [res.to_dict() for res in results]
