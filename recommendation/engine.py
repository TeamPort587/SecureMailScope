"""
SecureMailScope Recommendation Engine

Converts security findings from the Django analysis response
into actionable recommendations.

Responsibilities:
    1. Map finding types to recommendations.
    2. Deduplicate recommendations.
    3. Track affected sessions.
    4. Preserve useful finding information.
    5. Sort recommendations by priority.

This module does NOT:
    - Train or run the ML model.
    - Calculate the final ML risk.
    - Modify Django findings.
"""


from .catalog import get_recommendation
from .priority import sort_recommendations

# Lower number = higher priority.

def generate_recommendations(findings):
    """
    Generate recommendations from security findings.

    Multiple findings of the same type are combined into a single
    recommendation.

    Args:
        findings (list): List of finding dictionaries from Django.

    Returns:
        list: Deduplicated and priority-sorted recommendations.
    """

    if not findings:
        return []

    recommendations = {}

    for finding in findings:
        finding_type = finding.get("finding_type")

        if not finding_type:
            continue

        recommendation = get_recommendation(finding_type)

        if recommendation is None:
            continue

        recommendation_id = recommendation["recommendation_id"]

        # Create the recommendation the first time we encounter it.
        if recommendation_id not in recommendations:
            recommendations[recommendation_id] = {
                "recommendation_id": recommendation["recommendation_id"],
                "priority": recommendation["priority"],
                "title": recommendation["title"],
                "description": recommendation["description"],
                "finding_types": [],
                "affected_sessions": [],
                "finding_count": 0,
            }

        current = recommendations[recommendation_id]

        # Track which finding types caused this recommendation.
        if finding_type not in current["finding_types"]:
            current["finding_types"].append(finding_type)

        # Track affected session IDs.
        session_id = finding.get("session_id")

        if session_id and session_id not in current["affected_sessions"]:
            current["affected_sessions"].append(session_id)

        # Count how many findings resulted in this recommendation.
        current["finding_count"] += 1

    # Convert dictionary to list.
    result = list(recommendations.values())

    # Sort by priority.
    result = sort_recommendations(result)

    return result