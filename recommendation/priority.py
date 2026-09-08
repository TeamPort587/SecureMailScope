"""
SecureMailScope Recommendation Priority

Defines the priority order used when sorting security
recommendations.

Lower number = higher priority.
"""


PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def get_priority_value(priority):
    """
    Return the numeric value for a priority.

    Args:
        priority (str): Priority name.

    Returns:
        int: Numeric priority value.
    """
    return PRIORITY_ORDER.get(priority, 999)


def sort_recommendations(recommendations):
    """
    Sort recommendations from highest to lowest priority.

    Args:
        recommendations (list): List of recommendation dictionaries.

    Returns:
        list: Sorted recommendations.
    """
    return sorted(
        recommendations,
        key=lambda recommendation: get_priority_value(
            recommendation.get("priority")
        ),
    )